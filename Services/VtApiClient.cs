using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>
/// VirusTotal API v3 client. The key is passed per call (rotation). GET calls go through
/// the Polly pipeline; uploads run once. Maps wire DTOs to clean domain models.
/// </summary>
internal sealed class VtApiClient
{
    static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };
    HttpClient Http => VtHttpClientFactory.Client;

    /// <summary>Looks up an existing report by hash (md5/sha1/sha256). Returns null on 404.</summary>
    public async Task<VtFileReport?> GetFileReportAsync(string hash, string apiKey, CancellationToken ct = default)
    {
        Log($"VT lookup {hash}", LogLevel.Info);
        using var resp = await ExecuteAsync(() => Build(HttpMethod.Get, $"/files/{hash}", apiKey), ct);
        if (resp.StatusCode == HttpStatusCode.NotFound) { Log($"VT 404 (unknown file): {hash}"); return null; }
        await ThrowIfError(resp);

        var dto = await resp.Content.ReadFromJsonAsync<VtResponse<VtFileData>>(JsonOpts, ct);
        return MapReport(dto?.Data?.Attributes);
    }

    /// <summary>Requests an upload URL for files larger than the direct-upload limit.</summary>
    public async Task<string> GetUploadUrlAsync(string apiKey, CancellationToken ct = default)
    {
        using var resp = await ExecuteAsync(() => Build(HttpMethod.Get, "/files/upload_url", apiKey), ct);
        await ThrowIfError(resp);
        var dto = await resp.Content.ReadFromJsonAsync<VtResponse<string>>(JsonOpts, ct);
        return dto?.Data ?? throw new VtApiException("Upload URL response was empty.", resp.StatusCode);
    }

    /// <summary>Uploads a file for analysis, reporting progress. Returns the analysis id. No retry.</summary>
    public async Task<string> UploadFileAsync(string path, string apiKey, IProgress<UploadProgress>? progress, CancellationToken ct = default)
    {
        var fi = new FileInfo(path);
        string url = fi.Length > AppConstants.DirectUploadLimitBytes
            ? await GetUploadUrlAsync(apiKey, ct)
            : AppConstants.VtApiBase + "/files";

        Log($"VT upload {fi.Name} ({FormatBytes(fi.Length)}) -> {url}", LogLevel.Info);

        using var fs = File.OpenRead(path);
        var streamContent = new ProgressableStreamContent(fs, fi.Length, progress);
        streamContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        using var form = new MultipartFormDataContent { { streamContent, "file", fi.Name } };
        using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = form };
        req.Headers.Add("x-apikey", apiKey);
        req.Headers.Accept.ParseAdd("application/json");

        using var resp = await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        await ThrowIfError(resp);

        var dto = await resp.Content.ReadFromJsonAsync<VtResponse<VtUploadData>>(JsonOpts, ct);
        return dto?.Data?.Id ?? throw new VtApiException("Upload returned no analysis id.", resp.StatusCode);
    }

    /// <summary>Gets the status of a submitted analysis.</summary>
    public async Task<VtAnalysisInfo> GetAnalysisAsync(string analysisId, string apiKey, CancellationToken ct = default)
    {
        using var resp = await ExecuteAsync(() => Build(HttpMethod.Get, $"/analyses/{analysisId}", apiKey), ct);
        await ThrowIfError(resp);
        var dto = await resp.Content.ReadFromJsonAsync<VtResponse<VtAnalysisData>>(JsonOpts, ct);
        return new VtAnalysisInfo { Status = dto?.Data?.Attributes?.Status ?? "" };
    }

    /// <summary>Reads the per-key quota usage (hourly/daily/monthly).</summary>
    public async Task<VtQuotas?> GetUserQuotaAsync(string apiKey, CancellationToken ct = default)
    {
        using var resp = await ExecuteAsync(() => Build(HttpMethod.Get, $"/users/{apiKey}", apiKey), ct);
        if (resp.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Forbidden) return null;
        await ThrowIfError(resp);
        var dto = await resp.Content.ReadFromJsonAsync<VtResponse<VtUserData>>(JsonOpts, ct);
        var q = dto?.Data?.Attributes?.Quotas;
        if (q == null) return null;
        return new VtQuotas
        {
            Hourly = Slot(q.Hourly),
            Daily = Slot(q.Daily),
            Monthly = Slot(q.Monthly),
        };
        static VtQuotaSlot Slot(VtQuotaSlotDto? s) => new() { Used = s?.Used ?? 0, Allowed = s?.Allowed ?? 0 };
    }

    // ---- internals ----

    HttpRequestMessage Build(HttpMethod method, string relativeUrl, string apiKey)
    {
        var req = new HttpRequestMessage(method, AppConstants.VtApiBase + relativeUrl);
        req.Headers.Add("x-apikey", apiKey);
        req.Headers.Accept.ParseAdd("application/json");
        return req;
    }

    async Task<HttpResponseMessage> ExecuteAsync(Func<HttpRequestMessage> factory, CancellationToken ct)
    {
        return await VtResilience.Pipeline.ExecuteAsync(async token =>
        {
            using var req = factory();
            return await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token);
        }, ct);
    }

    static async Task ThrowIfError(HttpResponseMessage resp)
    {
        if (resp.IsSuccessStatusCode) return;
        string body = await SafeReadBody(resp);
        switch ((int)resp.StatusCode)
        {
            case 429:
                throw new VtRateLimitException(GetRetryAfter(resp), body);
            case 401:
            case 403:
                throw new VtAuthException(resp.StatusCode, body);
            default:
                throw new VtApiException($"VirusTotal API error {(int)resp.StatusCode} {resp.StatusCode}.", resp.StatusCode, body);
        }
    }

    static TimeSpan? GetRetryAfter(HttpResponseMessage resp)
    {
        var ra = resp.Headers.RetryAfter;
        if (ra?.Delta is { } d) return d;
        if (ra?.Date is { } date) return date - DateTimeOffset.UtcNow;
        return null;
    }

    static async Task<string> SafeReadBody(HttpResponseMessage resp)
    {
        try { return await resp.Content.ReadAsStringAsync(); }
        catch { return string.Empty; }
    }

    internal static VtFileReport? MapReport(VtFileAttributes? a)
    {
        if (a == null) return null;
        var report = new VtFileReport
        {
            Md5 = a.Md5,
            Sha1 = a.Sha1,
            Sha256 = a.Sha256,
            MeaningfulName = a.MeaningfulName,
            TypeDescription = a.TypeDescription,
            Size = a.Size,
            Reputation = a.Reputation,
            TimesSubmitted = a.TimesSubmitted,
            FirstSeenUtc = a.FirstSubmissionDate > 0 ? DateTimeOffset.FromUnixTimeSeconds(a.FirstSubmissionDate).UtcDateTime : null,
            LastSeenUtc = a.LastSubmissionDate > 0 ? DateTimeOffset.FromUnixTimeSeconds(a.LastSubmissionDate).UtcDateTime : null,
            VotesHarmless = a.TotalVotes?.Harmless ?? 0,
            VotesMalicious = a.TotalVotes?.Malicious ?? 0,
            Tags = a.Tags ?? [],
            ThreatLabel = a.ThreatClassification?.SuggestedLabel,
            Malicious = a.Stats?.Malicious ?? 0,
            Suspicious = a.Stats?.Suspicious ?? 0,
            Harmless = a.Stats?.Harmless ?? 0,
            Undetected = a.Stats?.Undetected ?? 0,
            Timeout = a.Stats?.Timeout ?? 0,
        };

        if (a.Results != null)
        {
            foreach (var kv in a.Results)
            {
                report.Engines.Add(new VtEngineResult
                {
                    EngineName = kv.Value.EngineName ?? kv.Key,
                    EngineVersion = kv.Value.EngineVersion,
                    Category = kv.Value.Category,
                    Result = kv.Value.Result,
                    Method = kv.Value.Method,
                    EngineUpdate = kv.Value.EngineUpdate,
                });
            }
            // Detections first, then alphabetical — handy for the GUI table.
            report.Engines = report.Engines
                .OrderByDescending(e => e.IsDetection)
                .ThenBy(e => e.EngineName, StringComparer.OrdinalIgnoreCase)
                .ToList();

            report.MajorFlaggers = report.Detections
                .Where(e => MajorEngines.IsMajor(e.EngineName))
                .Select(e => e.EngineName)
                .ToList();

            if (DetectionFamily.MostCommon(report.Detections) is { } fam)
            {
                report.Family = fam.Family;
                report.FamilyCount = fam.Count;
            }

            report.SignatureHits = report.Detections.Count(e => string.Equals(e.Method, "blacklist", StringComparison.OrdinalIgnoreCase));

            int staleDays = Settings.StaleSignatureDays.Value;
            if (staleDays > 0)
            {
                var cutoff = DateTime.UtcNow.AddDays(-staleDays);
                report.StaleDetections = report.Detections.Count(e => e.UpdatedUtc is { } u && u < cutoff);
            }

            foreach (var s in a.SigmaResults ?? []) if (!string.IsNullOrWhiteSpace(s.RuleTitle)) report.CommunityRules.Add($"Sigma: {s.RuleTitle}" + (string.IsNullOrWhiteSpace(s.RuleLevel) ? "" : $" [{s.RuleLevel}]"));
            foreach (var i in a.IdsResults ?? []) if (!string.IsNullOrWhiteSpace(i.RuleMsg)) report.CommunityRules.Add($"IDS: {i.RuleMsg}");
            foreach (var y in a.YaraResults ?? []) if (!string.IsNullOrWhiteSpace(y.RuleName)) report.CommunityRules.Add($"YARA: {y.RuleName}" + (string.IsNullOrWhiteSpace(y.Author) ? "" : $" ({y.Author})"));
        }

        return report;
    }
}
