using System.Text.Json.Serialization;

namespace VirusTotalScanner;

// ---------------------------------------------------------------------------
// JSON DTOs (wire format) for VirusTotal API v3
// ---------------------------------------------------------------------------

internal sealed class VtResponse<T>
{
    [JsonPropertyName("data")] public T? Data { get; set; }
}

internal sealed class VtFileData
{
    [JsonPropertyName("attributes")] public VtFileAttributes? Attributes { get; set; }
}

internal sealed class VtFileAttributes
{
    [JsonPropertyName("last_analysis_stats")] public VtStatsDto? Stats { get; set; }
    [JsonPropertyName("last_analysis_results")] public Dictionary<string, VtEngineDto>? Results { get; set; }
    [JsonPropertyName("meaningful_name")] public string? MeaningfulName { get; set; }
    [JsonPropertyName("type_description")] public string? TypeDescription { get; set; }
    [JsonPropertyName("type_tag")] public string? TypeTag { get; set; }
    [JsonPropertyName("md5")] public string? Md5 { get; set; }
    [JsonPropertyName("sha1")] public string? Sha1 { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("reputation")] public int Reputation { get; set; }
    [JsonPropertyName("times_submitted")] public int TimesSubmitted { get; set; }
    [JsonPropertyName("first_submission_date")] public long FirstSubmissionDate { get; set; }
    [JsonPropertyName("last_submission_date")] public long LastSubmissionDate { get; set; }
}

internal sealed class VtStatsDto
{
    [JsonPropertyName("malicious")] public int Malicious { get; set; }
    [JsonPropertyName("suspicious")] public int Suspicious { get; set; }
    [JsonPropertyName("harmless")] public int Harmless { get; set; }
    [JsonPropertyName("undetected")] public int Undetected { get; set; }
    [JsonPropertyName("timeout")] public int Timeout { get; set; }
    [JsonPropertyName("type-unsupported")] public int TypeUnsupported { get; set; }
    [JsonPropertyName("failure")] public int Failure { get; set; }
}

internal sealed class VtEngineDto
{
    [JsonPropertyName("engine_name")] public string? EngineName { get; set; }
    [JsonPropertyName("engine_version")] public string? EngineVersion { get; set; }
    [JsonPropertyName("category")] public string? Category { get; set; }
    [JsonPropertyName("result")] public string? Result { get; set; }
    [JsonPropertyName("method")] public string? Method { get; set; }
    [JsonPropertyName("engine_update")] public string? EngineUpdate { get; set; }
}

internal sealed class VtUploadData
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("type")] public string? Type { get; set; }
}

internal sealed class VtAnalysisData
{
    [JsonPropertyName("attributes")] public VtAnalysisAttributes? Attributes { get; set; }
}

internal sealed class VtAnalysisAttributes
{
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("stats")] public VtStatsDto? Stats { get; set; }
}

internal sealed class VtUserData
{
    [JsonPropertyName("attributes")] public VtUserAttributes? Attributes { get; set; }
}

internal sealed class VtUserAttributes
{
    [JsonPropertyName("quotas")] public VtQuotasDto? Quotas { get; set; }
}

internal sealed class VtQuotasDto
{
    [JsonPropertyName("api_requests_hourly")] public VtQuotaSlotDto? Hourly { get; set; }
    [JsonPropertyName("api_requests_daily")] public VtQuotaSlotDto? Daily { get; set; }
    [JsonPropertyName("api_requests_monthly")] public VtQuotaSlotDto? Monthly { get; set; }
}

internal sealed class VtQuotaSlotDto
{
    [JsonPropertyName("used")] public long Used { get; set; }
    [JsonPropertyName("allowed")] public long Allowed { get; set; }
}

// ---------------------------------------------------------------------------
// Domain models (what the rest of the app consumes)
// ---------------------------------------------------------------------------

/// <summary>A clean, UI-friendly view of a VirusTotal file report.</summary>
internal sealed class VtFileReport
{
    public string? Md5 { get; set; }
    public string? Sha1 { get; set; }
    public string? Sha256 { get; set; }
    public string? MeaningfulName { get; set; }
    public string? TypeDescription { get; set; }
    public long Size { get; set; }
    public int Reputation { get; set; }
    public int TimesSubmitted { get; set; }
    public DateTime? FirstSeenUtc { get; set; }
    public DateTime? LastSeenUtc { get; set; }

    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Harmless { get; set; }
    public int Undetected { get; set; }
    public int Timeout { get; set; }

    public List<VtEngineResult> Engines { get; set; } = [];

    /// <summary>Major-engine names that flagged this file; stored so it survives in the summary cache.</summary>
    public List<string> MajorFlaggers { get; set; } = [];

    [JsonIgnore] public IEnumerable<VtEngineResult> Detections => Engines.Where(e => e.IsDetection);
    [JsonIgnore] public int DetectionCount => Malicious + Suspicious;
    [JsonIgnore] public int TotalEngines => Malicious + Suspicious + Harmless + Undetected + Timeout;
    [JsonIgnore] public int MajorDetectionCount => MajorFlaggers.Count;
    [JsonIgnore] public int MinorDetectionCount => Math.Max(0, DetectionCount - MajorDetectionCount);
    /// <summary>True when there are detections but no major/high-reputation engine flagged it
    /// (the classic false-positive shape).</summary>
    [JsonIgnore] public bool MajorClean => TotalEngines > 0 && DetectionCount > 0 && MajorDetectionCount == 0;
    /// <summary>A "threat" per the user's verdict categories (e.g. 1 detection may count as clean).</summary>
    [JsonIgnore] public bool IsMalicious => TotalEngines > 0 && VerdictCategories.IsThreat(DetectionCount);
    [JsonIgnore] public string ReportUrl => AppConstants.VtGuiFile + (Sha256 ?? Md5 ?? Sha1 ?? string.Empty);

    [JsonIgnore]
    public string Verdict => TotalEngines > 0 ? VerdictCategories.Classify(DetectionCount).Name : "BİLİNMİYOR";

    /// <summary>Age + prevalence line: a 0/70 on a file the world first saw minutes ago is very
    /// different from a 0/70 on a years-old, widely-seen file.</summary>
    [JsonIgnore]
    public string? FirstSeenText
    {
        get
        {
            if (FirstSeenUtc is not { } first) return null;
            var age = DateTime.UtcNow - first;
            string ageStr = age.TotalDays >= 365 ? $"{(int)(age.TotalDays / 365)} yıl önce"
                : age.TotalDays >= 1 ? $"{(int)age.TotalDays} gün önce"
                : age.TotalHours >= 1 ? $"{(int)age.TotalHours} saat önce"
                : $"{(int)age.TotalMinutes} dakika önce";
            string prev = TimesSubmitted > 0 ? $" • {TimesSubmitted} gönderim" : "";
            string rare = age.TotalDays < 2 ? "  ⚠ çok yeni" : "";
            return $"İlk görülme: {first:yyyy-MM-dd} ({ageStr}){prev}{rare}";
        }
    }

    /// <summary>"Who flagged it" — splits detections into major vs minor engines so a few
    /// obscure-engine hits read as a likely false positive.</summary>
    [JsonIgnore]
    public string? ConsensusText
    {
        get
        {
            if (TotalEngines == 0) return null;
            if (DetectionCount == 0) return "🛡 Konsensüs: hiçbir motor işaretlemedi";
            string majors = MajorFlaggers.Count > 0 ? "  →  " + string.Join(", ", MajorFlaggers.Take(6)) : "";
            string hint = MajorClean ? "  (büyük motor yok → olası yanlış pozitif)" : "";
            return $"Büyük motorlar: {MajorDetectionCount} işaretledi   •   Küçük motorlar: {MinorDetectionCount}{majors}{hint}";
        }
    }
}

internal sealed class VtEngineResult
{
    public string EngineName { get; set; } = "";
    public string? EngineVersion { get; set; }
    public string? Category { get; set; }
    public string? Result { get; set; }
    public string? Method { get; set; }
    [JsonIgnore] public bool IsDetection => Category is "malicious" or "suspicious";
}

internal sealed class VtAnalysisInfo
{
    public string Status { get; set; } = "";
    public bool IsCompleted => string.Equals(Status, "completed", StringComparison.OrdinalIgnoreCase);
}

internal sealed class VtQuotas
{
    public VtQuotaSlot Hourly { get; set; } = new();
    public VtQuotaSlot Daily { get; set; } = new();
    public VtQuotaSlot Monthly { get; set; } = new();
}

internal sealed class VtQuotaSlot
{
    public long Used { get; set; }
    public long Allowed { get; set; }
}

internal sealed class UploadProgress
{
    public long BytesSent { get; set; }
    public long TotalBytes { get; set; }
    public long BytesPerSecond { get; set; }
    public double Percent => TotalBytes > 0 ? (double)BytesSent / TotalBytes * 100 : 0;
}
