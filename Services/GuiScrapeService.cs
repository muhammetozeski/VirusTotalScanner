using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>
/// Public facade over the new zero-cookie <see cref="BrowserSessionFactory"/> + <see cref="RoutePool"/>
/// infrastructure. Preserves compatibility for callers like <see cref="NetworkProbeRunner"/>,
/// <see cref="ScanDetailControl"/> (comments/behaviour), <see cref="RecheckService"/>, and
/// <see cref="WatchService"/> without keeping any stateful cookie-bearing browsers or global channel parks.
/// </summary>
internal static class GuiScrapeService
{
    static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    /// <summary>Picks a random Windows Chromium User-Agent from <see cref="UserAgentPool"/>.</summary>
    internal static string PickIdentity() => UserAgentPool.PickChromiumWindows();

    public static bool IsRuntimeAvailable => BrowserSessionFactory.IsRuntimeAvailable;

    /// <summary>No global channel park exists in the per-cell architecture; route health is tracked per route.</summary>
    public static bool IsBlocked => false;

    public static DateTime? BlockedUntilUtc => null;

    /// <summary>Diagnostic outcome of the most recent direct facade call (used by NetworkProbeRunner).</summary>
    public static KeylessOutcome LastOutcome { get; internal set; } = KeylessOutcome.None;

    /// <summary>Probe mode: never show a captcha window and never auto-click.</summary>
    public static bool ProbeMode { get; set; }

    /// <summary>Headless / CLI mode: never show a desktop captcha window.</summary>
    public static bool HeadlessMode { get; set; }

    /// <summary>Resets per-route cool-offs so the next lookup tries routes fresh.</summary>
    public static void InvalidateSession(string why)
    {
        RoutePool.ResetAllHealth();
        Log("Browser route health reset: " + why, LogLevel.Info);
    }

    /// <summary>Resets route health and wipes all idle browser cache slots in the background.</summary>
    public static void ResetHard(string why)
    {
        RoutePool.ResetAllHealth();
        BrowserSessionFactory.WipeAllIdleCacheSlots();
        Log("Browser cache slots and route health hard-reset: " + why, LogLevel.Info);
    }

    public static void Shutdown() => BrowserSessionFactory.Shutdown();

    /// <summary>
    /// Single zero-cookie browser lookup (respecting TorService.IsActive in ProbeMode, or RoutePool otherwise).
    /// Returns both the parsed report and the exact <see cref="KeylessOutcome"/>.
    /// </summary>
    public static async Task<(VtFileReport? Report, KeylessOutcome Outcome)> LookupWithOutcomeAsync(
        string hash, CancellationToken ct = default, TimeSpan? maxQueueWait = null)
    {
        hash = hash.Trim().ToLowerInvariant();
        if (!IsRuntimeAvailable) { LastOutcome = KeylessOutcome.NoRuntime; return (null, KeylessOutcome.NoRuntime); }

        var route = ProbeMode
            ? (TorService.IsActive ? new NetworkRoute(true, 0, TorService.ProxyUrl, "Tor #1") : RoutePool.Direct)
            : RoutePool.PickInitialRoute();

        var res = await BrowserSessionFactory.RunAttemptAsync(
            hash, "", AppConstants.VtGuiFile + hash, route, BrowserFingerprint.Random(),
            wipeProfileSlot: false, allowUserCaptcha: !ProbeMode && !HeadlessMode,
            maxQueueWait: maxQueueWait ?? TimeSpan.FromSeconds(45), ct);

        var outcome = MapOutcome(res.Outcome);
        LastOutcome = outcome;
        if (res.Outcome == BrowserAttemptOutcome.Report && !string.IsNullOrEmpty(res.Json))
        {
            RoutePool.ReportSuccess(route);
            var rep = QueryCell.ParseReport(res.Json, hash);
            return (rep, rep != null ? KeylessOutcome.Report : KeylessOutcome.NotFound);
        }
        if (res.Outcome == BrowserAttemptOutcome.NotFound) RoutePool.ReportSuccess(route);
        else if (res.Outcome is BrowserAttemptOutcome.Challenged or BrowserAttemptOutcome.CaptchaSolvedButFailed) RoutePool.ReportBlocked(route);
        return (null, outcome);
    }

    public static async Task<VtFileReport?> LookupAsync(string hash, CancellationToken ct = default, TimeSpan? maxQueueWait = null)
    {
        var (report, _) = await LookupWithOutcomeAsync(hash, ct, maxQueueWait);
        return report;
    }

    /// <summary>Fetches community comments for a hash via a zero-cookie browser session.</summary>
    public static async Task<List<VtComment>> FetchCommentsAsync(string hash, CancellationToken ct = default)
    {
        hash = hash.Trim().ToLowerInvariant();
        var result = new List<VtComment>();
        try
        {
            var route = RoutePool.PickInitialRoute();
            var res = await BrowserSessionFactory.RunAttemptAsync(
                hash, "/comments", AppConstants.VtGuiFile + hash + "/community", route, BrowserFingerprint.Random(),
                wipeProfileSlot: false, allowUserCaptcha: !HeadlessMode, maxQueueWait: TimeSpan.FromSeconds(45), ct);
            if (string.IsNullOrEmpty(res.Json)) return result;

            var dto = JsonSerializer.Deserialize<VtResponse<List<VtCommentData>>>(res.Json, JsonOpts);
            foreach (var c in dto?.Data ?? [])
            {
                var a = c.Attributes;
                if (a == null || string.IsNullOrWhiteSpace(a.Text)) continue;
                result.Add(new VtComment
                {
                    Date = a.Date > 0 ? DateTimeOffset.FromUnixTimeSeconds(a.Date).UtcDateTime : null,
                    Text = a.Text,
                    Tags = a.Tags ?? [],
                });
            }
            return result;
        }
        catch (Exception ex) { Log("Keyless GUI comments failed: " + ex.Message, LogLevel.Warning); return result; }
    }

    /// <summary>Fetches sandbox behaviour summary for a hash via a zero-cookie browser session.</summary>
    public static async Task<VtBehaviour> FetchBehaviourAsync(string hash, CancellationToken ct = default)
    {
        hash = hash.Trim().ToLowerInvariant();
        var b = new VtBehaviour();
        try
        {
            var route = RoutePool.PickInitialRoute();
            var res = await BrowserSessionFactory.RunAttemptAsync(
                hash, "/behaviours", AppConstants.VtGuiFile + hash + "/behavior", route, BrowserFingerprint.Random(),
                wipeProfileSlot: false, allowUserCaptcha: !HeadlessMode, maxQueueWait: TimeSpan.FromSeconds(45), ct);
            if (string.IsNullOrEmpty(res.Json)) return b;

            var reports = JsonSerializer.Deserialize<VtResponse<List<VtBehaviourReportData>>>(res.Json, JsonOpts)?.Data;
            foreach (var dto in (reports ?? []).Select(r => r.Attributes).Where(a => a != null))
            {
                foreach (var d in dto!.DnsLookups ?? []) if (!string.IsNullOrWhiteSpace(d.Hostname)) b.Network.Add("🌐 " + d.Hostname);
                foreach (var ip in dto.IpTraffic ?? []) if (!string.IsNullOrWhiteSpace(ip.DestinationIp)) b.Network.Add("📡 " + ip.DestinationIp);
                foreach (var f in dto.FilesWritten ?? []) if (!string.IsNullOrWhiteSpace(f)) b.FilesWritten.Add(f);
                foreach (var f in dto.FilesDropped ?? []) if (!string.IsNullOrWhiteSpace(f.Path)) b.FilesWritten.Add("⬇ " + f.Path);
                foreach (var r in dto.RegistryKeysSet ?? []) if (!string.IsNullOrWhiteSpace(r.Key)) b.Registry.Add(r.Key);
                foreach (var p in dto.ProcessesCreated ?? []) if (!string.IsNullOrWhiteSpace(p)) b.Processes.Add(p);
                foreach (var m in dto.Mitre ?? []) if (!string.IsNullOrWhiteSpace(m.Id)) b.Mitre.Add($"{m.Id} {m.Description}".Trim());
            }

            b.Network = b.Network.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            b.FilesWritten = b.FilesWritten.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            b.Registry = b.Registry.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            b.Processes = b.Processes.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            b.Mitre = b.Mitre.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            return b;
        }
        catch (Exception ex) { Log("Keyless GUI behaviour failed: " + ex.Message, LogLevel.Warning); return b; }
    }

    static KeylessOutcome MapOutcome(BrowserAttemptOutcome o) => o switch
    {
        BrowserAttemptOutcome.Report => KeylessOutcome.Report,
        BrowserAttemptOutcome.NotFound => KeylessOutcome.NotFound,
        BrowserAttemptOutcome.Challenged or BrowserAttemptOutcome.CaptchaSolvedButFailed or BrowserAttemptOutcome.UserSwitchedToApi => KeylessOutcome.Challenged,
        BrowserAttemptOutcome.NoRuntime => KeylessOutcome.NoRuntime,
        _ => KeylessOutcome.TimedOut,
    };
}
