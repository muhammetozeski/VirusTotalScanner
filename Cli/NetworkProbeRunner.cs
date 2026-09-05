using System.Diagnostics;
using System.Text;

namespace VirusTotalScanner;

/// <summary>
/// Answers, by measurement rather than by guessing, the two questions a stalled sweep raises:
///
///   1. When VirusTotal starts challenging us, does changing the source address help?
///   2. Are Tor exit addresses simply refused by VirusTotal?
///
/// It drives the real keyless browser (the same one the scan uses) at hashes the local cache says
/// VirusTotal already knows, so a "not found" cannot be confused with a block. Each route — the direct
/// connection first, then one Tor circuit per round — gets the same fixed number of lookups, and the
/// outcomes are tallied per exit address. The window is never shown and the checkbox is never clicked:
/// the point is to see how an address is treated on its own.
/// </summary>
internal static class NetworkProbeRunner
{
    sealed class RouteResult
    {
        public string Route = "";
        public string ExitIp = "";
        public string Country = "";
        public int Reports, NotFound, Challenged, TimedOut, Other;
        public int FirstChallengeAt = -1;   // 1-based lookup index, -1 = never challenged
        public long ElapsedMs;
        public int Lookups => Reports + NotFound + Challenged + TimedOut + Other;
        public string Verdict =>
            Challenged == 0 && Reports > 0 ? "OK"
            : Reports > 0 ? "PARTIAL"
            : Challenged > 0 ? "BLOCKED"
            : "NO ANSWER";
    }

    public static async Task<int> RunAsync(int rounds, int lookupsPerRoute, CancellationToken ct = default)
    {
        rounds = Math.Clamp(rounds, 1, 20);
        lookupsPerRoute = Math.Clamp(lookupsPerRoute, 1, 25);

        if (!GuiScrapeService.IsRuntimeAvailable)
        {
            Console.Error.WriteLine("WebView2 is not available; the keyless path cannot be probed.");
            return 2;
        }

        var hashes = PickKnownHashes(lookupsPerRoute * (rounds + 1));
        if (hashes.Count == 0)
        {
            Console.Error.WriteLine("No known-good hashes to probe with (the local cache is empty).");
            return 2;
        }

        var results = new List<RouteResult>();
        GuiScrapeService.ProbeMode = true;
        int hashCursor = 0;
        try
        {
            // Round 0: the direct connection, so every Tor number below has something to be compared to.
            TorService.Disable();
            VtHttpClientFactory.Invalidate();
            GuiScrapeService.InvalidateSession("probe: direct");
            results.Add(await ProbeRouteAsync("direct", await DirectIpAsync(ct), hashes, hashCursor, lookupsPerRoute, ct));
            hashCursor += lookupsPerRoute;

            for (int round = 1; round <= rounds; round++)
            {
                ct.ThrowIfCancellationRequested();
                bool up = TorService.IsActive ? await TorService.NewCircuitAsync(ct) : await TorService.EnableAsync(ct);
                if (!up)
                {
                    Console.Error.WriteLine($"round {round}: Tor route unavailable ({TorService.LastError ?? "?"}) — stopping here.");
                    break;
                }
                await TorService.RefreshExitInfoAsync(ct);
                VtHttpClientFactory.Invalidate();
                GuiScrapeService.InvalidateSession("probe: new circuit");

                var r = await ProbeRouteAsync($"tor #{round}", (TorService.ExitIp ?? "?", TorService.ExitCountry ?? "?"), hashes, hashCursor, lookupsPerRoute, ct);
                hashCursor += lookupsPerRoute;
                results.Add(r);
            }
        }
        catch (OperationCanceledException) { Console.Error.WriteLine("probe cancelled."); }
        catch (Exception ex) { Console.Error.WriteLine("probe failed: " + ex.Message); Log("Network probe failed: " + ex, LogLevel.Error); }
        finally { GuiScrapeService.ProbeMode = false; }

        string report = Render(results, lookupsPerRoute);
        Console.WriteLine(report);
        TryWrite(report);
        return results.Any(r => r.Reports > 0) ? 0 : 1;
    }

    static async Task<RouteResult> ProbeRouteAsync(string route, (string Ip, string Country) exit,
        List<string> hashes, int cursor, int count, CancellationToken ct)
    {
        var r = new RouteResult { Route = route, ExitIp = exit.Ip, Country = exit.Country };
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            string hash = hashes[(cursor + i) % hashes.Count];
            var report = await GuiScrapeService.LookupAsync(hash, ct, Timeout.InfiniteTimeSpan);
            var outcome = report != null ? KeylessOutcome.Report : GuiScrapeService.LastOutcome;
            switch (outcome)
            {
                case KeylessOutcome.Report: r.Reports++; break;
                case KeylessOutcome.NotFound: r.NotFound++; break;
                case KeylessOutcome.Challenged:
                    r.Challenged++;
                    if (r.FirstChallengeAt < 0) r.FirstChallengeAt = i + 1;
                    break;
                case KeylessOutcome.TimedOut: r.TimedOut++; break;
                default: r.Other++; break;
            }
            Console.Error.WriteLine($"  {route} [{i + 1}/{count}] {hash[..12]}… -> {outcome}");
        }
        r.ElapsedMs = sw.ElapsedMilliseconds;
        return r;
    }

    /// <summary>Hashes the local cache already holds a VirusTotal report for, so "not found" during the
    /// probe means something went wrong rather than "this file is unknown".</summary>
    static List<string> PickKnownHashes(int want)
    {
        var list = new List<string>();
        try
        {
            foreach (var e in AppServices.Cache.Snapshot())
            {
                if (string.IsNullOrWhiteSpace(e.Sha256)) continue;
                if (e.TotalEngines <= 0) continue;      // a report VirusTotal really answered
                list.Add(e.Sha256!.ToLowerInvariant());
                if (list.Count >= want) break;
            }
        }
        catch (Exception ex) { Log("Probe hash pick failed: " + ex.Message, LogLevel.Warning); }

        if (list.Count == 0)
        {
            // Fall back to two hashes VirusTotal is certain to know.
            list.Add("ab15a95de88ab0624307ae0e28e333756a2a522f650a0be78749901f7dc32ecf"); // notepad.exe
            list.Add("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"); // EICAR test string
        }
        return list;
    }

    static async Task<(string Ip, string Country)> DirectIpAsync(CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            string json = await http.GetStringAsync("http://ip-api.com/json/?fields=query,country,countryCode", ct);
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            string ip = doc.RootElement.TryGetProperty("query", out var q) ? q.GetString() ?? "?" : "?";
            string country = doc.RootElement.TryGetProperty("country", out var c) ? c.GetString() ?? "?" : "?";
            return (ip, country);
        }
        catch (Exception ex) { Log("Direct IP lookup failed: " + ex.Message, LogLevel.Warning); return ("?", "?"); }
    }

    static string Render(List<RouteResult> results, int perRoute)
    {
        var sb = new StringBuilder();
        sb.AppendLine("VirusTotal keyless-route probe — " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        sb.AppendLine($"{perRoute} lookup(s) per route, hashes VirusTotal already has, no window and no auto-click.");
        sb.AppendLine();
        sb.AppendLine("route     exit address      country              ok  404  challenged  timeout  first-challenge  verdict");
        sb.AppendLine("--------  ----------------  -------------------  --  ---  ----------  -------  ---------------  -------");
        foreach (var r in results)
        {
            sb.AppendLine(string.Format("{0,-8}  {1,-16}  {2,-19}  {3,2}  {4,3}  {5,10}  {6,7}  {7,15}  {8}",
                r.Route, Trim(r.ExitIp, 16), Trim(r.Country, 19), r.Reports, r.NotFound, r.Challenged, r.TimedOut,
                r.FirstChallengeAt < 0 ? "-" : r.FirstChallengeAt.ToString(), r.Verdict));
        }
        sb.AppendLine();

        var tor = results.Where(r => r.Route.StartsWith("tor", StringComparison.Ordinal)).ToList();
        var direct = results.FirstOrDefault(r => r.Route == "direct");
        if (direct != null)
            sb.AppendLine($"direct: {direct.Reports}/{direct.Lookups} answered, {direct.Challenged} challenged.");
        if (tor.Count > 0)
        {
            int okRoutes = tor.Count(r => r.Reports > 0);
            int blockedRoutes = tor.Count(r => r.Reports == 0 && r.Challenged > 0);
            sb.AppendLine($"tor: {tor.Count} exit address(es) tried — {okRoutes} answered at least once, {blockedRoutes} were challenged on every lookup.");
            sb.AppendLine($"tor totals: {tor.Sum(r => r.Reports)} answered, {tor.Sum(r => r.Challenged)} challenged, {tor.Sum(r => r.TimedOut)} timed out.");
            sb.AppendLine(okRoutes == 0
                ? "=> On this evidence VirusTotal's keyless interface refuses Tor exits outright; rotating does not help."
                : blockedRoutes == 0
                    ? "=> Every Tor exit answered: rotating the circuit is a working way out of a challenge."
                    : "=> Tor exits vary: some answer, some are challenged. Rotating is worth retrying a few times.");
        }
        return sb.ToString();
    }

    static string Trim(string s, int n) => s.Length <= n ? s : s[..n];

    static void TryWrite(string report)
    {
        try
        {
            string path = Path.Combine(ConfigPathResolver.DataFolder,
                "route-probe-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt");
            File.WriteAllText(path, report, new UTF8Encoding(true));
            Console.Error.WriteLine("report written: " + path);
        }
        catch (Exception ex) { Log("Probe report write failed: " + ex.Message, LogLevel.Warning); }
    }
}
