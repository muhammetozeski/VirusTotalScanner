using System.Diagnostics;
using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>Result returned by an autonomous <see cref="QueryCell"/> after exhausting its browser/API decision loop.</summary>
internal readonly record struct QueryCellResult(
    VtFileReport? Report,
    bool NotFoundOnVt,
    bool ServedByApi,
    double ResistanceScore,
    double ElapsedSeconds,
    LookupFailure Failure);

/// <summary>
/// Autonomous per-file lookup brain ("Sorgu Hücresi").
///
/// Lifecycle:
///   1) Browser-first: opens a brand-new zero-cookie browser session with a fresh fingerprint and asks
///      VirusTotal's public GUI (/gui/file/{sha256} -> /ui/files/{sha256}).
///   2) Definitive 200 -> returns the report with zero API quota spent.
///   3) Definitive 404 -> signals NotFoundOnVt so ScanScheduler submits the file to ApiCoordinator's upload queue.
///   4) Challenge / 429 / network failure / post-captcha failure -> steps through a deep, cross-combined
///      resistance matrix (cookie wipe, identity change, full profile slot wipe, Direct <-> Tor toggling,
///      isolated Tor circuit hopping, Tor NEWNYM IP rotation, cross-back retries).
///   5) Mid-resistance consultation: at checkpoints, asks ApiCoordinator whether it can admit this cell
///      based on cell ResistanceScore R (0..100) vs API LoadScore L (0..100). If rejected (API busy and
///      cell still has untested strategies), the cell keeps resisting on its own.
///   6) Exhaustion (R = 100 — all strategies tried or cell time budget spent): unconditionally admitted
///      to ApiCoordinator's lookup queue (whenever usable API keys have daily room).
/// </summary>
internal sealed class QueryCell
{
    static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    enum StepKind
    {
        InitialRouteClean,        // Zero-cookie browser, fresh UA/lang/viewport, initial route
        SameRouteFreshIdentity,   // Wipe cookies/storage, new identity, jitter backoff, same route
        CrossRouteWipeIdentity,   // Full profile slot wipe + opposite route (Direct <-> Tor)
        TorAlternateCircuit,      // Different isolated Tor SocksPort (distinct exit circuit) + fresh identity
        TorNewnymWipeProfile,     // SIGNAL NEWNYM + wiped profile slot + fresh identity
        CrossBackOriginalWipe,    // Return to original route after cool-off with fully wiped identity & slot
        TorSecondNewnymCooldown,  // Second NEWNYM + longer jitter cool-off + wiped slot
        FinalCrossOverAttempt,    // Final opposite-route + fresh slot + fresh identity
    }

    readonly record struct ResistanceStep(
        StepKind Kind,
        double Weight,
        bool WipeSlot,
        bool AllowUserCaptcha,
        bool ConsultApiAfter,
        int BackoffMinMs,
        int BackoffMaxMs,
        string Label);

    readonly ApiCoordinator _api;
    readonly PauseTokenSource? _pause;

    static int _activeCells;
    public static int ActiveCellCount => Volatile.Read(ref _activeCells);

    public QueryCell(ApiCoordinator api, PauseTokenSource? pause = null)
    {
        _api = api;
        _pause = pause;
    }

    public async Task<QueryCellResult> LookupAsync(
        string sha256,
        long urgentOrder,
        int fileTier,
        bool allowBrowser,
        bool allowApi,
        bool allowUserCaptcha,
        Action<double, string>? onStatus,
        CancellationToken ct)
    {
        sha256 = sha256.Trim().ToLowerInvariant();
        Interlocked.Increment(ref _activeCells);
        var sw = Stopwatch.StartNew();
        double userWaitSec = 0;

        try
        {
            bool browserReady = allowBrowser && BrowserSessionFactory.IsRuntimeAvailable;

            // Fast path when browser lookup is disabled or WebView2 is missing: go straight to API at R=100.
            if (!browserReady)
            {
                if (!allowApi || !_api.HasUsableKeys)
                    return new QueryCellResult(null, false, false, 100, sw.Elapsed.TotalSeconds, LookupFailure.UnknownNoKey);

                onStatus?.Invoke(100, Strings.StatusAskingApi);
                var (served, apiRep) = await _api.LookupFileReportAsync(
                    sha256, ApiWorkKind.ExhaustedLookup, urgentOrder, fileTier, TimeSpan.FromSeconds(90), ct);
                if (apiRep != null) return new QueryCellResult(apiRep, false, true, 100, sw.Elapsed.TotalSeconds, LookupFailure.None);
                if (served) return new QueryCellResult(null, true, true, 100, sw.Elapsed.TotalSeconds, LookupFailure.None);
                return new QueryCellResult(null, false, true, 100, sw.Elapsed.TotalSeconds, LookupFailure.LookupEmpty);
            }

            // Build cell's adaptive resistance plan based on environment capabilities (Tor installed or not).
            var initialRoute = RoutePool.PickInitialRoute();
            bool torPossible = RoutePool.CanUseTor;
            var plan = BuildPlan(initialRoute.IsTor, torPossible, allowUserCaptcha);
            double totalWeight = plan.Sum(s => s.Weight);
            if (totalWeight <= 0) totalWeight = 1;

            // Dynamic per-cell time budget: brisk when only 1-3 files are active, more patient during big sweeps.
            double timeBudgetSec = ComputeTimeBudgetSeconds(torPossible);
            double triedWeight = 0;
            NetworkRoute currentRoute = initialRoute;
            int lastTorCircuit = initialRoute.IsTor ? initialRoute.CircuitIndex : -1;

            for (int idx = 0; idx < plan.Count; idx++)
            {
                ct.ThrowIfCancellationRequested();
                if (_pause != null) await _pause.WaitWhilePausedAsync(ct);

                var step = plan[idx];
                double activeElapsed = Math.Max(0, sw.Elapsed.TotalSeconds - userWaitSec);
                if (idx > 0 && activeElapsed >= timeBudgetSec)
                {
                    Log($"QueryCell {sha256[..12]}… time budget ({timeBudgetSec:0}s) reached at step {idx}; R=100.", LogLevel.Info);
                    break;
                }

                // Backoff with jitter before retry steps
                if (step.BackoffMaxMs > 0)
                {
                    int ms = step.BackoffMinMs == step.BackoffMaxMs
                        ? step.BackoffMinMs
                        : Random.Shared.Next(step.BackoffMinMs, step.BackoffMaxMs + 1);
                    await Task.Delay(ms, ct);
                }

                // Resolve the concrete route for this step (never disrupting other cells!)
                var resolved = await ResolveStepRouteAsync(step.Kind, initialRoute, currentRoute, lastTorCircuit, ct);
                if (resolved is not { } route)
                {
                    // E.g. Tor failed to start; count this step's weight and move on cleanly
                    triedWeight += step.Weight;
                    continue;
                }
                currentRoute = route;
                if (route.IsTor) lastTorCircuit = route.CircuitIndex;

                double rBefore = ComputeResistance(triedWeight, totalWeight, Math.Max(0, sw.Elapsed.TotalSeconds - userWaitSec), timeBudgetSec);
                onStatus?.Invoke(rBefore, $"Tarayıcı [R:{rBefore:0}/100] · {route.Label} · {step.Label}");

                var fp = BrowserFingerprint.Random();
                // Scale browser slot queue wait with live API load: when all browser slots are busy AND
                // API keys sit idle (L ~ 0), overflow cells don't stall 45s behind browsers — they quickly
                // spill over to consult ApiCoordinator while the active browser pool stays 100% utilized.
                // As API pressure L climbs, cells wait patiently (up to 45s) for browser/Tor slots instead.
                TimeSpan slotWait = TimeSpan.FromSeconds(45);
                if (idx == 0 && allowApi && _api.HasUsableKeys)
                {
                    double liveLoad = _api.ComputeLoadScore();
                    double waitSec = 2.0 + (43.0 * Math.Clamp(liveLoad / 100.0, 0.0, 1.0));
                    slotWait = TimeSpan.FromSeconds(waitSec);
                }

                var attempt = await BrowserSessionFactory.RunAttemptAsync(
                    sha256,
                    "",
                    AppConstants.VtGuiFile + sha256,
                    route,
                    fp,
                    wipeProfileSlot: step.WipeSlot,
                    allowUserCaptcha: step.AllowUserCaptcha,
                    maxQueueWait: slotWait,
                    ct);

                userWaitSec += attempt.UserWaitSeconds;

                if (attempt.Outcome == BrowserAttemptOutcome.Cancelled)
                    throw new OperationCanceledException(ct);

                if (attempt.Outcome == BrowserAttemptOutcome.Report && !string.IsNullOrEmpty(attempt.Json))
                {
                    RoutePool.ReportSuccess(route);
                    var report = ParseReport(attempt.Json, sha256);
                    double rFinal = ComputeResistance(triedWeight, totalWeight, Math.Max(0, sw.Elapsed.TotalSeconds - userWaitSec), timeBudgetSec);
                    return new QueryCellResult(report, report == null, false, rFinal, sw.Elapsed.TotalSeconds, LookupFailure.None);
                }

                if (attempt.Outcome == BrowserAttemptOutcome.NotFound)
                {
                    RoutePool.ReportSuccess(route);
                    double rFinal = ComputeResistance(triedWeight, totalWeight, Math.Max(0, sw.Elapsed.TotalSeconds - userWaitSec), timeBudgetSec);
                    return new QueryCellResult(null, true, false, rFinal, sw.Elapsed.TotalSeconds, LookupFailure.None);
                }

                // Update per-route health (isolated to THIS route only)
                if (attempt.Outcome is BrowserAttemptOutcome.Challenged or BrowserAttemptOutcome.CaptchaSolvedButFailed)
                    RoutePool.ReportBlocked(route);
                else if (attempt.Outcome is BrowserAttemptOutcome.TimedOut or BrowserAttemptOutcome.NetworkError)
                    RoutePool.ReportTransportFailure(route);

                triedWeight += step.Weight;
                double rNow = ComputeResistance(triedWeight, totalWeight, Math.Max(0, sw.Elapsed.TotalSeconds - userWaitSec), timeBudgetSec);

                Log($"QueryCell {sha256[..12]}… step {idx} ({route.Label}/{step.Label}) -> {attempt.Outcome} ({attempt.Detail}) [R={rNow:0}/100]", LogLevel.Info);

                // Mid-resistance consultation with ApiCoordinator (or immediate consult if user clicked "API")
                bool shouldConsult = allowApi && _api.HasUsableKeys &&
                    (step.ConsultApiAfter || attempt.Outcome == BrowserAttemptOutcome.UserSwitchedToApi);

                if (shouldConsult)
                {
                    double effectiveR = attempt.Outcome == BrowserAttemptOutcome.UserSwitchedToApi ? Math.Max(rNow, 85.0) : rNow;
                    if (_api.TryAdmitLookup(effectiveR, out double apiLoad))
                    {
                        onStatus?.Invoke(rNow, $"API kabul etti [R:{rNow:0} ≥ Baskı:{apiLoad:0}]");
                        Log($"QueryCell {sha256[..12]}… admitted by ApiCoordinator (R={effectiveR:0.0} >= L={apiLoad:0.0}).", LogLevel.Info);
                        var (served, apiRep) = await _api.LookupFileReportAsync(
                            sha256, ApiWorkKind.AssistLookup, urgentOrder, fileTier, TimeSpan.FromSeconds(45), ct);
                        if (apiRep != null)
                            return new QueryCellResult(apiRep, false, true, rNow, sw.Elapsed.TotalSeconds, LookupFailure.None);
                        if (served)
                            return new QueryCellResult(null, true, true, rNow, sw.Elapsed.TotalSeconds, LookupFailure.None);
                        // API call couldn't get a slot in time -> cell seamlessly resumes its resistance loop!
                        Log($"QueryCell {sha256[..12]}… API assist returned no slot; continuing browser resistance.", LogLevel.Info);
                    }
                    else
                    {
                        onStatus?.Invoke(rNow, $"API yoğun [Baskı:{apiLoad:0}] · direnç sürüyor [R:{rNow:0}/100]");
                        Log($"QueryCell {sha256[..12]}… deferred by ApiCoordinator (R={effectiveR:0.0} < L={apiLoad:0.0}); continuing resistance.", LogLevel.Debug);
                    }
                }
            }

            // Cell reached R = 100 (exhausted all browser/route/identity options or time budget):
            // Unconditional last-resort admission to ApiCoordinator if any API key has daily quota.
            if (allowApi && _api.HasUsableKeys)
            {
                if (_api.TryAdmitLookup(100.0, out double finalLoad))
                {
                    onStatus?.Invoke(100, $"Rezistans tükendi [R:100] · API kuyruğunda (Baskı:{finalLoad:0})");
                    Log($"QueryCell {sha256[..12]}… resistance exhausted (R=100); entering API last-resort queue (L={finalLoad:0.0}).", LogLevel.Info);
                    var (served, apiRep) = await _api.LookupFileReportAsync(
                        sha256, ApiWorkKind.ExhaustedLookup, urgentOrder, fileTier, TimeSpan.FromSeconds(120), ct);
                    if (apiRep != null)
                        return new QueryCellResult(apiRep, false, true, 100, sw.Elapsed.TotalSeconds, LookupFailure.None);
                    if (served)
                        return new QueryCellResult(null, true, true, 100, sw.Elapsed.TotalSeconds, LookupFailure.None);
                }
            }

            return new QueryCellResult(
                null, false, false, 100, sw.Elapsed.TotalSeconds,
                _api.HasUsableKeys ? LookupFailure.LookupEmpty : LookupFailure.UnknownNoKey);
        }
        finally
        {
            Interlocked.Decrement(ref _activeCells);
        }
    }

    static List<ResistanceStep> BuildPlan(bool startWithTor, bool torPossible, bool allowUserCaptcha)
    {
        var steps = new List<ResistanceStep>
        {
            // Step 0 tries a fresh zero-cookie browser first. If it is challenged or all browser slots are
            // busy, it consults ApiCoordinator: when keys sit idle (L ~ 0..11) it gets immediate API help;
            // as minute slots fill past ~60% or uploads pile up (L >= 16..36+), the cell is deferred and
            // continues through cookie/identity/Tor resistance.
            new(StepKind.InitialRouteClean, 16, WipeSlot: false, AllowUserCaptcha: allowUserCaptcha, ConsultApiAfter: true, 0, 0, "sıfır tarayıcı"),
            new(StepKind.SameRouteFreshIdentity, 12, WipeSlot: false, AllowUserCaptcha: false, ConsultApiAfter: true, 1200, 2600, "çerez sil + yeni kimlik"),
        };

        if (torPossible)
        {
            steps.Add(new(StepKind.CrossRouteWipeIdentity, 13, WipeSlot: true, AllowUserCaptcha: allowUserCaptcha, ConsultApiAfter: true, 1500, 3000,
                startWithTor ? "Tor kapat + kimlik sıfırla" : "Tor aç + kimlik sıfırla"));
            steps.Add(new(StepKind.TorAlternateCircuit, 12, WipeSlot: false, AllowUserCaptcha: false, ConsultApiAfter: false, 1500, 3000, "farklı Tor devresi"));
            steps.Add(new(StepKind.TorNewnymWipeProfile, 12, WipeSlot: true, AllowUserCaptcha: allowUserCaptcha, ConsultApiAfter: true, 2000, 4000, "Tor yeni IP + profil sıfırla"));
            steps.Add(new(StepKind.CrossBackOriginalWipe, 11, WipeSlot: true, AllowUserCaptcha: false, ConsultApiAfter: false, 2500, 5000,
                startWithTor ? "Tor'a çapraz dönüş" : "Direkt çapraz dönüş + sıfır kimlik"));
            steps.Add(new(StepKind.TorSecondNewnymCooldown, 12, WipeSlot: true, AllowUserCaptcha: false, ConsultApiAfter: true, 3000, 6000, "Tor yeni IP #2 + soğuma"));
            steps.Add(new(StepKind.FinalCrossOverAttempt, 12, WipeSlot: true, AllowUserCaptcha: allowUserCaptcha, ConsultApiAfter: false, 3000, 6000, "son çaprazlama"));
        }
        else
        {
            // No Tor binary installed: deeper identity + full profile wipe + cooldown retries, normalized to 0..100.
            steps.Add(new(StepKind.CrossBackOriginalWipe, 20, WipeSlot: true, AllowUserCaptcha: allowUserCaptcha, ConsultApiAfter: true, 2500, 4500, "tüm kimlik & profil sıfırla"));
            steps.Add(new(StepKind.SameRouteFreshIdentity, 22, WipeSlot: true, AllowUserCaptcha: false, ConsultApiAfter: true, 4000, 7000, "yeni kimlik + soğuma"));
            steps.Add(new(StepKind.FinalCrossOverAttempt, 30, WipeSlot: true, AllowUserCaptcha: allowUserCaptcha, ConsultApiAfter: false, 5000, 9000, "son sıfır tarayıcı"));
        }

        return steps;
    }

    static async Task<NetworkRoute?> ResolveStepRouteAsync(
        StepKind kind, NetworkRoute initial, NetworkRoute current, int lastTorCircuit, CancellationToken ct)
    {
        switch (kind)
        {
            case StepKind.InitialRouteClean:
                return initial;

            case StepKind.SameRouteFreshIdentity:
                return current;

            case StepKind.CrossRouteWipeIdentity:
                return initial.IsTor
                    ? RoutePool.Direct
                    : await RoutePool.AcquireTorRouteAsync(excludeCircuit: lastTorCircuit, requestNewnym: false, ct);

            case StepKind.TorAlternateCircuit:
                return await RoutePool.AcquireTorRouteAsync(excludeCircuit: lastTorCircuit, requestNewnym: false, ct);

            case StepKind.TorNewnymWipeProfile:
            case StepKind.TorSecondNewnymCooldown:
                return await RoutePool.AcquireTorRouteAsync(excludeCircuit: lastTorCircuit, requestNewnym: true, ct);

            case StepKind.CrossBackOriginalWipe:
                if (!initial.IsTor) return RoutePool.Direct;
                return await RoutePool.AcquireTorRouteAsync(excludeCircuit: lastTorCircuit, requestNewnym: false, ct);

            case StepKind.FinalCrossOverAttempt:
                if (current.IsTor) return RoutePool.Direct;
                return await RoutePool.AcquireTorRouteAsync(excludeCircuit: lastTorCircuit, requestNewnym: true, ct)
                    ?? RoutePool.Direct;

            default:
                return RoutePool.Direct;
        }
    }

    static double ComputeTimeBudgetSeconds(bool torPossible)
    {
        int active = Math.Max(1, ActiveCellCount);
        // Few files active -> snappy (90-140s); larger sweeps -> patient (180-240s) to spare API quota.
        double baseBudget = active <= 3 ? 95.0 : active <= 10 ? 150.0 : 210.0;
        return torPossible ? baseBudget + 30.0 : baseBudget;
    }

    static double ComputeResistance(double triedWeight, double totalWeight, double activeElapsedSec, double timeBudgetSec)
    {
        double s = Math.Clamp(triedWeight / Math.Max(1.0, totalWeight), 0.0, 1.0);
        double t = Math.Clamp(activeElapsedSec / Math.Max(15.0, timeBudgetSec), 0.0, 1.0);
        if (s >= 0.999 || t >= 0.999) return 100.0;
        return Math.Clamp(100.0 * (0.75 * s + 0.25 * t), 0.0, 99.5);
    }

    internal static VtFileReport? ParseReport(string json, string sha256)
    {
        try
        {
            var dto = JsonSerializer.Deserialize<VtResponse<VtFileData>>(json, JsonOpts);
            var report = VtApiClient.MapReport(dto?.Data?.Attributes);
            if (report != null) report.Sha256 ??= sha256;
            return report;
        }
        catch (Exception ex)
        {
            Log("Failed to parse VirusTotal GUI JSON: " + ex.Message, LogLevel.Warning);
            return null;
        }
    }
}
