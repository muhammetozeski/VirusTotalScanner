using System.Collections.Concurrent;
using System.ComponentModel;

namespace VirusTotalScanner;

/// <summary>Tiny IProgress that invokes the callback synchronously (we marshal ourselves).</summary>
internal sealed class ActionProgress<T>(Action<T> action) : IProgress<T>
{
    public void Report(T value) => action(value);
}

/// <summary>
/// Drives the whole scan: enumerate selection -> hash (MD5+SHA256) -> cache check ->
/// VT lookup (rotating keys) -> upload with progress -> poll -> fetch report. Honors the
/// 4/min per-key limit through <see cref="KeyRotator"/>, supports pause/resume/cancel, and
/// marshals all UI-bound mutations through <see cref="UiPost"/>.
/// </summary>
internal sealed class ScanScheduler
{
    readonly KeyRotator _rotator;
    readonly VtApiClient _api;
    readonly HashCache _cache;
    readonly PauseTokenSource _pause = new();

    CancellationTokenSource? _cts;
    SemaphoreSlim? _uploadGate; // MaxUploads: how many files may be SENDING bytes at once (bandwidth)
    SemaphoreSlim? _lookupGate; // MaxConcurrency: how many files may be in the VT network stage at once.
                                // Released before the analysis poll — waiting for VirusTotal to finish is
                                // not work, and holding a slot through it serialized the whole scan.
                                // The local pipeline (hash/trust/cache) runs wider, at core count.
    ConcurrentDictionary<string, SemaphoreSlim>? _md5Gates; // per-run: one lookup per identical content

    /// <summary>Marshals an action to the UI thread (set by the GUI; direct call by default/CLI).</summary>
    public Action<Action> UiPost { get; set; } = a => a();

    public BindingList<ScanItem> Items { get; } = [];

    /// <summary>Targets of the last run that could not be found on disk. Empty on a normal run; the CLI
    /// turns a fully-missing selection into a non-zero exit so a script never reads it as "clean".</summary>
    public IReadOnlyList<string> MissingPaths { get; private set; } = [];

    public event Action<OverallProgress>? ProgressChanged;
    public event Action<ScanItem>? ItemFinished;
    public event Action? Started;
    public event Action? Finished;

    public bool IsRunning { get; private set; }
    public bool IsPaused => _pause.IsPaused;

    // aggregate counters
    int _total, _done, _malicious, _suspicious, _clean, _unknown, _failed, _skipped, _signedSkipped;

    // live throughput / ETA
    readonly System.Diagnostics.Stopwatch _stopwatch = new();
    readonly Queue<long> _recent = new(); // ElapsedMs at each of the last ~30 completions
    readonly object _rateLock = new();

    public ScanScheduler(KeyRotator rotator, VtApiClient api, HashCache cache)
    {
        _rotator = rotator;
        _api = api;
        _cache = cache;
    }

    public void Pause() { _pause.Pause(); Log("Scan paused.", LogLevel.Info); }
    public void Resume() { _pause.Resume(); Log("Scan resumed.", LogLevel.Info); }
    public void Cancel() { try { _cts?.Cancel(); } catch (Exception ex) { Log("Cancel failed: " + ex.Message, LogLevel.Warning); } Log("Scan cancel requested.", LogLevel.Info); }

    // Paths that arrived while a run was active, drained into an automatic follow-up run —
    // a drop / right-click / forwarded path during a scan is queued, never silently discarded.
    readonly object _pendingLock = new();
    readonly List<string> _pendingPaths = [];
    ScanOptions? _pendingOpts;

    /// <summary>Raised (marshalled via <see cref="UiPost"/>) when a scan request arrives while a run
    /// is active and gets queued behind it. Carries the total pending path count.</summary>
    public event Action<int>? PendingQueued;

    public async Task RunAsync(IEnumerable<string> paths, ScanOptions opts, CancellationToken externalCt = default)
    {
        lock (_pendingLock)
        {
            if (IsRunning)
            {
                _pendingPaths.AddRange(paths);
                _pendingOpts = opts;
                int pending = _pendingPaths.Count;
                Log($"Scan already running; queued {pending} path(s) for an automatic follow-up run.", LogLevel.Info);
                UiPost(() => { try { PendingQueued?.Invoke(pending); } catch (Exception ex) { Log("PendingQueued handler failed: " + ex.Message, LogLevel.Warning); } });
                return;
            }
            IsRunning = true; // reserved inside the lock, so two racing requests can't both start
        }

        var runPaths = paths;
        var runOpts = opts;
        bool clearQueue = true; // only the user-initiated first run clears the grid; follow-ups append
        while (true)
        {
            await RunCoreAsync(runPaths, runOpts, clearQueue, externalCt);
            lock (_pendingLock)
            {
                if (_cts?.IsCancellationRequested == true) { _pendingPaths.Clear(); _pendingOpts = null; } // Cancel covers the queued batch too
                if (_pendingPaths.Count == 0) { IsRunning = false; return; }
                runPaths = _pendingPaths.ToArray();
                _pendingPaths.Clear();
                runOpts = _pendingOpts ?? runOpts;
                _pendingOpts = null;
                clearQueue = false;
            }
        }
    }

    /// <summary>One scan pass over one batch of paths. Never touches <see cref="IsRunning"/> — the
    /// pending-queue loop in <see cref="RunAsync"/> owns that flag.</summary>
    async Task RunCoreAsync(IEnumerable<string> paths, ScanOptions opts, bool clearQueue, CancellationToken externalCt)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        var ct = _cts.Token;
        ResetCounters();
        _stopwatch.Restart();
        lock (_rateLock) _recent.Clear();
        if (clearQueue) UiPost(() => Items.Clear());
        try { Started?.Invoke(); } catch (Exception ex) { Log("Started handler failed: " + ex.Message, LogLevel.Warning); }

        var archiveTemps = new List<string>(); // temp folders from archive expansion, cleaned in finally
        try
        {
            if (Settings.ResumeInterruptedScans) ScanSessionStore.SaveRunning(paths, opts.Recurse, opts.BypassTrust);
            KnownGoodDb.Reload();
            var safe = SelectionEnumerator.ParseExtensions(Settings.SafeExtensions);
            var oversize = new List<string>();
            var missing = new List<string>();
            var files = await Task.Run(() => SelectionEnumerator.Expand(
                paths, safe, opts.Recurse, opts.ApplySafeFilter, opts.MaxFileSizeBytes, oversize, missing), ct);
            MissingPaths = missing;
            if (missing.Count > 0)
            {
                // Never let a vanished target read as "scanned, nothing found": a scheduled sweep of a
                // folder that was renamed or is on an unplugged drive would report all-clean forever.
                string list = string.Join(", ", missing.Take(5));
                Log($"Scan target(s) not found ({missing.Count}): {list}", LogLevel.Warning);
                UiStatusHub.Report(Strings.StatusSourceScan,
                    string.Format(Strings.ScanTargetsMissingFormat, missing.Count, list), StatusSeverity.Warning);
            }

            // Archive expansion: swap each ZIP-family archive for its extracted members so each member
            // is hashed and looked up on its own (no upload). Archives we cannot open stay as-is.
            if (opts.ExpandArchives)
                files = await Task.Run(() => ExpandArchives(files, archiveTemps), ct);

            // Risk-weighted ordering: scan the likeliest-malicious files first (cheap local signals).
            if (Settings.RiskWeightedOrdering && files.Count > 1)
                files = await Task.Run(() => files.OrderByDescending(RiskScorer.Score).ToList(), ct);

            _total = files.Count;
            var items = files.Select(f => new ScanItem(f)).ToList();
            UiPost(() => BulkAdd(items));

            // Ledger: show each size-skipped file as a row so the user sees what was excluded and why.
            if (oversize.Count > 0)
            {
                int capMb = (int)(opts.MaxFileSizeBytes / (1024 * 1024));
                var skipped = oversize.Select(f => new ScanItem(f) { Status = ScanStatus.Skipped, SkipReason = string.Format(Strings.SkipReasonTooLargeFormat, capMb) }).ToList();
                UiPost(() => BulkAdd(skipped));
                for (int n = 0; n < oversize.Count; n++) Bump(ref _skipped);
                Log($"{oversize.Count} file(s) skipped by the {capMb} MB size cap.", LogLevel.Info);
            }
            ReportProgress();

            if (items.Count == 0)
            {
                Log("Nothing to scan.", LogLevel.Warning);
                return;
            }

            _uploadGate = new SemaphoreSlim(Math.Max(1, opts.MaxUploads));
            _lookupGate = new SemaphoreSlim(Math.Max(1, opts.MaxConcurrency));
            _md5Gates = new ConcurrentDictionary<string, SemaphoreSlim>(StringComparer.OrdinalIgnoreCase);
            // Worker count has to EXCEED the network gate, or the scan grinds. Every worker that reaches
            // VirusTotal holds a _lookupGate slot for seconds; with as many workers as slots, all of them
            // end up waiting on the network and nothing local moves — even though most of a Windows disk
            // is Microsoft-signed or already cached and needs no network at all. The extra workers keep
            // those cheap decisions flowing at disk speed while the gated ones wait.
            int localDegree = Math.Max(1, opts.MaxConcurrency) + Math.Max(4, Environment.ProcessorCount);
            var po = new ParallelOptions { MaxDegreeOfParallelism = localDegree, CancellationToken = ct };
            await Parallel.ForEachAsync(items, po, async (item, token) => await ProcessAsync(item, opts, token));
        }
        catch (OperationCanceledException)
        {
            Log("Scan cancelled.", LogLevel.Info);
        }
        catch (Exception ex)
        {
            Log("Scan run failed: " + ex, LogLevel.Error);
        }
        finally
        {
            // Keep the session if the user stopped (cancelled) so it can be resumed; clear it on
            // a natural finish. A crash also leaves it (finally never runs) -> resume offered.
            if (!ct.IsCancellationRequested) ScanSessionStore.Clear();
            foreach (var td in archiveTemps) ArchiveExpander.CleanupTemp(td);
            _cache.Flush();
            FingerprintCache.Flush();
            Log($"Fingerprint cache: {FingerprintCache.Hits} reuse(s), {FingerprintCache.Misses} miss(es), {FingerprintCache.Count} entr(ies) held.", LogLevel.Info);
            try { Finished?.Invoke(); } catch (Exception ex) { Log("Finished handler failed: " + ex.Message, LogLevel.Warning); }
            Log("Scan finished.", LogLevel.Info);
        }
    }

    /// <summary>Replaces each expandable archive with its extracted member paths (tracking the temp
    /// folders for cleanup). Archives that fail to open are scanned as the archive file itself.</summary>
    static List<string> ExpandArchives(List<string> files, List<string> tempDirs)
    {
        var result = new List<string>();
        foreach (var f in files)
        {
            if (!ArchiveExpander.IsExpandable(f)) { result.Add(f); continue; }
            var members = ArchiveExpander.ExpandToTemp(f, out var td);
            if (members.Count > 0) { result.AddRange(members); tempDirs.Add(td); }
            else { ArchiveExpander.CleanupTemp(td); result.Add(f); }
        }
        return result;
    }

    async Task ProcessAsync(ScanItem item, ScanOptions opts, CancellationToken ct)
    {
        // Per file, at Debug: on a 300k-file sweep this is the only way to answer "what was it doing
        // when it stopped?" — the aggregate counters cannot point at a single stuck file.
        using var op = OpLog.Begin("File", $"{item.FileName} ({item.SizeText}) — {item.FilePath}");
        try
        {
            await _pause.WaitWhilePausedAsync(ct);

            // Cheapest signal first: a trusted code signature is read from the file handle and needs
            // NO hash, so check it before reading the whole file end-to-end. A trusted-signed file
            // then skips without ever being hashed — a big win on signed-heavy install trees.
            // (Trusted = vouched-for provenance, NOT "clean" — it never shows the green banner.)
            if (opts.SkipTrusted && !opts.BypassTrust)
            {
                var trust = TrustService.Evaluate(item.FilePath);
                item.Trust = trust; // keep the signature signal even when the file is still sent to VT
                if (trust.Trusted) ProductSignerRegistry.RecordTrusted(item.FilePath, trust.Publisher);
                if (TrustService.ShouldSkip(trust, Settings.TrustMicrosoftOnly, Settings.TrustPublisherAllowList))
                {
                    TrustSkip(item, trust.Reason, trust.Publisher);
                    op.Ok("trusted signature — " + trust.Reason);
                    return;
                }
            }

            SetStatus(item, ScanStatus.Hashing);
            string md5, sha256;
            // Reading the file end-to-end is the whole cost of the local stage, and on a repeat sweep
            // the answer is almost always the one from last time. A deliberate re-check (BypassTrust)
            // still hashes for real.
            var known = (Settings.UseFingerprintCache && !opts.BypassTrust) ? FingerprintCache.TryGet(item.FilePath) : null;
            if (known is { } fp)
            {
                (md5, sha256) = (fp.Md5, fp.Sha256);
                op.Step("hashes reused from the fingerprint cache");
            }
            else
            {
                (md5, sha256) = await HashService.ComputeAsync(item.FilePath, ct);
                if (Settings.UseFingerprintCache) FingerprintCache.Put(item.FilePath, md5, sha256);
            }
            UiPost(() => { item.Md5 = md5; item.Sha256 = sha256; });

            // --no-trust (BypassTrust) forces a fresh scan: ignore the local cache too.
            if (opts.UseCache && !opts.BypassTrust)
            {
                var cached = _cache.TryGet(md5, opts.CacheDays, opts.ThreatCacheDays);
                if (cached != null)
                {
                    UiPost(() => { item.Report = cached; item.FromCache = true; });
                    Complete(item, cached);
                    op.Ok($"cache hit — {cached.DetectionCount}/{cached.TotalEngines}");
                    return;
                }
            }

            // Known-good list check needs the hash, so it stays after hashing.
            if (opts.SkipTrusted && !opts.BypassTrust && KnownGoodDb.Contains(md5, sha256))
            {
                TrustSkip(item, Strings.SkipReasonKnownGoodList, null);
                op.Ok("known-good list");
                return;
            }

            // User allowlist ("I marked this clean"): an explicit per-file override, honored unless the
            // user forced a full re-scan with BypassTrust.
            if (!opts.BypassTrust && AllowlistStore.Contains(md5, sha256))
            {
                TrustSkip(item, Strings.SkipReasonUserSaidClean, null);
                op.Ok("allowlisted by the user");
                return;
            }

            // Folder suppression: dev/build-output dirs whose ever-changing hashes the per-file allowlist
            // can't cover.
            if (!opts.BypassTrust && FolderSuppressionStore.Contains(item.FilePath))
            {
                TrustSkip(item, Strings.SkipReasonDevFolder, null);
                op.Ok("suppressed folder");
                return;
            }

            // In-scan dedup: serialize lookups of identical content within one run so duplicate
            // files (node_modules, bundled runtimes, repeated installers) share a single VT/GUI
            // lookup. The first item caches the report; the rest get the cache hit here.
            var dedupGate = _md5Gates!.GetOrAdd(md5, _ => new SemaphoreSlim(1, 1));
            await dedupGate.WaitAsync(ct);
            VtFileReport? report;
            var failure = LookupFailure.None;
            try
            {
                var dup = (opts.UseCache && !opts.BypassTrust) ? _cache.TryGet(md5, opts.CacheDays, opts.ThreatCacheDays) : null;
                if (dup != null) { UiPost(() => item.FromCache = true); report = dup; }
                else (report, failure) = await DoLookupAsync(item, md5, sha256, opts, ct);
            }
            finally { dedupGate.Release(); }

            if (report == null && failure == LookupFailure.NotSubmitted)
            {
                // Not a failure: VirusTotal has never seen it and it is not the kind of file a
                // submission would be spent on. Saying "error" here would paint a disk sweep red.
                UiPost(() => { item.SkipReason = Strings.SkipReasonNotSubmitted; item.Status = ScanStatus.Skipped; });
                Bump(ref _skipped);
                op.Ok("not in VirusTotal, not submitted");
            }
            else if (report == null)
            {
                string reason = failure switch
                {
                    LookupFailure.UnknownNoKey => Strings.ItemErrorUnknownNoKey,
                    LookupFailure.AnalysisTimedOut => string.Format(Strings.ItemErrorAnalysisTimedOutFormat, PollWindowMinutes),
                    _ => Strings.ItemErrorNoReport,
                };
                UiPost(() => item.Error = reason);
                SetStatus(item, ScanStatus.Failed);
                Bump(ref _failed);
                Log($"No report for {item.FileName} ({failure}): {reason}", LogLevel.Warning);
                // Offline self-heal: if we're offline, remember the file to retry when connectivity returns
                // (a real "not found" while online is NOT queued, so 404s don't pile up).
                if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable()) PendingOutbox.Add(item.FilePath);
                op.Fail(failure + " — " + reason);
            }
            else
            {
                UiPost(() => item.Report = report);
                Complete(item, report);
                op.Ok($"{report.DetectionCount}/{report.TotalEngines} detections" + (item.FromCache ? " (cache)" : ""));
            }
        }
        catch (OperationCanceledException)
        {
            SetStatus(item, ScanStatus.Cancelled);
            op.Note("cancelled");
        }
        catch (Exception ex)
        {
            UiPost(() => item.Error = ex.Message);
            SetStatus(item, ScanStatus.Failed);
            Bump(ref _failed);
            if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable()) PendingOutbox.Add(item.FilePath);
            Log($"Scan failed for {item.FileName}: {ex}", LogLevel.Error);
            op.Fail(ex.Message);
            op.Fail(ex.Message);
        }
        finally
        {
            DoneOne();
            // Marshal to the UI thread like ProgressChanged: subscribers mutate the grid/BindingList,
            // and several Parallel workers finish concurrently — a direct call here races the UI.
            UiPost(() => { try { ItemFinished?.Invoke(item); } catch (Exception ex) { Log("ItemFinished handler failed: " + ex.Message, LogLevel.Warning); } });
        }
    }

    /// <summary>The resilient lookup chain for one file (keyless GUI when it is free, API + upload
    /// otherwise, GUI again as the last resort), caching the result. Held under a per-md5 gate so
    /// duplicates in a run share it. Returns the report, or null plus the reason there is none.
    ///
    /// Two things here decide the real throughput of a big scan:
    ///  * The keyless browser can only serve ONE lookup at a time. Queueing every worker behind it
    ///    turned a 16-way scan into a 1-way scan and left the API keys idle, so when a key has room
    ///    right now the browser is skipped instead of waited for.
    ///  * The concurrency slot is released before the analysis poll. Polling is waiting, not working;
    ///    holding a slot through a 15-minute wait is what made uploads run one-after-another.
    /// </summary>
    async Task<(VtFileReport? Report, LookupFailure Failure)> DoLookupAsync(ScanItem item, string md5, string sha256, ScanOptions opts, CancellationToken ct)
    {
        await _pause.WaitWhilePausedAsync(ct);
        SetStatus(item, ScanStatus.LookingUp);

        bool guiAvailable = Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable;
        VtFileReport? report = null;
        var failure = LookupFailure.LookupEmpty;
        bool guiAnswered = false;      // the browser actually ran the lookup (rather than being skipped as busy)
        bool vtHasNeverSeenIt = false; // the API answered 404 — asking any other channel gets the same 404

        await _lookupGate!.WaitAsync(ct);
        int slotHeld = 1;
        void ReleaseSlot() { if (Interlocked.Exchange(ref slotHeld, 0) == 1) _lookupGate!.Release(); }
        try
        {
            if (guiAvailable)
            {
                // When a key can serve this file right now, don't queue behind the single browser —
                // let the API take it and leave the browser for the workers that have no key room.
                var guiWait = _rotator.HasImmediateRoom ? TimeSpan.Zero : Timeout.InfiniteTimeSpan;
                guiAnswered = guiWait == Timeout.InfiniteTimeSpan; // a waited lookup always ran to an answer
                report = await GuiScrapeService.LookupAsync(sha256, ct, guiWait).WaitAsync(ct);
            }

            if (report == null && !_rotator.HasUsableKeys) failure = LookupFailure.UnknownNoKey;

            // Every key parked until the daily reset? Then waiting 75 seconds per file to find that out
            // again is pure delay — go straight to the keyless path, which costs no quota.
            bool apiWorthTrying = _rotator.HasImmediateRoom
                || _rotator.SoonestResetUtc is not { } reset
                || reset - DateTime.UtcNow <= ApiWaitForKey
                || !guiAvailable;

            if (report == null && _rotator.HasUsableKeys && apiWorthTrying)
            {
                var (gotKeySlot, existing) = await TryCallWithRotation(key => _api.GetFileReportAsync(md5, key, ct), ApiWaitForKey, ct);
                report = existing;
                if (report == null && gotKeySlot) vtHasNeverSeenIt = true; // a served 404 is an answer
                if (report == null && gotKeySlot && !ShouldUpload(item.FilePath, opts))
                {
                    failure = LookupFailure.NotSubmitted;
                    Log($"Not in VirusTotal and not submitted (upload policy): {item.FileName}", LogLevel.Debug);
                }
                else if (report == null && gotKeySlot)
                {
                    await _pause.WaitWhilePausedAsync(ct);
                    SetStatus(item, ScanStatus.Uploading);
                    var progress = new ActionProgress<UploadProgress>(p => UiPost(() =>
                    {
                        item.Progress = (int)Math.Round(p.Percent);
                        item.Detail = string.Format(Strings.UploadProgressDetailFormat, p.Percent, FormatBytes(p.BytesSent), FormatBytes(p.TotalBytes), FormatBytes(p.BytesPerSecond));
                    }));
                    await _uploadGate!.WaitAsync(ct);
                    (bool uploaded, string? analysisId) = (false, null);
                    try { (uploaded, analysisId) = await TryCallWithRotation(key => _api.UploadFileAsync(item.FilePath, key, progress, ct), ApiWaitForKey, ct); }
                    finally { _uploadGate.Release(); }

                    if (uploaded && analysisId != null)
                    {
                        SetStatus(item, ScanStatus.Polling);
                        ReleaseSlot(); // waiting for VirusTotal to finish must not block another file's lookup
                        report = await PollUntilCompleteAsync(analysisId, sha256, item, ct);
                        if (report == null) failure = LookupFailure.AnalysisTimedOut;
                    }
                }
            }

            // Last resort: the API was off, spent or refused -> take the keyless browser, waiting for it
            // this time (there is nothing else left to try). Skipped when another channel already gave a
            // definite answer: a file still being analysed, or one the API said outright it has never
            // seen. Both would come back identical from the browser and cost a slot to learn nothing.
            if (report == null && guiAvailable && !guiAnswered && !vtHasNeverSeenIt && !ct.IsCancellationRequested
                && failure is not (LookupFailure.AnalysisTimedOut or LookupFailure.NotSubmitted))
                report = await GuiScrapeService.LookupAsync(sha256, ct, Timeout.InfiniteTimeSpan).WaitAsync(ct);
        }
        finally { ReleaseSlot(); }

        if (report != null && opts.UseCache && report.TotalEngines > 0)
            _cache.Put(md5, report, item.FilePath);

        return (report, report != null ? LookupFailure.None : failure);
    }

    /// <summary>How long one file waits for a free API key before the keyless path is tried instead.
    /// Long enough to ride out the 4-per-minute window, short enough that a day-long quota block does
    /// not park the whole scan.</summary>
    static readonly TimeSpan ApiWaitForKey = TimeSpan.FromSeconds(75);

    /// <summary>Whether an unknown file should actually be submitted. Looking a hash up is cheap and
    /// always happens; submitting is not, so by default only code-shaped files earn one.</summary>
    static bool ShouldUpload(string path, ScanOptions opts) => opts.UploadPolicy switch
    {
        0 => false,
        2 => true,
        _ => FileClass.IsWorthUploading(path),
    };

    /// <summary>
    /// How long to wait before each analysis status check. Every check spends one API request, and the
    /// old schedule was sixty checks fifteen seconds apart — one uploaded file could cost sixty units
    /// out of a 500-a-day key. Free-tier analyses usually finish inside a minute or two, so the first
    /// few checks are close together and the rest back off. Eleven checks now cover a LONGER window
    /// than sixty used to.
    /// </summary>
    static readonly int[] PollDelaysSeconds = [20, 20, 30, 45, 60, 90, 120, 150, 180, 210, 240];
    public static readonly int PollWindowMinutes = PollDelaysSeconds.Sum() / 60;

    /// <summary>Waits for a submitted analysis to finish, then fetches the finished report. Returns null
    /// when the analysis is still running after the whole poll window, which the caller reports as its own
    /// outcome — the file did reach VirusTotal, so it must not be described as "not found".</summary>
    async Task<VtFileReport?> PollUntilCompleteAsync(string analysisId, string sha256, ScanItem item, CancellationToken ct)
    {
        for (int i = 0; i < PollDelaysSeconds.Length; i++)
        {
            ct.ThrowIfCancellationRequested();
            await _pause.WaitWhilePausedAsync(ct);
            await Task.Delay(TimeSpan.FromSeconds(PollDelaysSeconds[i]), ct);

            var (gotKey, info) = await TryCallWithRotation(key => _api.GetAnalysisAsync(analysisId, key, ct), ApiWaitForKey, ct);
            if (!gotKey || info == null)
            {
                // No key free for the status check — keep the analysis alive and try again next tick
                // instead of throwing the whole upload away.
                UiPost(() => item.Detail = Strings.PollWaitingForQuota);
                continue;
            }
            UiPost(() => item.Detail = string.Format(Strings.PollProgressDetailFormat, info.Status, i + 1));
            if (info.IsCompleted)
            {
                var (gotReportKey, finished) = await TryCallWithRotation(key => _api.GetFileReportAsync(sha256, key, ct), ApiWaitForKey, ct);
                if (finished != null) return finished;
                if (!gotReportKey && GuiScrapeService.IsRuntimeAvailable)
                    return await GuiScrapeService.LookupAsync(sha256, ct, Timeout.InfiniteTimeSpan).WaitAsync(ct);
                return null;
            }
        }
        Log($"Analysis {analysisId} for {item.FileName} still unfinished after {PollWindowMinutes} min; giving up.", LogLevel.Warning);
        return null;
    }

    /// <summary>
    /// Runs a VirusTotal call, rotating keys on 429/auth failures. Returns
    /// (false, default) when no key could be obtained within <paramref name="maxWait"/> or every key
    /// refused the request — the caller then falls back to the keyless path instead of an exception.
    /// This is what stops a scan sitting still: the old version kept re-acquiring keys and throwing,
    /// which turned a spent daily quota into hours of 429 traffic and zero progress.
    /// </summary>
    async Task<(bool Served, T? Value)> TryCallWithRotation<T>(Func<string, Task<T>> call, TimeSpan maxWait, CancellationToken ct)
    {
        int maxAttempts = Math.Max(2, Math.Min(_rotator.UsableKeyCount + 2, 8));
        var deadline = DateTime.UtcNow + maxWait;
        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            var left = deadline - DateTime.UtcNow;
            if (left <= TimeSpan.Zero) return (false, default);

            string? key = await _rotator.AcquireAsync(left, ct);
            if (key == null) return (false, default);
            try
            {
                // WaitAsync guarantees cancellation wins on time even if a slow HTTP path honors the token late (principle 43).
                var value = await call(key).WaitAsync(ct);
                _rotator.ReportSuccess(key);
                return (true, value);
            }
            catch (VtRateLimitException ex) { _rotator.ReportRateLimited(key, ex.RetryAfter); }
            catch (VtAuthException) { _rotator.ReportAuthError(key); }
            catch (HttpRequestException ex)
            {
                // A transport failure while Tor is carrying the traffic usually means a bad exit node.
                NetworkBlockMonitor.ReportTorPathFailure("api:" + ex.HttpRequestError);
                Log("VirusTotal API transport failure: " + ex.Message, LogLevel.Warning);
                return (false, default);
            }
        }
        return (false, default);
    }

    // ---- progress bookkeeping ----

    void SetStatus(ScanItem item, ScanStatus status) => UiPost(() => item.Status = status);

    void Complete(ScanItem item, VtFileReport report)
    {
        SetStatus(item, ScanStatus.Completed);
        PendingOutbox.Remove(item.FilePath); // healed: this file finally got a verdict
        switch (VerdictClassifier.Of(report))
        {
            case VerdictClass.Malicious:
                // Within "threat", the highest band is counted as malicious and the rest as suspicious.
                bool topBand = ReferenceEquals(VerdictCategories.Classify(report.DetectionCount), VerdictCategories.All[^1]);
                if (topBand) Bump(ref _malicious); else Bump(ref _suspicious);
                break;
            case VerdictClass.Suspicious: Bump(ref _suspicious); break;
            case VerdictClass.Clean: Bump(ref _clean); break;
            default: Bump(ref _unknown); break;
        }
    }

    void TrustSkip(ScanItem item, string reason, string? publisher)
    {
        UiPost(() => { item.SkipReason = reason; item.Publisher = publisher; item.Status = ScanStatus.TrustedSkipped; });
        Bump(ref _signedSkipped);
        Log($"VT skipped (trusted): {item.FileName} — {reason}", LogLevel.Info);
    }

    /// <summary>Add many items to the grid-bound list in chunks, suppressing per-item ListChanged so the
    /// DataGridView repaints once per chunk instead of once per row — adding tens of thousands of files
    /// no longer freezes the window for seconds at scan start. Runs on the UI thread (caller marshals).</summary>
    void BulkAdd(List<ScanItem> toAdd)
    {
        const int chunk = 500;
        for (int i = 0; i < toAdd.Count; i += chunk)
        {
            Items.RaiseListChangedEvents = false;
            try { for (int j = i, end = Math.Min(i + chunk, toAdd.Count); j < end; j++) Items.Add(toAdd[j]); }
            finally { Items.RaiseListChangedEvents = true; Items.ResetBindings(); }
        }
    }

    void DoneOne()
    {
        Interlocked.Increment(ref _done);
        lock (_rateLock) { _recent.Enqueue(_stopwatch.ElapsedMilliseconds); while (_recent.Count > 30) _recent.Dequeue(); }
        ReportProgress();
    }

    /// <summary>Rolling files/sec over the recent window + a remaining-time estimate, so trusted-skip
    /// and cache hits (near-instant) at the start don't skew the rate against slow VT uploads.</summary>
    (double Rate, TimeSpan? Remaining) ComputeRate(int total, int done)
    {
        lock (_rateLock)
        {
            if (_recent.Count < 2) return (0, null);
            long span = _recent.Last() - _recent.First();
            if (span <= 0) return (0, null);
            double rate = (_recent.Count - 1) / (span / 1000.0);
            int left = Math.Max(0, total - done);
            TimeSpan? rem = rate > 0 ? TimeSpan.FromSeconds(left / rate) : null;
            return (rate, rem);
        }
    }
    static void Bump(ref int counter) { Interlocked.Increment(ref counter); }

    void ResetCounters() { _total = _done = _malicious = _suspicious = _clean = _unknown = _failed = _skipped = _signedSkipped = 0; }

    void ReportProgress()
    {
        var p = new OverallProgress
        {
            Total = _total,
            Done = _done,
            Malicious = _malicious,
            Suspicious = _suspicious,
            Clean = _clean,
            Unknown = _unknown,
            Failed = _failed,
            Skipped = _skipped,
            SignedSkipped = _signedSkipped,
        };
        var (rate, rem) = ComputeRate(_total, _done);
        p.Elapsed = _stopwatch.Elapsed;
        p.FilesPerSec = rate;
        p.Remaining = rem;
        UiPost(() => { try { ProgressChanged?.Invoke(p); } catch (Exception ex) { Log("ProgressChanged handler failed: " + ex.Message, LogLevel.Warning); } });
    }
}
