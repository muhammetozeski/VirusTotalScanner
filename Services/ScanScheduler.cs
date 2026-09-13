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
    public void Cancel()
    {
        try { _cts?.Cancel(); } catch (Exception ex) { Log("Cancel failed: " + ex.Message, LogLevel.Warning); }
        // A cancelled run is not a paused one. Left closed, the gate outlived the run and every worker of
        // the NEXT scan stopped on its first line, forever: 24 files "started", none ended, 0 done.
        if (_pause.IsPaused) { _pause.Resume(); Log("Pause lifted by the cancel.", LogLevel.Info); }
        Log("Scan cancel requested.", LogLevel.Info);
    }

    // Paths that arrived while a run was active, drained into an automatic follow-up run —
    // a drop / right-click / forwarded path during a scan is queued, never silently discarded.
    readonly object _pendingLock = new();
    readonly List<string> _pendingPaths = [];
    ScanOptions? _pendingOpts;
    /// <summary>Targets of the pass currently running, used to drop a queued request the running pass
    /// already covers.</summary>
    string[] _activeTargets = [];

    /// <summary>Raised (marshalled via <see cref="UiPost"/>) when a scan request arrives while a run
    /// is active and gets queued behind it. Carries the total pending path count.</summary>
    public event Action<int>? PendingQueued;

    bool _runIsAutomatic; // the pass running now was started by the app, not the user
    bool _preempting;     // a user request cancelled that automatic pass and waits in _pendingPaths

    /// <summary>True while the running pass is one the app started on its own.</summary>
    public bool IsRunningAutomatic { get { lock (_pendingLock) return IsRunning && _runIsAutomatic; } }

    public async Task RunAsync(IEnumerable<string> paths, ScanOptions opts, CancellationToken externalCt = default)
    {
        lock (_pendingLock)
        {
            if (IsRunning && _runIsAutomatic && !opts.Automatic)
            {
                // The user asked for a scan while the app was busy with one of its own (a retry of the
                // pending outbox, an auto-resumed session). Queueing behind it put the user's folder at
                // the back of an unrelated list that could run for hours; the window showed that list
                // instead of the folder that was right-clicked. The automatic pass stops and the user's
                // request runs next, on a cleared table. Files the automatic pass did not reach stay in
                // their store and are retried another time.
                _pendingPaths.Clear();
                _pendingPaths.AddRange(paths);
                _pendingOpts = opts;
                _preempting = true;
                Log($"User scan request replaces the running automatic scan: {string.Join(", ", paths.Take(4))}", LogLevel.Info);
                try { _cts?.Cancel(); } catch (Exception ex) { Log("Stopping the automatic scan failed: " + ex.Message, LogLevel.Warning); }
                return;
            }
            if (IsRunning)
            {
                // Anything the running pass already walks is dropped, not queued. An auto-resumed
                // session and the path on the command line are the same drive; queueing the second one
                // scheduled a whole second sweep of C:\ to start the moment the first one ended.
                // A forced re-check or a hand-picked file is never dropped: those mean "this one, now",
                // and the running pass would answer them from the cache or not reach them for hours.
                var (fresh, covered) = opts.BypassTrust || opts.ExplicitFileSelection
                    ? (paths.ToList(), new List<string>())
                    : SplitAlreadyCovered(paths);
                if (covered.Count > 0)
                    Log($"Scan request covered by the running pass; {covered.Count} path(s) dropped: {string.Join(", ", covered.Take(5))}", LogLevel.Info);
                if (fresh.Count == 0) return;

                _pendingPaths.AddRange(fresh);
                // An automatic request joining a queued user request must not turn the user's batch into
                // an automatic one (which the next user request would then cancel).
                if (!(opts.Automatic && _pendingOpts is { Automatic: false })) _pendingOpts = opts;
                int pending = _pendingPaths.Count;
                Log($"Scan already running; queued {pending} path(s) for an automatic follow-up run.", LogLevel.Info);
                UiPost(() => { try { PendingQueued?.Invoke(pending); } catch (Exception ex) { Log("PendingQueued handler failed: " + ex.Message, LogLevel.Warning); } });
                return;
            }
            IsRunning = true; // reserved inside the lock, so two racing requests can't both start
            _runIsAutomatic = opts.Automatic;
            _activeTargets = paths.ToArray();
        }

        var runPaths = paths;
        var runOpts = opts;
        bool clearQueue = true; // only the user-initiated first run clears the grid; follow-ups append
        while (true)
        {
            await RunCoreAsync(runPaths, runOpts, clearQueue, externalCt);
            lock (_pendingLock)
            {
                bool preempted = _preempting;
                _preempting = false;
                if (!preempted && _cts?.IsCancellationRequested == true) { _pendingPaths.Clear(); _pendingOpts = null; } // Cancel covers the queued batch too
                if (_pendingPaths.Count == 0) { IsRunning = false; _runIsAutomatic = false; _activeTargets = []; return; }
                var next = _pendingPaths.ToArray();
                runPaths = next;
                _activeTargets = next;
                _pendingPaths.Clear();
                runOpts = _pendingOpts ?? runOpts;
                _pendingOpts = null;
                _runIsAutomatic = runOpts.Automatic;
                clearQueue = preempted; // the user's request replaces the automatic list; a follow-up appends
            }
        }
    }

    /// <summary>Splits a request into the paths the running pass does not already cover and the ones it
    /// does. A path is covered when it IS an active target or sits under one; the recursive walk of that
    /// target will reach it anyway. Caller holds <see cref="_pendingLock"/>.</summary>
    (List<string> Fresh, List<string> Covered) SplitAlreadyCovered(IEnumerable<string> paths)
    {
        var fresh = new List<string>();
        var covered = new List<string>();
        foreach (var p in paths)
        {
            if (string.IsNullOrWhiteSpace(p)) continue;
            string full;
            try { full = Path.GetFullPath(p); }
            catch (Exception ex) { Log($"Queued path '{p}' could not be normalised ({ex.Message}); treating it as new.", LogLevel.Warning); fresh.Add(p); continue; }

            bool inside = _activeTargets.Any(t =>
            {
                string tf;
                try { tf = Path.GetFullPath(t); } catch { return false; }
                if (string.Equals(tf, full, StringComparison.OrdinalIgnoreCase)) return true;
                if (!tf.EndsWith(Path.DirectorySeparatorChar)) tf += Path.DirectorySeparatorChar;
                return full.StartsWith(tf, StringComparison.OrdinalIgnoreCase);
            });

            (inside ? covered : fresh).Add(p);
        }
        return (fresh, covered);
    }

    /// <summary>One scan pass over one batch of paths. Never touches <see cref="IsRunning"/> — the
    /// pending-queue loop in <see cref="RunAsync"/> owns that flag.</summary>
    async Task RunCoreAsync(IEnumerable<string> paths, ScanOptions opts, bool clearQueue, CancellationToken externalCt)
    {
        using var runOp = OpLog.Begin("Scan run",
            $"targets=[{string.Join(", ", paths.Take(4))}{(paths.Count() > 4 ? ", …" : "")}] recurse={opts.Recurse} "
            + $"concurrency={opts.MaxConcurrency} uploads={opts.MaxUploads} uploadPolicy={opts.UploadPolicy} "
            + $"cacheDays={opts.CacheDays}/{opts.ThreatCacheDays} clearQueue={clearQueue}");
        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        var ct = _cts.Token;
        // A user request that arrived between two passes cancelled the previous pass's token, not this
        // one. This automatic pass must not start in its place.
        lock (_pendingLock) if (_preempting) _cts.Cancel();
        // Pause belongs to the run it was pressed in. A new run always starts moving.
        if (_pause.IsPaused) { _pause.Resume(); runOp.Step("pause left over from the previous run lifted"); }
        ResetCounters();
        _stopwatch.Restart();
        lock (_rateLock) _recent.Clear();
        if (clearQueue) UiPost(() => Items.Clear());
        try { Started?.Invoke(); } catch (Exception ex) { Log("Started handler failed: " + ex.Message, LogLevel.Warning); }

        var archiveTemps = new List<string>(); // temp folders from archive expansion, cleaned in finally
        List<ScanItem> items = [];             // this run's rows, so a cancel can close the ones never reached
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
            items = files.Select(f => new ScanItem(f)).ToList();
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
            _pendingAnalyses.Clear(); // a cancelled run can leave watchers behind; they are not this run's

            // Worker count has to EXCEED the network gate, or the scan grinds. Every worker that reaches
            // VirusTotal holds a _lookupGate slot for seconds; with as many workers as slots, all of them
            // end up waiting on the network and nothing local moves — even though most of a Windows disk
            // is Microsoft-signed or already cached and needs no network at all. The extra workers keep
            // those cheap decisions flowing at disk speed while the gated ones wait.
            int localDegree = Math.Max(1, opts.MaxConcurrency) + Math.Max(4, Environment.ProcessorCount);
            var po = new ParallelOptions { MaxDegreeOfParallelism = localDegree, CancellationToken = ct };
            using var heartbeat = StartHeartbeat(items.Count, localDegree, ct);
            using var quietList = SuspendItemNotifications();
            using var finishedFlush = StartFinishedFlush();
            using var politeCpu = YieldToTheRestOfTheMachine(items.Count);

            _netQueue = System.Threading.Channels.Channel.CreateUnbounded<NetworkJob>(
                new System.Threading.Channels.UnboundedChannelOptions { SingleReader = false, SingleWriter = false });
            int netWorkers = Math.Max(1, opts.MaxConcurrency);
            var netTasks = Enumerable.Range(0, netWorkers).Select(i => NetworkWorkerAsync(i, ct)).ToArray();
            Log($"Network stage started with {netWorkers} worker(s); disk stage runs {localDegree} wide.", LogLevel.Info);

            await Parallel.ForEachAsync(items, po, async (item, token) => await ProcessAsync(item, opts, token));

            // The disk is done; tell the network stage no more files are coming and let it finish.
            using (var drainNet = OpLog.Begin("Drain network queue", $"in: {_netQueue.Reader.Count} file(s) still queued"))
            {
                _netQueue.Writer.TryComplete();
                await Task.WhenAll(netTasks);
                drainNet.Ok("out: network stage closed");
            }

            // Uploaded files whose analysis is still running finish on the background watcher; the run
            // is not over until they land, or the whole sweep would report them as never answered.
            if (!_pendingAnalyses.IsEmpty)
            {
                using var drain = OpLog.Begin("Drain pending analyses", $"in: {_pendingAnalyses.Count} still running");
                await Task.WhenAll(_pendingAnalyses.Values.ToArray());
                drain.Ok($"out: {_pendingAnalyses.Count} left");
            }
        }
        catch (OperationCanceledException)
        {
            Log("Scan cancelled.", LogLevel.Info);
            runOp.Note("cancelled");
        }
        catch (Exception ex)
        {
            Log("Scan run failed: " + ex, LogLevel.Error);
            runOp.Fail(ex.Message);
        }
        finally
        {
            // Keep the session if the user stopped (cancelled) so it can be resumed; clear it on
            // a natural finish. A crash also leaves it (finally never runs) -> resume offered.
            if (!ct.IsCancellationRequested) ScanSessionStore.Clear();
            else MarkUnfinishedCancelled(items, runOp);
            foreach (var td in archiveTemps) ArchiveExpander.CleanupTemp(td);
            _cache.Flush();
            FingerprintCache.Flush();
            Log($"Fingerprint cache: {FingerprintCache.Hits} reuse(s), {FingerprintCache.Misses} miss(es), {FingerprintCache.Count} entr(ies) held.", LogLevel.Info);
            try { Finished?.Invoke(); } catch (Exception ex) { Log("Finished handler failed: " + ex.Message, LogLevel.Warning); }
            Log("Scan finished.", LogLevel.Info);
            runOp.Ok($"{_done}/{_total} done — malicious={_malicious} suspicious={_suspicious} clean={_clean} "
                + $"unknown={_unknown} failed={_failed} skipped={_skipped} trustSkipped={_signedSkipped}");
        }
    }

    /// <summary>
    /// Closes every row a cancelled run never finished. Files the workers had not reached, and files
    /// still waiting in the network queue, kept the status they had when the run stopped, so the table
    /// said "Sırada" for thousands of files that nothing was ever going to touch again. One trip to the
    /// UI thread and one grid reset for the whole batch.
    /// </summary>
    void MarkUnfinishedCancelled(List<ScanItem> items, OpLog runOp)
    {
        if (items.Count == 0) return;
        UiPost(() =>
        {
            bool raising = Items.RaiseListChangedEvents;
            Items.RaiseListChangedEvents = false;
            int closed = 0;
            try
            {
                foreach (var it in items)
                {
                    if (it.Status is not (ScanStatus.Queued or ScanStatus.AwaitingLookup or ScanStatus.Hashing
                        or ScanStatus.LookingUp or ScanStatus.Uploading or ScanStatus.Polling)) continue;
                    it.Status = ScanStatus.Cancelled;
                    closed++;
                }
            }
            catch (Exception ex) { Log("Closing the unfinished rows failed: " + ex.Message, LogLevel.Warning); }
            finally
            {
                Items.RaiseListChangedEvents = raising;
                if (raising) Items.ResetBindings();
                Log($"Run cancelled: {closed} unfinished row(s) marked cancelled.", LogLevel.Info);
            }
        });
        runOp.Step("unfinished rows handed to the UI to be marked cancelled");
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
        bool handedOff = false;
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
            ItemWrite(() => { item.Md5 = md5; item.Sha256 = sha256; });

            // --no-trust (BypassTrust) forces a fresh scan: ignore the local cache too.
            if (opts.UseCache && !opts.BypassTrust)
            {
                var cached = _cache.TryGet(md5, opts.CacheDays, opts.ThreatCacheDays);
                if (cached != null)
                {
                    ItemWrite(() => { item.Report = cached; item.FromCache = true; });
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

            // Scope: on a folder sweep set to code-shaped files only, a font or a Store icon does not
            // get a lookup. It still went through hashing and the cache, so a KNOWN verdict above would
            // already have been reported; this only stops spending quota to be told "never seen it".
            if (opts.LookupPolicy == 1 && !opts.ExplicitFileSelection && !opts.BypassTrust
                && !FileClass.IsWorthUploading(item.FilePath))
            {
                ItemWrite(() => { item.SkipReason = Strings.SkipReasonNotCodeFile; item.Status = ScanStatus.Skipped; });
                Bump(ref _skipped);
                op.Ok("not a code file — no lookup spent");
                return;
            }

            // Everything above was local and costs milliseconds. What is left needs VirusTotal, which
            // costs seconds to minutes and is rate-limited to about a lookup a second across every key.
            // A worker that carries a file through that stage is a worker not hashing the next one, and
            // there are only two dozen of them: the sweep dropped from 2,587 files a minute to 20 the
            // moment they were all queued on the network. So the file is handed to the network stage,
            // which runs on its own bounded set of tasks, and this worker goes back to the disk.
            SetStatus(item, ScanStatus.AwaitingLookup);
            if (!_netQueue!.Writer.TryWrite(new NetworkJob(item, md5, sha256, opts)))
            {
                // An unbounded channel only refuses after it is completed, i.e. the run is ending.
                Log($"Network queue closed; {item.FileName} was not looked up.", LogLevel.Warning);
                op.Note("network queue closed");
                return;
            }
            handedOff = true;
            op.Note("local stage done — handed to the network queue");
        }
        catch (OperationCanceledException)
        {
            SetStatus(item, ScanStatus.Cancelled);
            op.Note("cancelled");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A disk sweep walks live temp files and folders this account cannot open. Neither is a
            // scan error, and reporting them as failures painted the whole run red. The row says which
            // one it was and the file is counted as not examined — it is not quietly called clean.
            string reason = ex is UnauthorizedAccessException ? Strings.SkipReasonNoAccess : Strings.SkipReasonFileLocked;
            ItemWrite(() => { item.SkipReason = reason; item.Status = ScanStatus.Skipped; });
            Bump(ref _skipped);
            Log($"Not readable, skipped: {item.FilePath} — {ex.Message}", LogLevel.Warning);
            op.Note("not readable — " + reason);
        }
        catch (Exception ex)
        {
            ItemWrite(() => item.Error = ex.Message);
            SetStatus(item, ScanStatus.Failed);
            Bump(ref _failed);
            if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable()) PendingOutbox.Add(item.FilePath);
            Log($"Scan failed for {item.FileName}: {ex}", LogLevel.Error);
            op.Fail(ex.Message);
        }
        finally
        {
            if (!handedOff) FinishItem(item);
        }
    }

    /// <summary>Turns a lookup result into the item's visible outcome and bumps the matching counter.
    /// Shared by the inline path and by the background analysis watcher, so a file that finished late
    /// is reported exactly like one that finished on its worker.</summary>
    void RecordOutcome(ScanItem item, VtFileReport? report, LookupFailure failure, OpLog op)
    {
        if (report == null && failure == LookupFailure.NotSubmitted)
        {
            // Not a failure: VirusTotal has never seen it and it is not the kind of file a
            // submission would be spent on. Saying "error" here would paint a disk sweep red.
            ItemWrite(() => { item.SkipReason = Strings.SkipReasonNotSubmitted; item.Status = ScanStatus.Skipped; });
            Bump(ref _skipped);
            op.Ok("not in VirusTotal, not submitted");
        }
        else if (report == null && failure is LookupFailure.LookupEmpty or LookupFailure.UnknownNoKey)
        {
            // Never asked, rather than asked and got a bad answer: the keys were spent and the keyless
            // channel was blocked. Calling that a scan failure would report a file as broken when
            // nothing about it was ever checked. It is queued for the next run instead.
            ItemWrite(() => { item.SkipReason = Strings.SkipReasonNotAskedYet; item.Status = ScanStatus.Skipped; });
            Bump(ref _skipped);
            PendingOutbox.Add(item.FilePath);
            op.Note("not asked yet — no channel could serve it; queued for the next run");
        }
        else if (report == null)
        {
            string reason = failure switch
            {
                LookupFailure.AnalysisTimedOut => string.Format(Strings.ItemErrorAnalysisTimedOutFormat, PollWindowMinutes),
                _ => Strings.ItemErrorNoReport,
            };
            ItemWrite(() => item.Error = reason);
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
            ItemWrite(() => item.Report = report);
            Complete(item, report);
            op.Ok($"{report.DetectionCount}/{report.TotalEngines} detections" + (item.FromCache ? " (cache)" : ""));
        }
    }

    /// <summary>A sweep large enough that the machine has to keep being usable while it runs.</summary>
    const int SweepSizeThatNeedsToBePolite = 5000;

    /// <summary>
    /// Drops the process to below-normal priority for the length of a large sweep, and puts it back
    /// afterwards. Two dozen workers reading the disk flat out at normal priority make the whole machine
    /// lag — windows stop coming to the front, everything else waits behind the scan. Below-normal keeps
    /// every bit of idle capacity for the sweep while whatever the user is doing goes first.
    /// </summary>
    IDisposable? YieldToTheRestOfTheMachine(int fileCount)
    {
        if (fileCount < SweepSizeThatNeedsToBePolite) return null;
        try
        {
            var me = System.Diagnostics.Process.GetCurrentProcess();
            var previous = me.PriorityClass;
            if (previous != System.Diagnostics.ProcessPriorityClass.Normal) return null; // the user set it; leave it
            me.PriorityClass = System.Diagnostics.ProcessPriorityClass.BelowNormal;
            Log($"Sweep of {fileCount} file(s): process priority lowered to BelowNormal so the machine stays usable.", LogLevel.Info);
            return new Restore(() =>
            {
                try
                {
                    System.Diagnostics.Process.GetCurrentProcess().PriorityClass = previous;
                    Log("Sweep finished: process priority restored to " + previous + ".", LogLevel.Info);
                }
                catch (Exception ex) { Log("Could not restore process priority: " + ex.Message, LogLevel.Warning); }
            });
        }
        catch (Exception ex) { Log("Could not lower process priority: " + ex.Message, LogLevel.Warning); return null; }
    }

    readonly List<ScanItem> _finished = [];
    readonly object _finishedLock = new();

    /// <summary>
    /// Counts one item done and queues its announcement.
    ///
    /// <see cref="ItemFinished"/> is marshalled to the UI thread because subscribers mutate the grid,
    /// but one post per file is 460 posts a second on a fast sweep and the message pump cannot answer
    /// anything else. Finished items are collected here and announced in batches a few times a second
    /// instead — same event, same order, one post per batch.
    /// </summary>
    void FinishItem(ScanItem item)
    {
        DoneOne();
        lock (_finishedLock) _finished.Add(item);
    }

    /// <summary>Announces everything finished since the last flush, in one trip to the UI thread.</summary>
    void FlushFinished()
    {
        ScanItem[] batch;
        lock (_finishedLock)
        {
            if (_finished.Count == 0) return;
            batch = [.. _finished];
            _finished.Clear();
        }
        UiPost(() =>
        {
            foreach (var it in batch)
            {
                try { ItemFinished?.Invoke(it); }
                catch (Exception ex) { Log("ItemFinished handler failed: " + ex.Message, LogLevel.Warning); }
            }
        });
    }

    /// <summary>Flushes finished items to the UI a few times a second for the length of a run.</summary>
    IDisposable StartFinishedFlush()
    {
        var timer = new System.Threading.Timer(_ =>
        {
            try { FlushFinished(); FlushProgress(); }
            catch (Exception ex) { Log("Finished flush failed: " + ex.Message, LogLevel.Warning); }
        }, null, TimeSpan.FromMilliseconds(250), TimeSpan.FromMilliseconds(250));
        return new Restore(() => { try { timer.Dispose(); } catch { } FlushFinished(); FlushProgress(); });
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
        ItemWrite(() => { item.Detail = null; item.Status = ScanStatus.LookingUp; }); // a retry note from the queue no longer applies

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
                //
                // The wait is bounded even when no key has room. The browser serves one lookup at a
                // time; waiting on it forever meant every network worker queued behind that one
                // instance while the per-minute key windows rolled over unused, and the measured rate
                // was 15 lookups a minute against the 56 the keys allow. A worker that does not get
                // the browser quickly falls through to the API below and waits for a key instead.
                var guiWait = _rotator.HasImmediateRoom ? TimeSpan.Zero : GuiWaitWhenKeysBusy;
                report = await GuiScrapeService.LookupAsync(sha256, ct, guiWait).WaitAsync(ct);
                guiAnswered = report != null;
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
                    var progress = new ActionProgress<UploadProgress>(p => ItemWrite(() =>
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
                        // ...and it must not hold a scan WORKER either. An analysis takes minutes; a
                        // worker parked on one is a worker not hashing the next file, and with enough of
                        // them parked the sweep stops moving even though most of the disk needs no
                        // network at all. The wait goes to a background watcher and this file is
                        // finished by whatever that watcher gets back.
                        WatchAnalysis(item, analysisId, md5, sha256, opts, ct);
                        return (null, LookupFailure.AnalysisPending);
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

    /// <summary>
    /// Writes one line a minute saying where the sweep actually is: how many files are done out of how
    /// many, what the free paths absorbed, how many are waiting on VirusTotal, and the rate. Without it
    /// a 340k-file run leaves nothing in the log between "started" and "finished" but a per-file trace
    /// nobody can add up, and a stall looks exactly like slow progress.
    /// </summary>
    IDisposable StartHeartbeat(int total, int workers, CancellationToken ct)
    {
        var started = DateTime.UtcNow;
        int lastDone = 0;
        var timer = new System.Threading.Timer(_ =>
        {
            try
            {
                int done = Volatile.Read(ref _done);
                var elapsed = DateTime.UtcNow - started;
                double perMin = elapsed.TotalMinutes > 0 ? done / elapsed.TotalMinutes : 0;
                string eta = perMin > 0.01 ? TimeSpan.FromMinutes((total - done) / perMin).ToString(@"d\g\ hh\:mm") : "?";
                Log($"Sweep progress: {done}/{total} ({(total > 0 ? done * 100.0 / total : 0):0.0}%), "
                    + $"+{done - lastDone} in the last minute, {perMin:0.0}/min, ETA {eta} — "
                    + $"clean={_clean} malicious={_malicious} suspicious={_suspicious} unknown={_unknown} "
                    + $"skipped={_skipped} signed={_signedSkipped} failed={_failed}; "
                    + $"queued for VirusTotal={NetworkQueueDepth}, waiting on analysis={_pendingAnalyses.Count}, workers={workers}, "
                    + $"keys usable={_rotator.UsableKeyCount} immediateRoom={_rotator.HasImmediateRoom}",
                    LogLevel.Info);
                lastDone = done;
            }
            catch (Exception ex) { Log("Heartbeat failed: " + ex.Message, LogLevel.Warning); }
        }, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        ct.Register(() => { try { timer.Change(Timeout.Infinite, Timeout.Infinite); } catch (Exception ex) { Log("Heartbeat stop failed: " + ex.Message, LogLevel.Warning); } });
        return timer;
    }

    /// <summary>One file that finished its local stage and now needs VirusTotal.</summary>
    readonly record struct NetworkJob(ScanItem Item, string Md5, string Sha256, ScanOptions Options, int Attempt = 0);

    /// <summary>How many times a file goes back to the queue before it is reported as unanswered. Each
    /// retry waits for a channel first, so this is attempts, not a spin.</summary>
    const int MaxLookupAttempts = 20;

    long _channelsHeldUntilTicks;

    /// <summary>Parks every network worker for a while after a lookup found no channel able to answer.
    /// Without it the workers race through the whole queue against a wall — thousands of files a minute,
    /// none of them actually asked about.</summary>
    void HoldOffChannels(string why)
    {
        var until = DateTime.UtcNow + ChannelHoldOff;
        if (_rotator.SoonestResetUtc is { } reset && reset > DateTime.UtcNow && reset < until) until = reset;

        long ticks = until.Ticks;
        long was = Interlocked.Read(ref _channelsHeldUntilTicks);
        if (ticks > was)
        {
            Interlocked.Exchange(ref _channelsHeldUntilTicks, ticks);
            Log($"Network stage holding until {until:HH:mm:ss} UTC — {why}.", LogLevel.Info);
        }
    }

    static readonly TimeSpan ChannelHoldOff = TimeSpan.FromSeconds(30);

    /// <summary>Waits out any hold-off before the next lookup.</summary>
    async Task WaitForAChannelAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            long until = Interlocked.Read(ref _channelsHeldUntilTicks);
            var left = new DateTime(until, DateTimeKind.Utc) - DateTime.UtcNow;
            if (left <= TimeSpan.Zero) return;
            await Task.Delay(left > ChannelHoldOff ? ChannelHoldOff : left, ct);
        }
    }

    /// <summary>Files handed over by the scan workers, waiting for the network stage. Unbounded on
    /// purpose: the entries are references to items that already exist, and a bounded channel would
    /// push the backpressure back onto the disk workers — which is exactly what this separates.</summary>
    System.Threading.Channels.Channel<NetworkJob>? _netQueue;

    /// <summary>How many files have finished hashing and are waiting their turn at VirusTotal.</summary>
    public int NetworkQueueDepth => _netQueue?.Reader.Count ?? 0;

    /// <summary>
    /// Runs the VirusTotal stage for one file at a time, forever, until the queue is completed. As many
    /// of these run as the concurrency setting allows; nothing else in the scan waits on them.
    /// </summary>
    async Task NetworkWorkerAsync(int index, CancellationToken ct)
    {
        using var op = OpLog.Begin($"Network worker {index}");
        int handled = 0;
        try
        {
            await foreach (var job in _netQueue!.Reader.ReadAllAsync(ct))
            {
                await WaitForAChannelAsync(ct);
                handled++;
                using var fileOp = OpLog.Begin("Lookup", $"in: {job.Item.FileName} md5={job.Md5}");
                VtFileReport? report = null;
                var failure = LookupFailure.LookupEmpty;
                try
                {
                    // In-scan dedup: serialize lookups of identical content within one run so duplicate
                    // files (node_modules, bundled runtimes, repeated installers) share a single VT/GUI
                    // lookup. The first item caches the report; the rest get the cache hit here.
                    var dedupGate = _md5Gates!.GetOrAdd(job.Md5, _ => new SemaphoreSlim(1, 1));
                    await dedupGate.WaitAsync(ct);
                    try
                    {
                        var dup = (job.Options.UseCache && !job.Options.BypassTrust)
                            ? _cache.TryGet(job.Md5, job.Options.CacheDays, job.Options.ThreatCacheDays) : null;
                        if (dup != null) { ItemWrite(() => job.Item.FromCache = true); report = dup; failure = LookupFailure.None; }
                        else (report, failure) = await DoLookupAsync(job.Item, job.Md5, job.Sha256, job.Options, ct);
                    }
                    finally { dedupGate.Release(); }

                    if (failure == LookupFailure.AnalysisPending)
                    {
                        // Uploaded: the background watcher owns this item's ending now.
                        fileOp.Note("out: uploaded — the analysis watcher will finish it");
                        continue;
                    }
                }
                catch (OperationCanceledException) { SetStatus(job.Item, ScanStatus.Cancelled); fileOp.Note("cancelled"); throw; }
                catch (Exception ex)
                {
                    ItemWrite(() => job.Item.Error = ex.Message);
                    SetStatus(job.Item, ScanStatus.Failed);
                    Bump(ref _failed);
                    Log($"Lookup failed for {job.Item.FileName}: {ex}", LogLevel.Error);
                    fileOp.Fail(ex.Message);
                    FinishItem(job.Item);
                    continue;
                }

                // "No channel could answer" is not a result about the file. Burning it as a failure
                // consumed the queue at network speed and reported a third of the disk as errors, when
                // nothing had actually been asked about those files. The job goes back to the queue and
                // the workers hold until a key window or the keyless channel comes back.
                if (report == null && failure == LookupFailure.LookupEmpty && !ct.IsCancellationRequested)
                {
                    var again = job with { Attempt = job.Attempt + 1 };
                    if (again.Attempt <= MaxLookupAttempts && _netQueue.Writer.TryWrite(again))
                    {
                        HoldOffChannels("every channel came back empty");
                        string retry = string.Format(Strings.StatusRequeuedFormat, again.Attempt, MaxLookupAttempts);
                        ItemWrite(() => { job.Item.Detail = retry; job.Item.Status = ScanStatus.AwaitingLookup; });
                        fileOp.Note($"out: no channel could answer — requeued (attempt {again.Attempt})");
                        continue;
                    }
                }

                RecordOutcome(job.Item, report, failure, fileOp);
                FinishItem(job.Item);
            }
            op.Ok($"out: {handled} file(s) looked up");
        }
        catch (OperationCanceledException) { op.Note($"cancelled after {handled} file(s)"); }
        catch (Exception ex) { op.Fail($"{ex.Message} (after {handled} file(s))"); Log($"Network worker {index} died: {ex}", LogLevel.Error); }
    }

    /// <summary>Analyses still being waited for. The run is not over until these drain, and the count is
    /// what the progress heartbeat reports as "waiting on VirusTotal".</summary>
    readonly ConcurrentDictionary<string, Task> _pendingAnalyses = new(StringComparer.Ordinal);

    /// <summary>How many uploaded files are still waiting for their VirusTotal analysis.</summary>
    public int PendingAnalysisCount => _pendingAnalyses.Count;

    /// <summary>
    /// Waits for one uploaded file's analysis off the scan workers, then finishes the item. Started and
    /// forgotten on purpose: the returned task is tracked in <see cref="_pendingAnalyses"/> and awaited
    /// once at the end of the run, so nothing is lost and no worker is held.
    /// </summary>
    void WatchAnalysis(ScanItem item, string analysisId, string md5, string sha256, ScanOptions opts, CancellationToken ct)
    {
        var task = Task.Run(async () =>
        {
            using var op = OpLog.Begin("Analysis watch", $"in: analysis={analysisId} file={item.FileName}");
            VtFileReport? report = null;
            var failure = LookupFailure.AnalysisTimedOut;
            try
            {
                report = await PollUntilCompleteAsync(analysisId, sha256, item, ct);
                if (report != null)
                {
                    failure = LookupFailure.None;
                    if (opts.UseCache && report.TotalEngines > 0) _cache.Put(md5, report, item.FilePath);
                }
            }
            catch (OperationCanceledException) { SetStatus(item, ScanStatus.Cancelled); op.Note("cancelled"); return; }
            catch (Exception ex)
            {
                ItemWrite(() => item.Error = ex.Message);
                Log($"Analysis watch failed for {item.FileName}: {ex}", LogLevel.Error);
                op.Fail(ex.Message);
            }
            finally { _pendingAnalyses.TryRemove(analysisId, out _); }

            RecordOutcome(item, report, failure, op);
            FinishItem(item);
        }, CancellationToken.None);

        _pendingAnalyses[analysisId] = task;
    }

    /// <summary>How long one file waits for a free API key before the keyless path is tried instead.
    /// Long enough to ride out the 4-per-minute window, short enough that a day-long quota block does
    /// not park the whole scan.</summary>
    static readonly TimeSpan ApiWaitForKey = TimeSpan.FromSeconds(75);

    /// <summary>How long one file waits for the single keyless browser before falling through to the
    /// API. Short: the browser answers one lookup at a time, so a queue on it is dead time for every
    /// worker in it, while a key window rolls over every minute.</summary>
    static readonly TimeSpan GuiWaitWhenKeysBusy = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Whether an unknown file should actually be submitted.
    ///
    /// A hash lookup costs one API request. A submission costs about thirteen: the upload, then up to
    /// eleven status checks, then the finished report. With 500 requests a key a day, ninety uploads
    /// spend everything fourteen keys have — and on a drive sweep the files VirusTotal has never seen
    /// are shortcuts, build output and per-machine scripts that no verdict was ever going to exist for.
    /// So a sweep looks up and reports what is known; submitting is for files the user picked, or for
    /// someone who set the policy to "always" on purpose.
    /// </summary>
    static bool ShouldUpload(string path, ScanOptions opts) => opts.UploadPolicy switch
    {
        0 => false,
        2 => true,
        _ => opts.ExplicitFileSelection && FileClass.IsWorthUploading(path),
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
                ItemWrite(() => item.Detail = Strings.PollWaitingForQuota);
                continue;
            }
            ItemWrite(() => item.Detail = string.Format(Strings.PollProgressDetailFormat, info.Status, i + 1));
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
            catch (VtAuthException ex) { _rotator.ReportAuthError(key, ex); }
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

    void SetStatus(ScanItem item, ScanStatus status) => ItemWrite(() => item.Status = status);

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
        ItemWrite(() => { item.SkipReason = reason; item.Publisher = publisher; item.Status = ScanStatus.TrustedSkipped; });
        Bump(ref _signedSkipped);
        Log($"VT skipped (trusted): {item.FileName} — {reason}", LogLevel.Info);
    }

    /// <summary>
    /// Silences per-item ListChanged for the length of a run, and restores it with one reset at the end.
    ///
    /// <see cref="BindingList{T}"/> subscribes to every item's PropertyChanged and answers each one by
    /// calling IndexOf to find the row — a linear walk of the whole list. On a 340,000-file sweep that
    /// is a 340,000-element search per property set, on the UI thread, several hundred times a second:
    /// the window stopped answering and Windows logged the scan as hung four minutes in. The grid is
    /// repainted by the queue view's own timer while a scan runs, so these notifications buy nothing.
    /// </summary>
    IDisposable SuspendItemNotifications()
    {
        UiPost(() => Items.RaiseListChangedEvents = false);
        Volatile.Write(ref _quietItems, 1);
        return new Restore(() =>
        {
            Volatile.Write(ref _quietItems, 0);
            UiPost(() =>
            {
                Items.RaiseListChangedEvents = true;
                Items.ResetBindings();
            });
        });
    }

    int _quietItems;

    /// <summary>
    /// Writes to one row's fields. Marshalled to the UI thread normally, because the binding list
    /// answers a property change by touching the grid — but NOT while a run has those notifications
    /// suspended. Then the write reaches nothing but the object's own fields, and marshalling it cost
    /// one window message per property: at 30,000 files a minute that was over a thousand posts a
    /// second and the message pump had nothing left for the user. The grid reads these fields when it
    /// repaints on its own timer.
    /// </summary>
    void ItemWrite(Action write)
    {
        if (Volatile.Read(ref _quietItems) == 1)
        {
            try { write(); } catch (Exception ex) { Log("Item write failed: " + ex.Message, LogLevel.Warning); }
        }
        else UiPost(write);
    }

    /// <summary>Runs an action when disposed.</summary>
    sealed class Restore(Action onDispose) : IDisposable
    {
        int _done;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) == 1) return;
            try { onDispose(); } catch (Exception ex) { Log("Restore failed: " + ex.Message, LogLevel.Warning); }
        }
    }

    /// <summary>Add many items to the grid-bound list in chunks, suppressing per-item ListChanged so the
    /// DataGridView repaints once per chunk instead of once per row — adding tens of thousands of files
    /// no longer freezes the window for seconds at scan start. Runs on the UI thread (caller marshals).</summary>
    void BulkAdd(List<ScanItem> toAdd)
    {
        // One reset for the whole add, not one per chunk. ResetBindings makes the grid rebuild from
        // scratch, so resetting every 500 rows over a 346,000-file selection was 693 rebuilds of a list
        // that kept growing — quadratic work on the UI thread, and the window stopped answering before
        // the first file was even hashed.
        bool wasRaising = Items.RaiseListChangedEvents;
        Items.RaiseListChangedEvents = false;
        try { foreach (var item in toAdd) Items.Add(item); }
        finally
        {
            Items.RaiseListChangedEvents = wasRaising;
            if (wasRaising) Items.ResetBindings();
        }
    }

    int _progressDirty;

    void DoneOne()
    {
        Interlocked.Increment(ref _done);
        lock (_rateLock) { _recent.Enqueue(_stopwatch.ElapsedMilliseconds); while (_recent.Count > 30) _recent.Dequeue(); }

        // Marked, not reported. This used to raise ProgressChanged for every finished file, and the
        // handler sets a label whose text change lays the whole scan tab out again — at 30,000 files a
        // minute that is 500 layout passes a second and the window never answers anything else. The
        // flush timer reports four times a second, and once more when the run ends.
        Volatile.Write(ref _progressDirty, 1);
    }

    // What the summary line last showed about the work that is not finished yet. Only the flush timer
    // touches these.
    int _shownAwaiting = -1, _shownAnalyses = -1;
    bool _shownPaused;
    long _shownHeldTicks;

    /// <summary>
    /// Reports progress if anything finished since the last report, or if the unfinished work changed
    /// shape. Hashing a file finishes nothing, and neither does a pause or a hold-off on VirusTotal, so a
    /// report driven only by finished files left the summary frozen on a number while the queue for
    /// VirusTotal grew by thousands — the window gave no sign of what the scan was doing.
    /// </summary>
    void FlushProgress()
    {
        int awaiting = NetworkQueueDepth, analyses = _pendingAnalyses.Count;
        bool paused = _pause.IsPaused;
        long held = Interlocked.Read(ref _channelsHeldUntilTicks);
        bool shapeChanged = awaiting != _shownAwaiting || analyses != _shownAnalyses || paused != _shownPaused || held != _shownHeldTicks;
        if (Interlocked.Exchange(ref _progressDirty, 0) == 1 || shapeChanged)
        {
            (_shownAwaiting, _shownAnalyses, _shownPaused, _shownHeldTicks) = (awaiting, analyses, paused, held);
            ReportProgress();
        }
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
            AwaitingLookup = NetworkQueueDepth,
            AnalysesPending = _pendingAnalyses.Count,
            Paused = _pause.IsPaused,
        };
        long held = Interlocked.Read(ref _channelsHeldUntilTicks);
        if (held > DateTime.UtcNow.Ticks) p.NetworkHeldUntilUtc = new DateTime(held, DateTimeKind.Utc);
        var (rate, rem) = ComputeRate(_total, _done);
        p.Elapsed = _stopwatch.Elapsed;
        p.FilesPerSec = rate;
        p.Remaining = rem;
        UiPost(() => { try { ProgressChanged?.Invoke(p); } catch (Exception ex) { Log("ProgressChanged handler failed: " + ex.Message, LogLevel.Warning); } });
    }
}
