using System.Collections.Concurrent;
using System.ComponentModel;

namespace VirusTotalScanner;

/// <summary>Tiny IProgress that invokes the callback synchronously (we marshal ourselves).</summary>
internal sealed class ActionProgress<T>(Action<T> action) : IProgress<T>
{
    public void Report(T value) => action(value);
}

/// <summary>
/// Thread-safe, priority-ordered async work queue supporting live mid-run urgent injection.
/// Lower priority key = dequeued first.
/// </summary>
internal sealed class PriorityWorkQueue<T, TKey> where TKey : IComparable<TKey>
{
    readonly object _lock = new();
    readonly PriorityQueue<T, TKey> _pq = new();
    readonly SemaphoreSlim _signal = new(0, int.MaxValue);
    bool _completed;

    public int Count { get { lock (_lock) return _pq.Count; } }

    public bool TryEnqueue(T item, TKey priority)
    {
        lock (_lock)
        {
            if (_completed) return false;
            _pq.Enqueue(item, priority);
        }
        _signal.Release();
        return true;
    }

    public void Complete()
    {
        lock (_lock)
        {
            if (_completed) return;
            _completed = true;
        }
        // Wake any waiting readers so they observe completion.
        _signal.Release(64);
    }

    public async Task<(bool HasItem, T? Item)> TryDequeueAsync(CancellationToken ct)
    {
        while (true)
        {
            lock (_lock)
            {
                if (_pq.TryDequeue(out var item, out _))
                    return (true, item);
                if (_completed)
                    return (false, default);
            }
            await _signal.WaitAsync(ct);
        }
    }
}

/// <summary>
/// Drives the whole scan:
///   enumerate -> strict priority ordering (exe > dll > bat > ps1 > lnk > ...) ->
///   local stage (signature/hash/cache/meta) -> autonomous per-file QueryCell (browser-first, zero-cookie,
///   cross-route resistance 0..100, mid-resistance ApiCoordinator consultation) ->
///   unknown (404) files queued to ApiCoordinator upload + background analysis polling.
///
/// Supports three clean session modes:
///   - Fresh scan (replaces the grid),
///   - Live append (adds files to a running session without wiping existing rows or counters),
///   - In-place urgent rescan / promote (never clears the list, never cancels active uploads, puts the
///     chosen row(s) at the very front of pending disk, browser, and API queues).
/// </summary>
internal sealed class ScanScheduler
{
    readonly KeyRotator _rotator;
    readonly VtApiClient _api;
    readonly ApiCoordinator _apiCoord;
    readonly HashCache _cache;
    readonly PauseTokenSource _pause = new();

    CancellationTokenSource? _cts;
    ConcurrentDictionary<string, SemaphoreSlim>? _md5Gates;
    ConcurrentDictionary<string, string>? _runNotSubmittedByMd5;
    ConcurrentDictionary<string, Task<(VtFileReport? Report, LookupFailure Failure)>>? _runPendingUploadByMd5;
    bool _isLargeSweep;
    long _watcherSeq;

    const int LargeSweepUploadCap = 500;
    const int SweepSizeThatNeedsToBePolite = 5000;

    /// <summary>Marshals an action to the UI thread (set by the GUI; direct call by default/CLI).</summary>
    public Action<Action> UiPost { get; set; } = a => a();

    /// <summary>UI-bound row collection. Only mutated on the UI thread via <see cref="UiPost"/>.</summary>
    public BindingList<ScanItem> Items { get; } = [];

    /// <summary>Authoritative thread-safe mirror of all rows currently in the session.</summary>
    readonly object _itemsLock = new();
    readonly List<ScanItem> _allItems = [];

    /// <summary>Returns a thread-safe point-in-time snapshot of all rows in the session.</summary>
    public IReadOnlyList<ScanItem> SnapshotItems() { lock (_itemsLock) return [.. _allItems]; }

    public IReadOnlyList<string> MissingPaths { get; private set; } = [];

    public event Action<OverallProgress>? ProgressChanged;
    public event Action<ScanItem>? ItemFinished;
    public event Action? Started;
    public event Action? Finished;
    public event Action<int>? PendingQueued;
    public event Action<int>? QueueUnstuck;

    public bool IsRunning { get; private set; }
    public bool IsPaused => _pause.IsPaused;
    public bool HasUiThread { get; set; }

    // Aggregate counters (always reconciled against real _allItems state)
    int _total, _done, _malicious, _suspicious, _clean, _unknown, _failed, _skipped, _signedSkipped;

    readonly System.Diagnostics.Stopwatch _stopwatch = new();
    readonly ScanEtaEstimator _eta = new();
    long _lastProgressEmitMs;

    // Live work queues for the active run
    readonly record struct DiskJob(ScanItem Item, int Generation, ScanOptions Options);
    readonly record struct NetworkJob(ScanItem Item, int Generation, string Md5, string Sha256, ScanOptions Options, int Attempt = 0);
    readonly record struct QueueKey(long NegUrgent, int Tier, long Seq) : IComparable<QueueKey>
    {
        public int CompareTo(QueueKey other)
        {
            int c = NegUrgent.CompareTo(other.NegUrgent);
            if (c != 0) return c;
            c = Tier.CompareTo(other.Tier);
            return c != 0 ? c : Seq.CompareTo(other.Seq);
        }
    }

    PriorityWorkQueue<DiskJob, QueueKey>? _diskQueue;
    PriorityWorkQueue<NetworkJob, QueueKey>? _netQueue;
    ScanOptions? _currentOpts;
    readonly ConcurrentDictionary<string, Task> _pendingAnalyses = new(StringComparer.Ordinal);

    public int NetworkQueueDepth => _netQueue?.Count ?? 0;
    public int PendingAnalysisCount => _pendingAnalyses.Count;

    public ScanScheduler(KeyRotator rotator, VtApiClient api, ApiCoordinator apiCoordinator, HashCache cache)
    {
        _rotator = rotator;
        _api = api;
        _apiCoord = apiCoordinator;
        _cache = cache;
    }

    public void Pause() { _pause.Pause(); Log("Scan paused.", LogLevel.Info); }
    public void Resume() { _pause.Resume(); Log("Scan resumed.", LogLevel.Info); }
    public void Cancel()
    {
        try { _cts?.Cancel(); } catch (Exception ex) { Log("Cancel failed: " + ex.Message, LogLevel.Warning); }
        if (_pause.IsPaused) { _pause.Resume(); Log("Pause lifted by the cancel.", LogLevel.Info); }
        Log("Scan cancel requested.", LogLevel.Info);
    }

    // ---- pending / follow-up batch coordination ----
    readonly object _pendingLock = new();
    readonly List<string> _pendingPaths = [];
    readonly List<(ScanItem Item, bool BypassTrust)> _pendingRescanItems = [];
    ScanOptions? _pendingOpts;
    string[] _activeTargets = [];
    bool _runIsAutomatic;
    bool _preempting;

    public bool IsRunningAutomatic { get { lock (_pendingLock) return IsRunning && _runIsAutomatic; } }

    /// <summary>Starts a path-based scan (or appends to an already-running scan without clearing the list).</summary>
    public async Task RunAsync(IEnumerable<string> paths, ScanOptions opts, CancellationToken externalCt = default)
    {
        var pathArray = paths.Where(p => !string.IsNullOrWhiteSpace(p)).ToArray();
        if (pathArray.Length == 0) return;

        bool replaceRunningAuto = false;
        lock (_pendingLock)
        {
            if (IsRunning && _runIsAutomatic && !opts.Automatic)
            {
                _pendingPaths.Clear();
                _pendingPaths.AddRange(pathArray);
                _pendingOpts = opts;
                _preempting = true;
                replaceRunningAuto = true;
                Log($"User scan request replaces the running automatic scan: {string.Join(", ", pathArray.Take(4))}", LogLevel.Info);
                try { _cts?.Cancel(); } catch (Exception ex) { Log("Stopping the automatic scan failed: " + ex.Message, LogLevel.Warning); }
                return;
            }
            if (IsRunning)
            {
                var (fresh, covered) = opts.BypassTrust || opts.BypassCache || opts.ExplicitFileSelection
                    ? (pathArray.ToList(), new List<string>())
                    : SplitAlreadyCovered(pathArray);
                if (covered.Count > 0)
                    Log($"Scan request covered by the running pass; {covered.Count} path(s) dropped.", LogLevel.Info);
                if (fresh.Count == 0) return;

                _pendingPaths.AddRange(fresh);
                if (!(opts.Automatic && _pendingOpts is { Automatic: false })) _pendingOpts = opts;
                int pending = _pendingPaths.Count;
                Log($"Scan already running; queued {pending} path(s) to append without clearing.", LogLevel.Info);
                UiPost(() => { try { PendingQueued?.Invoke(pending); } catch { } });
                return;
            }

            IsRunning = true;
            _runIsAutomatic = opts.Automatic;
            _activeTargets = pathArray;
        }

        if (replaceRunningAuto) return;

        bool clearQueue = !opts.PreserveExistingList;
        await RunLoopAsync(initialPaths: pathArray, initialRescans: null, initialOpts: opts, clearQueue: clearQueue, externalCt: externalCt);
    }

    /// <summary>
    /// Promotes or rescans the selected existing rows IN PLACE with top priority:
    ///   - NEVER clears the existing scan list,
    ///   - NEVER cancels any in-flight upload or active lookup,
    ///   - Works even for rows that haven't been scanned yet (Queued / AwaitingLookup) by jumping them
    ///     to the absolute front of pending disk, browser, and API queues.
    /// </summary>
    public async Task RescanOrPromoteItemsAsync(IReadOnlyList<ScanItem> targets, bool bypassTrust, CancellationToken externalCt = default)
    {
        var valid = targets.Where(i => i != null && File.Exists(i.FilePath)).Distinct(ReferenceEqualityComparer.Instance).Cast<ScanItem>().ToList();
        if (valid.Count == 0) return;

        List<ScanItem>? startNowWhenIdle = null;
        lock (_pendingLock)
        {
            if (IsRunning)
            {
                var opts = _currentOpts ?? ScanOptions.FromSettings(recurse: false);
                var needFollowUp = new List<ScanItem>();
                int promotedLive = 0;

                foreach (var item in valid)
                {
                    if (item.Status is ScanStatus.CheckingSignature or ScanStatus.Hashing or ScanStatus.LookingUp or ScanStatus.Uploading or ScanStatus.Polling)
                    {
                        // Active work is NEVER cancelled; just mark urgent so any subsequent stage (upload/API) prioritizes it.
                        item.PromoteUrgent();
                        if (bypassTrust) item.BypassTrustForThisItem = true;
                        promotedLive++;
                        continue;
                    }

                    if (item.Status == ScanStatus.AwaitingLookup && !string.IsNullOrEmpty(item.Md5) && !string.IsNullOrEmpty(item.Sha256))
                    {
                        item.PromoteUrgent();
                        if (bypassTrust) item.BypassTrustForThisItem = true;
                        var netQ = _netQueue;
                        if (netQ != null && netQ.TryEnqueue(new NetworkJob(item, item.ScanGeneration, item.Md5!, item.Sha256!, opts), MakeQueueKey(item)))
                        {
                            promotedLive++;
                            continue;
                        }
                    }

                    if (item.Status == ScanStatus.Queued)
                    {
                        item.PromoteUrgent();
                        item.Detail = Strings.StatusUrgentQueued;
                        if (bypassTrust) item.BypassTrustForThisItem = true;
                        var diskQ = _diskQueue;
                        if (diskQ != null && diskQ.TryEnqueue(new DiskJob(item, item.ScanGeneration, opts), MakeQueueKey(item)))
                        {
                            promotedLive++;
                            continue;
                        }
                    }

                    // Completed / Failed / Skipped / TrustedSkipped / Cancelled (or disk queue already closed):
                    // Reset in place and inject into the front of the live disk queue (or follow-up in-place pass).
                    item.ResetForRescan(bypassTrust);
                    var dq = _diskQueue;
                    if (dq != null && dq.TryEnqueue(new DiskJob(item, item.ScanGeneration, opts), MakeQueueKey(item)))
                    {
                        _eta.AddPendingWork([item]);
                        promotedLive++;
                    }
                    else
                    {
                        needFollowUp.Add(item);
                    }
                }

                if (needFollowUp.Count > 0)
                {
                    foreach (var it in needFollowUp) _pendingRescanItems.Add((it, bypassTrust));
                }

                if (promotedLive > 0 || needFollowUp.Count > 0)
                {
                    RecountCounters();
                    ReportProgress();
                    Log($"Urgent rescan/promote: {promotedLive} injected live, {needFollowUp.Count} queued for immediate in-place pass.", LogLevel.Info);
                }
                return;
            }

            // Idle: reset selected items IN PLACE (keep the entire existing grid intact!) and run only them.
            IsRunning = true;
            _runIsAutomatic = false;
            _activeTargets = valid.Select(i => i.FilePath).ToArray();
            startNowWhenIdle = valid;
        }

        var rescanOpts = ScanOptions.FromSettings(recurse: false);
        rescanOpts.BypassCache = true;
        rescanOpts.BypassTrust = bypassTrust;
        rescanOpts.ExplicitFileSelection = true;
        rescanOpts.PreserveExistingList = true;

        foreach (var item in startNowWhenIdle)
            item.ResetForRescan(bypassTrust);

        // Ensure items exist in _allItems (defensive, e.g. if invoked from an external dialog)
        lock (_itemsLock)
        {
            foreach (var item in startNowWhenIdle)
                if (!_allItems.Contains(item)) _allItems.Add(item);
        }

        await RunLoopAsync(initialPaths: null, initialRescans: startNowWhenIdle, initialOpts: rescanOpts, clearQueue: false, externalCt: externalCt);
    }

    async Task RunLoopAsync(string[]? initialPaths, List<ScanItem>? initialRescans, ScanOptions initialOpts, bool clearQueue, CancellationToken externalCt)
    {
        var runPaths = initialPaths;
        var runRescans = initialRescans;
        var runOpts = initialOpts;
        bool clear = clearQueue;

        while (true)
        {
            await RunCoreAsync(runPaths, runRescans, runOpts, clear, externalCt);

            lock (_pendingLock)
            {
                bool preempted = _preempting;
                _preempting = false;
                if (!preempted && _cts?.IsCancellationRequested == true)
                {
                    _pendingPaths.Clear();
                    _pendingRescanItems.Clear();
                    _pendingOpts = null;
                }

                // In-place urgent rescans queued while disk stage was draining run first, without clearing the grid.
                if (_pendingRescanItems.Count > 0)
                {
                    var batch = _pendingRescanItems.ToList();
                    _pendingRescanItems.Clear();
                    runPaths = null;
                    runRescans = batch.Select(x => x.Item).ToList();
                    runOpts = ScanOptions.FromSettings(recurse: false);
                    runOpts.BypassCache = true;
                    runOpts.BypassTrust = batch.Any(x => x.BypassTrust);
                    runOpts.ExplicitFileSelection = true;
                    runOpts.PreserveExistingList = true;
                    _runIsAutomatic = false;
                    clear = false;
                    continue;
                }

                if (_pendingPaths.Count == 0)
                {
                    IsRunning = false;
                    _runIsAutomatic = false;
                    _activeTargets = [];
                    return;
                }

                var next = _pendingPaths.ToArray();
                runPaths = next;
                runRescans = null;
                _activeTargets = next;
                _pendingPaths.Clear();
                runOpts = _pendingOpts ?? runOpts;
                _pendingOpts = null;
                _runIsAutomatic = runOpts.Automatic;
                clear = preempted; // only preempting an automatic pass replaces the grid; follow-ups append!
            }
        }
    }

    (List<string> Fresh, List<string> Covered) SplitAlreadyCovered(IEnumerable<string> paths)
    {
        var fresh = new List<string>();
        var covered = new List<string>();
        foreach (var p in paths)
        {
            if (string.IsNullOrWhiteSpace(p)) continue;
            string full;
            try { full = Path.GetFullPath(p); }
            catch { fresh.Add(p); continue; }

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

    async Task RunCoreAsync(string[]? paths, List<ScanItem>? inPlaceItems, ScanOptions opts, bool clearQueue, CancellationToken externalCt)
    {
        bool isInPlace = inPlaceItems != null;
        using var runOp = OpLog.Begin("Scan run",
            isInPlace
                ? $"in-place rescan of {inPlaceItems!.Count} item(s) bypassTrust={opts.BypassTrust}"
                : $"targets=[{string.Join(", ", (paths ?? []).Take(4))}] recurse={opts.Recurse} concurrency={opts.MaxConcurrency} uploads={opts.MaxUploads} clearQueue={clearQueue}");

        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        var ct = _cts.Token;
        lock (_pendingLock) if (_preempting) _cts.Cancel();
        if (_pause.IsPaused) { _pause.Resume(); runOp.Step("pause lifted"); }

        _apiCoord.ConfigureConcurrency(opts.MaxUploads);
        _stopwatch.Restart();
        _lastProgressEmitMs = 0;

        if (clearQueue)
        {
            lock (_itemsLock) _allItems.Clear();
            ResetCounters();
            UiPost(() => Items.Clear());
        }
        else
        {
            RecountCounters();
        }

        try { Started?.Invoke(); } catch (Exception ex) { Log("Started handler failed: " + ex.Message, LogLevel.Warning); }

        var archiveTemps = new List<string>();
        List<ScanItem> batchItems = [];
        try
        {
            if (!isInPlace && Settings.ResumeInterruptedScans && paths != null)
                ScanSessionStore.SaveRunning(paths, opts.Recurse, opts.BypassTrust);
            KnownGoodDb.Reload();

            if (isInPlace)
            {
                batchItems = [.. inPlaceItems!];
                batchItems.Sort(ScanPriorityOrderer.CompareItems);
            }
            else
            {
                var safe = SelectionEnumerator.ParseExtensions(Settings.SafeExtensions);
                var oversize = new List<string>();
                var missing = new List<string>();
                var files = await Task.Run(() => SelectionEnumerator.Expand(
                    paths ?? [], safe, opts.Recurse, opts.ApplySafeFilter, opts.MaxFileSizeBytes, oversize, missing), ct);
                MissingPaths = missing;
                if (missing.Count > 0)
                {
                    string list = string.Join(", ", missing.Take(5));
                    Log($"Scan target(s) not found ({missing.Count}): {list}", LogLevel.Warning);
                    UiStatusHub.Report(Strings.StatusSourceScan,
                        string.Format(Strings.ScanTargetsMissingFormat, missing.Count, list), StatusSeverity.Warning);
                }

                var origins = new Dictionary<string, (string Archive, string Member)>(StringComparer.OrdinalIgnoreCase);
                if (opts.ExpandArchives)
                {
                    var toExpand = files;
                    files = await Task.Run(() => ExpandArchives(toExpand, archiveTemps, origins), ct);
                }

                // Always enforce strict primary extension order: exe > dll > bat > ps1 > lnk > ...
                // Risk signals break ties inside each tier for <= 5000 files without ever reordering tiers.
                if (files.Count > 1)
                {
                    using var orderOp = OpLog.Begin("Priority ordering", $"in: {files.Count} file(s)");
                    var toOrder = files;
                    files = await Task.Run(() => ScanPriorityOrderer.OrderPaths(toOrder, Settings.RiskWeightedOrdering), ct);
                    orderOp.Ok("out: ordered (exe > dll > bat > ps1 > lnk)");
                }

                batchItems = files.Select(f => origins.TryGetValue(f, out var o)
                    ? new ScanItem(f) { ContainerPath = o.Archive, MemberPath = o.Member }
                    : new ScanItem(f)).ToList();

                lock (_itemsLock) _allItems.AddRange(batchItems);
                UiPost(() => BulkAdd(batchItems));

                if (oversize.Count > 0)
                {
                    int capMb = (int)(opts.MaxFileSizeBytes / (1024 * 1024));
                    var skipped = oversize.Select(f => new ScanItem(f) { Status = ScanStatus.Skipped, SkipReason = string.Format(Strings.SkipReasonTooLargeFormat, capMb) }).ToList();
                    lock (_itemsLock) _allItems.AddRange(skipped);
                    UiPost(() => BulkAdd(skipped));
                    Log($"{oversize.Count} file(s) skipped by the {capMb} MB size cap.", LogLevel.Info);
                }
            }

            RecountCounters();
            ReportProgress();

            if (batchItems.Count == 0)
            {
                Log("Nothing to scan.", LogLevel.Warning);
                return;
            }

            _md5Gates = new ConcurrentDictionary<string, SemaphoreSlim>(StringComparer.OrdinalIgnoreCase);
            _runNotSubmittedByMd5 = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            _runPendingUploadByMd5 = new ConcurrentDictionary<string, Task<(VtFileReport? Report, LookupFailure Failure)>>(StringComparer.OrdinalIgnoreCase);
            _isLargeSweep = !isInPlace && (opts.Automatic || (!opts.ExplicitFileSelection && (batchItems.Count > LargeSweepUploadCap || IsWholeDriveTarget(paths ?? []))));
            _pendingAnalyses.Clear();
            _eta.Reset(batchItems, opts, _isLargeSweep);
            ReportProgress();

            const int localDegree = 1;
            using var heartbeat = StartHeartbeat(localDegree, ct);
            using var quietList = SuspendItemNotifications();
            using var finishedFlush = StartFinishedFlush();
            using var politeCpu = YieldToTheRestOfTheMachine(batchItems.Count);

            _diskQueue = new PriorityWorkQueue<DiskJob, QueueKey>();
            _netQueue = new PriorityWorkQueue<NetworkJob, QueueKey>();
            _currentOpts = opts;
            Interlocked.Exchange(ref _consecutiveEmpty, 0);

            foreach (var item in batchItems)
                _diskQueue.TryEnqueue(new DiskJob(item, item.ScanGeneration, opts), MakeQueueKey(item));

            int netWorkers = Math.Max(2, Math.Max(opts.MaxConcurrency, BrowserSessionFactory.DesiredConcurrency()));
            var netTasks = Enumerable.Range(0, netWorkers).Select(i => NetworkWorkerAsync(i, ct)).ToArray();
            Log($"Network stage started with {netWorkers} cell worker(s); disk stage runs {localDegree} wide (browser-first).", LogLevel.Info);

            // Drain priority-ordered disk queue; live urgent promotions/rescans can jump to the front mid-run!
            while (!ct.IsCancellationRequested)
            {
                if (_diskQueue.Count == 0)
                {
                    // Check once under _pendingLock: no more disk jobs arriving unless a live rescan arrives later.
                    _diskQueue.Complete();
                    break;
                }
                var (hasJob, job) = await _diskQueue.TryDequeueAsync(ct);
                if (!hasJob) break;
                if (job.Generation != job.Item.ScanGeneration) continue; // superseded by an urgent promotion
                await ProcessAsync(job.Item, job.Options, job.Generation, ct);
            }

            using (var drainNet = OpLog.Begin("Drain network queue", $"in: {_netQueue.Count} file(s) still queued"))
            {
                _netQueue.Complete();
                await Task.WhenAll(netTasks);
                drainNet.Ok("out: network stage closed");
            }

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
            if (!ct.IsCancellationRequested) ScanSessionStore.Clear();
            else MarkUnfinishedCancelled(batchItems, runOp);
            foreach (var td in archiveTemps) ArchiveExpander.CleanupTemp(td);
            _cache.Flush();
            FingerprintCache.Flush();
            PendingOutbox.Flush();
            RecountCounters();
            ReportProgress();
            Log($"Fingerprint cache: {FingerprintCache.Hits} reuse(s), {FingerprintCache.Misses} miss(es), {FingerprintCache.Count} entr(ies) held.", LogLevel.Info);
            try { Finished?.Invoke(); } catch (Exception ex) { Log("Finished handler failed: " + ex.Message, LogLevel.Warning); }
            Log("Scan finished.", LogLevel.Info);
            runOp.Ok($"{_done}/{_total} done — malicious={_malicious} suspicious={_suspicious} clean={_clean} "
                + $"unknown={_unknown} failed={_failed} skipped={_skipped} trustSkipped={_signedSkipped}");
        }
    }

    static QueueKey MakeQueueKey(ScanItem item) => new(-item.UrgentOrder, item.PriorityTier, item.AddedSequence);

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
                    if (it.Status is not (ScanStatus.Queued or ScanStatus.AwaitingLookup or ScanStatus.CheckingSignature
                        or ScanStatus.Hashing or ScanStatus.LookingUp or ScanStatus.Uploading or ScanStatus.Polling)) continue;
                    it.Status = ScanStatus.Cancelled;
                    closed++;
                }
            }
            catch (Exception ex) { Log("Closing unfinished rows failed: " + ex.Message, LogLevel.Warning); }
            finally
            {
                Items.RaiseListChangedEvents = raising;
                if (raising) Items.ResetBindings();
                Log($"Run cancelled: {closed} unfinished row(s) marked cancelled.", LogLevel.Info);
            }
        });
        runOp.Step("unfinished rows marked cancelled");
    }

    static List<string> ExpandArchives(List<string> files, List<string> tempDirs, Dictionary<string, (string Archive, string Member)> origins)
    {
        var result = new List<string>();
        foreach (var f in files)
        {
            if (!ArchiveExpander.IsExpandable(f)) { result.Add(f); continue; }
            var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var members = ArchiveExpander.ExpandToTemp(f, out var td, names);
            if (members.Count > 0)
            {
                result.AddRange(members);
                tempDirs.Add(td);
                foreach (var m in members)
                    origins[m] = (f, names.TryGetValue(m, out var inside) ? inside : Path.GetFileName(m));
            }
            else { ArchiveExpander.CleanupTemp(td); result.Add(f); }
        }
        return result;
    }

    async Task ProcessAsync(ScanItem item, ScanOptions opts, int generation, CancellationToken ct)
    {
        using var op = OpLog.Begin("File", $"{item.DisplayName} ({item.SizeText}) — {item.FilePath}");
        bool handedOff = false;
        System.Diagnostics.Stopwatch? localSw = null;
        double hashSec = 0;
        bool hashedFromDisk = false;
        bool bypassTrust = opts.BypassTrust || item.BypassTrustForThisItem;
        bool bypassCache = opts.BypassCache || bypassTrust || item.BypassCacheForThisItem;

        try
        {
            await _pause.WaitWhilePausedAsync(ct);
            localSw = System.Diagnostics.Stopwatch.StartNew();

            // Pre-compute zone & overlay metadata off the UI thread so the detail pane never freezes.
            if (!item.LocalMetaComputed)
            {
                try { item.CachedZoneSummary = ZoneIdentifier.Read(item.ContainerPath ?? item.FilePath)?.Summary; } catch { }
                try { item.CachedOverlayBytes = OverlayDetector.OverlayBytes(item.FilePath); } catch { }
                item.LocalMetaComputed = true;
            }

            if (opts.SkipTrusted && !bypassTrust)
            {
                SetStatus(item, ScanStatus.CheckingSignature);
                var trust = TrustService.Evaluate(item.FilePath);
                item.Trust = trust;
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
            var known = (Settings.UseFingerprintCache && !bypassCache) ? FingerprintCache.TryGet(item.FilePath) : null;
            if (known is { } fp)
            {
                (md5, sha256) = (fp.Md5, fp.Sha256);
                op.Step("hashes reused from fingerprint cache");
            }
            else
            {
                var hashSw = System.Diagnostics.Stopwatch.StartNew();
                (md5, sha256) = await HashService.ComputeAsync(item.FilePath, ct);
                hashSec = hashSw.Elapsed.TotalSeconds;
                hashedFromDisk = true;
                if (Settings.UseFingerprintCache) FingerprintCache.Put(item.FilePath, md5, sha256);
            }
            ItemWrite(() => { item.Md5 = md5; item.Sha256 = sha256; });

            if (opts.UseCache && !bypassCache)
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

            if (opts.SkipTrusted && !bypassTrust && KnownGoodDb.Contains(md5, sha256))
            {
                TrustSkip(item, Strings.SkipReasonKnownGoodList, null);
                op.Ok("known-good list");
                return;
            }

            if (!bypassTrust && AllowlistStore.Contains(md5, sha256))
            {
                TrustSkip(item, Strings.SkipReasonUserSaidClean, null);
                op.Ok("allowlisted by user");
                return;
            }

            if (!bypassTrust && FolderSuppressionStore.Contains(item.FilePath))
            {
                TrustSkip(item, Strings.SkipReasonDevFolder, null);
                op.Ok("suppressed folder");
                return;
            }

            if (opts.LookupPolicy == 1 && !opts.ExplicitFileSelection && !bypassTrust && !item.IsPriorityBoosted
                && !FileClass.IsWorthUploading(item.FilePath))
            {
                ItemWrite(() => { item.SkipReason = Strings.SkipReasonNotCodeFile; item.Status = ScanStatus.Skipped; });
                op.Ok("not a code file — no lookup spent");
                return;
            }

            SetStatus(item, ScanStatus.AwaitingLookup);
            if (!_netQueue!.TryEnqueue(new NetworkJob(item, item.ScanGeneration, md5, sha256, opts), MakeQueueKey(item)))
            {
                Log($"Network queue closed; {item.FileName} was not looked up.", LogLevel.Warning);
                op.Note("network queue closed");
                return;
            }
            handedOff = true;
            op.Note("local stage done — handed to query cell queue");
        }
        catch (OperationCanceledException)
        {
            SetStatus(item, ScanStatus.Cancelled);
            op.Note("cancelled");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            string reason = ex is UnauthorizedAccessException ? Strings.SkipReasonNoAccess : Strings.SkipReasonFileLocked;
            ItemWrite(() => { item.SkipReason = reason; item.Status = ScanStatus.Skipped; });
            Log($"Not readable, skipped: {item.FilePath} — {ex.Message}", LogLevel.Warning);
            op.Note("not readable — " + reason);
        }
        catch (Exception ex)
        {
            ItemWrite(() => item.Error = ex.Message);
            SetStatus(item, ScanStatus.Failed);
            if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable()) PendingOutbox.Add(item.FilePath);
            Log($"Scan failed for {item.FileName}: {ex}", LogLevel.Error);
            op.Fail(ex.Message);
        }
        finally
        {
            _eta.RecordLocalStage(item.SizeBytes, localSw?.Elapsed.TotalSeconds ?? 0, hashSec, hashedFromDisk, handedOff);
            if (!handedOff) FinishItem(item);
        }
    }

    void RecordOutcome(ScanItem item, VtFileReport? report, LookupFailure failure, OpLog op)
    {
        if (report == null && failure == LookupFailure.NotSubmitted)
        {
            ItemWrite(() => { item.SkipReason ??= Strings.SkipReasonNotSubmitted; item.Status = ScanStatus.Skipped; });
            op.Ok("not in VirusTotal, not submitted");
        }
        else if (report == null && failure is LookupFailure.LookupEmpty or LookupFailure.UnknownNoKey)
        {
            ItemWrite(() => { item.SkipReason = Strings.SkipReasonNotAskedYet; item.Status = ScanStatus.Skipped; });
            PendingOutbox.Add(item.FilePath);
            op.Note("not asked yet — queued for next run");
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
            Log($"No report for {item.FileName} ({failure}): {reason}", LogLevel.Warning);
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

    static void SetCurrentThreadPriority(System.Threading.ThreadPriority priority)
    {
        try
        {
            if (!System.Windows.Forms.Application.MessageLoop) return;
            System.Threading.Thread.CurrentThread.Priority = priority;
        }
        catch { }
    }

    IDisposable? YieldToTheRestOfTheMachine(int fileCount)
    {
        if (fileCount < SweepSizeThatNeedsToBePolite) return null;
        try
        {
            var me = System.Diagnostics.Process.GetCurrentProcess();
            var previous = me.PriorityClass;
            if (previous != System.Diagnostics.ProcessPriorityClass.Normal) return null;
            me.PriorityClass = System.Diagnostics.ProcessPriorityClass.BelowNormal;
            if (HasUiThread) UiPost(() => SetCurrentThreadPriority(System.Threading.ThreadPriority.Highest));
            return new Restore(() =>
            {
                try
                {
                    System.Diagnostics.Process.GetCurrentProcess().PriorityClass = previous;
                    if (HasUiThread) UiPost(() => SetCurrentThreadPriority(System.Threading.ThreadPriority.Normal));
                }
                catch { }
            });
        }
        catch { return null; }
    }

    readonly List<ScanItem> _finished = [];
    readonly object _finishedLock = new();

    void FinishItem(ScanItem item)
    {
        item.BypassCacheForThisItem = false;
        item.BypassTrustForThisItem = false;
        RecountCounters();
        _eta.RecordItemDone();
        Volatile.Write(ref _progressDirty, 1);
        lock (_finishedLock) _finished.Add(item);
    }

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

    IDisposable StartFinishedFlush()
    {
        var timer = new System.Threading.Timer(_ =>
        {
            try { FlushFinished(); FlushProgress(); }
            catch (Exception ex) { Log("Finished flush failed: " + ex.Message, LogLevel.Warning); }
        }, null, TimeSpan.FromMilliseconds(250), TimeSpan.FromMilliseconds(250));
        return new Restore(() => { try { timer.Dispose(); } catch { } FlushFinished(); FlushProgress(); });
    }

    /// <summary>
    /// Executes one autonomous <see cref="QueryCell"/> lookup (browser-first, zero-cookie, full resistance
    /// matrix + dynamic ApiCoordinator consultation). If VT definitively answers 404 and the file is upload-eligible,
    /// submits the file to <see cref="ApiCoordinator"/>'s priority upload queue and hands polling to WatchAnalysis.
    /// </summary>
    async Task<(VtFileReport? Report, LookupFailure Failure)> DoLookupAsync(ScanItem item, string md5, string sha256, ScanOptions opts, CancellationToken ct)
    {
        await _pause.WaitWhilePausedAsync(ct);

        bool allowBrowser = (opts.ForceKeyless || Settings.KeylessGuiLookup) && BrowserSessionFactory.IsRuntimeAvailable;
        bool allowApi = !opts.ForceKeyless && _apiCoord.HasUsableKeys;
        bool allowUserCaptcha = !GuiScrapeService.HeadlessMode && !GuiScrapeService.ProbeMode;

        ItemWrite(() => { item.Status = ScanStatus.LookingUp; item.Detail = Strings.StatusLookingUp; });

        var cell = new QueryCell(_apiCoord, _pause);
        var res = await cell.LookupAsync(
            sha256,
            item.UrgentOrder,
            item.PriorityTier,
            allowBrowser,
            allowApi,
            allowUserCaptcha,
            onStatus: (rScore, detail) => ItemWrite(() =>
            {
                item.ResistanceScore = rScore;
                item.Detail = detail;
            }),
            ct);

        if (res.Report != null)
        {
            _eta.RecordLookup(res.ElapsedSeconds, viaKeyless: !res.ServedByApi, triggeredUpload: false);
            if (opts.UseCache && res.Report.TotalEngines > 0)
                _cache.Put(md5, res.Report, item.LastingPath);
            return (res.Report, LookupFailure.None);
        }

        if (res.NotFoundOnVt)
        {
            var (shouldUpload, skipReason) = EvaluateUpload(item, opts, _isLargeSweep);
            if (!shouldUpload)
            {
                _eta.RecordLookup(res.ElapsedSeconds, viaKeyless: !res.ServedByApi, triggeredUpload: false);
                ItemWrite(() => item.SkipReason = skipReason);
                _runNotSubmittedByMd5?.TryAdd(md5, skipReason);
                return (null, LookupFailure.NotSubmitted);
            }
            if (!_apiCoord.HasUsableKeys)
            {
                _eta.RecordLookup(res.ElapsedSeconds, viaKeyless: !res.ServedByApi, triggeredUpload: false);
                return (null, LookupFailure.UnknownNoKey);
            }

            _eta.RecordLookup(res.ElapsedSeconds, viaKeyless: !res.ServedByApi, triggeredUpload: true);
            await _pause.WaitWhilePausedAsync(ct);
            ItemWrite(() =>
            {
                item.Status = ScanStatus.Uploading;
                item.Detail = string.Format(Strings.StatusApiUploadQueuedFormat, Math.Max(1, _apiCoord.PendingUploadCount + 1));
            });

            _eta.UpdateUploadProgress(item.AddedSequence, Math.Max(0, item.SizeBytes), 0, 0);
            var progress = new ActionProgress<UploadProgress>(p =>
            {
                _eta.UpdateUploadProgress(item.AddedSequence, p.TotalBytes, p.BytesSent, p.BytesPerSecond);
                ItemWrite(() =>
                {
                    item.Progress = (int)Math.Round(p.Percent);
                    item.Detail = string.Format(Strings.UploadProgressDetailFormat, p.Percent, FormatBytes(p.BytesSent), FormatBytes(p.TotalBytes), FormatBytes(p.BytesPerSecond));
                });
            });

            (bool uploaded, string? analysisId) = (false, null);
            try
            {
                (uploaded, analysisId) = await _apiCoord.UploadFileAsync(
                    item.FilePath, item.UrgentOrder, item.PriorityTier, progress, ApiWaitForUpload, ct);
            }
            finally { _eta.EndUpload(item.AddedSequence); }

            if (uploaded && analysisId != null)
            {
                SetStatus(item, ScanStatus.Polling);
                WatchAnalysis(item, analysisId, md5, sha256, opts, ct);
                return (null, LookupFailure.AnalysisPending);
            }
            return (null, LookupFailure.LookupEmpty);
        }

        _eta.RecordLookup(res.ElapsedSeconds, viaKeyless: !res.ServedByApi, triggeredUpload: false);
        return (null, res.Failure);
    }

    IDisposable StartHeartbeat(int workers, CancellationToken ct)
    {
        var started = DateTime.UtcNow;
        int lastDone = 0;
        var timer = new System.Threading.Timer(_ =>
        {
            try
            {
                int done = Volatile.Read(ref _done);
                int total = Volatile.Read(ref _total);
                var elapsed = DateTime.UtcNow - started;
                double perMin = elapsed.TotalMinutes > 0 ? done / elapsed.TotalMinutes : 0;
                var (_, rem) = EstimateProgress(total, done);
                string eta = rem is { } r
                    ? (r.TotalDays >= 1 ? r.ToString(@"d\g\ hh\:mm") : r.ToString(@"hh\:mm\:ss"))
                    : "?";
                Log($"Sweep progress: {done}/{total} ({(total > 0 ? done * 100.0 / total : 0):0.0}%), "
                    + $"+{done - lastDone} in last min, {perMin:0.0}/min, ETA {eta} — "
                    + $"clean={_clean} malicious={_malicious} suspicious={_suspicious} unknown={_unknown} "
                    + $"skipped={_skipped} signed={_signedSkipped} failed={_failed}; "
                    + $"queued={NetworkQueueDepth}, analyses={_pendingAnalyses.Count}, cells={QueryCell.ActiveCellCount}, "
                    + $"apiLoad={_apiCoord.ComputeLoadScore():0}/100, keys={_rotator.UsableKeyCount} room={_rotator.HasImmediateRoom}",
                    LogLevel.Info);
                lastDone = done;
            }
            catch (Exception ex) { Log("Heartbeat failed: " + ex.Message, LogLevel.Warning); }
        }, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        ct.Register(() => { try { timer.Change(Timeout.Infinite, Timeout.Infinite); } catch { } });
        return timer;
    }

    const int MaxLookupAttempts = 3;
    long _channelsHeldUntilTicks;
    static readonly TimeSpan ChannelHoldOff = TimeSpan.FromSeconds(15);

    void HoldOffChannels(string why)
    {
        var until = DateTime.UtcNow + ChannelHoldOff;
        long ticks = until.Ticks;
        if (ticks > Interlocked.Read(ref _channelsHeldUntilTicks))
        {
            Interlocked.Exchange(ref _channelsHeldUntilTicks, ticks);
            Log($"Network stage holding until {until:HH:mm:ss} UTC — {why}.", LogLevel.Info);
        }
    }

    async Task WaitForAChannelAsync(ScanItem item, CancellationToken ct)
    {
        var poll = TimeSpan.FromSeconds(2);
        while (!ct.IsCancellationRequested)
        {
            long until = Interlocked.Read(ref _channelsHeldUntilTicks);
            var untilUtc = new DateTime(until, DateTimeKind.Utc);
            var left = untilUtc - DateTime.UtcNow;
            if (left <= TimeSpan.Zero) return;
            string note = string.Format(Strings.StatusNetworkHeldFormat, untilUtc.ToLocalTime());
            ItemWrite(() => { item.Detail = note; item.Status = ScanStatus.AwaitingLookup; });
            await Task.Delay(left < poll ? left : poll, ct);
        }
    }

    int _consecutiveEmpty;
    long _lastAutoUnstickTicks;
    const int AutoUnstickAfterEmpties = 12;
    static readonly TimeSpan AutoUnstickThrottle = TimeSpan.FromSeconds(45);

    void NoteEmptyLookup()
    {
        if (Interlocked.Increment(ref _consecutiveEmpty) < AutoUnstickAfterEmpties) return;
        long now = DateTime.UtcNow.Ticks;
        long last = Interlocked.Read(ref _lastAutoUnstickTicks);
        if (now - last < AutoUnstickThrottle.Ticks) return;
        if (Interlocked.CompareExchange(ref _lastAutoUnstickTicks, now, last) != last) return;
        Interlocked.Exchange(ref _consecutiveEmpty, 0);
        Log($"Network stage stuck ({AutoUnstickAfterEmpties} empty cells) — unsticking automatically.", LogLevel.Warning);
        _ = UnstickAsync("stuck queue (automatic)", auto: true);
    }

    void NoteLookupServed() => Interlocked.Exchange(ref _consecutiveEmpty, 0);

    public async Task<int> UnstickAsync(string why, bool auto = false)
    {
        Interlocked.Exchange(ref _channelsHeldUntilTicks, 0);
        try
        {
            if (TorService.IsActive) await TorService.NewCircuitAsync();
        }
        catch (Exception ex) { Log("Unstick Tor rotation failed: " + ex.Message, LogLevel.Warning); }
        GuiScrapeService.ResetHard(why);

        int requeued = RequeueDroppedLookups();
        Log($"Unstick ({why}): route health & browser cache slots reset, {requeued} dropped file(s) requeued.", LogLevel.Info);
        try { UiPost(() => { try { QueueUnstuck?.Invoke(requeued); } catch { } }); } catch { }
        return requeued;
    }

    int RequeueDroppedLookups()
    {
        var queue = _netQueue;
        var opts = _currentOpts;
        if (queue == null || opts == null || !IsRunning) return 0;

        int requeued = 0;
        foreach (var item in SnapshotItems())
        {
            if (item.Status != ScanStatus.Skipped || item.SkipReason != Strings.SkipReasonNotAskedYet) continue;
            if (string.IsNullOrEmpty(item.Md5) || string.IsNullOrEmpty(item.Sha256)) continue;
            if (!queue.TryEnqueue(new NetworkJob(item, item.ScanGeneration, item.Md5!, item.Sha256!, opts), MakeQueueKey(item))) break;
            PendingOutbox.Remove(item.FilePath);
            ItemWrite(() => { item.SkipReason = null; item.Detail = Strings.StatusWaitingLookupSlot; item.Status = ScanStatus.AwaitingLookup; });
            requeued++;
        }
        if (requeued > 0) { RecountCounters(); ReportProgress(); }
        return requeued;
    }

    async Task NetworkWorkerAsync(int index, CancellationToken ct)
    {
        using var op = OpLog.Begin($"Cell worker {index}");
        int handled = 0;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var (hasJob, job) = await _netQueue!.TryDequeueAsync(ct);
                if (!hasJob) break;
                if (job.Generation != job.Item.ScanGeneration) continue; // superseded by an urgent promotion

                await WaitForAChannelAsync(job.Item, ct);
                handled++;
                using var fileOp = OpLog.Begin("CellLookup", $"in: {job.Item.FileName} md5={job.Md5}");
                VtFileReport? report = null;
                var failure = LookupFailure.LookupEmpty;
                try
                {
                    bool bypassCache = job.Options.BypassCache || job.Options.BypassTrust
                        || job.Item.BypassCacheForThisItem || job.Item.BypassTrustForThisItem;

                    var dedupGate = _md5Gates!.GetOrAdd(job.Md5, _ => new SemaphoreSlim(1, 1));
                    if (!dedupGate.Wait(0))
                    {
                        ItemWrite(() => { job.Item.Detail = Strings.StatusWaitingSameContent; job.Item.Status = ScanStatus.AwaitingLookup; });
                        await dedupGate.WaitAsync(ct);
                    }
                    try
                    {
                        var dup = (job.Options.UseCache && !bypassCache)
                            ? _cache.TryGet(job.Md5, job.Options.CacheDays, job.Options.ThreatCacheDays) : null;
                        if (dup != null)
                        {
                            ItemWrite(() => job.Item.FromCache = true);
                            report = dup;
                            failure = LookupFailure.None;
                        }
                        else if (!bypassCache && _runNotSubmittedByMd5 != null && _runNotSubmittedByMd5.TryGetValue(job.Md5, out var skipReason))
                        {
                            ItemWrite(() => job.Item.SkipReason = skipReason);
                            report = null;
                            failure = LookupFailure.NotSubmitted;
                        }
                        else if (_runPendingUploadByMd5 != null && _runPendingUploadByMd5.TryGetValue(job.Md5, out var pendingUpload))
                        {
                            SetStatus(job.Item, ScanStatus.Polling);
                            WatchSharedAnalysis(job.Item, pendingUpload, ct);
                            report = null;
                            failure = LookupFailure.AnalysisPending;
                        }
                        else (report, failure) = await DoLookupAsync(job.Item, job.Md5, job.Sha256, job.Options, ct);
                    }
                    finally { dedupGate.Release(); }

                    if (failure == LookupFailure.AnalysisPending)
                    {
                        fileOp.Note("out: uploaded — analysis watcher active");
                        continue;
                    }
                }
                catch (OperationCanceledException) { SetStatus(job.Item, ScanStatus.Cancelled); fileOp.Note("cancelled"); throw; }
                catch (Exception ex)
                {
                    ItemWrite(() => job.Item.Error = ex.Message);
                    SetStatus(job.Item, ScanStatus.Failed);
                    Log($"Lookup failed for {job.Item.FileName}: {ex}", LogLevel.Error);
                    fileOp.Fail(ex.Message);
                    FinishItem(job.Item);
                    continue;
                }

                if (report == null && failure == LookupFailure.LookupEmpty && !ct.IsCancellationRequested)
                {
                    var again = job with { Attempt = job.Attempt + 1 };
                    if (again.Attempt <= MaxLookupAttempts && _netQueue.TryEnqueue(again, MakeQueueKey(job.Item)))
                    {
                        HoldOffChannels("cell exhausted all routes");
                        NoteEmptyLookup();
                        string retry = string.Format(Strings.StatusRequeuedFormat, again.Attempt, MaxLookupAttempts);
                        ItemWrite(() => { job.Item.Detail = retry; job.Item.Status = ScanStatus.AwaitingLookup; });
                        fileOp.Note($"out: requeued (attempt {again.Attempt})");
                        continue;
                    }
                }

                if (report != null) NoteLookupServed();
                RecordOutcome(job.Item, report, failure, fileOp);
                FinishItem(job.Item);
            }
            op.Ok($"out: {handled} file(s) looked up");
        }
        catch (OperationCanceledException) { op.Note($"cancelled after {handled} file(s)"); }
        catch (Exception ex) { op.Fail($"{ex.Message} (after {handled} file(s))"); Log($"Cell worker {index} died: {ex}", LogLevel.Error); }
    }

    void WatchAnalysis(ScanItem item, string analysisId, string md5, string sha256, ScanOptions opts, CancellationToken ct)
    {
        string watchKey = $"{analysisId}#{Interlocked.Increment(ref _watcherSeq)}";
        var sharedTcs = new TaskCompletionSource<(VtFileReport? Report, LookupFailure Failure)>(TaskCreationOptions.RunContinuationsAsynchronously);
        _runPendingUploadByMd5?.TryAdd(md5, sharedTcs.Task);
        _eta.BeginPoll(watchKey);

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
                    if (opts.UseCache && report.TotalEngines > 0) _cache.Put(md5, report, item.LastingPath);
                }
            }
            catch (OperationCanceledException)
            {
                SetStatus(item, ScanStatus.Cancelled);
                op.Note("cancelled");
                sharedTcs.TrySetCanceled(ct);
                return;
            }
            catch (Exception ex)
            {
                ItemWrite(() => item.Error = ex.Message);
                Log($"Analysis watch failed for {item.FileName}: {ex}", LogLevel.Error);
                op.Fail(ex.Message);
            }
            finally
            {
                _eta.EndPoll(watchKey, report != null);
                _pendingAnalyses.TryRemove(watchKey, out _);
                _runPendingUploadByMd5?.TryRemove(md5, out _);
            }

            sharedTcs.TrySetResult((report, failure));
            RecordOutcome(item, report, failure, op);
            FinishItem(item);
        }, CancellationToken.None);

        _pendingAnalyses[watchKey] = task;
    }

    void WatchSharedAnalysis(ScanItem item, Task<(VtFileReport? Report, LookupFailure Failure)> shared, CancellationToken ct)
    {
        string watchKey = $"shared#{Interlocked.Increment(ref _watcherSeq)}";
        var task = Task.Run(async () =>
        {
            using var op = OpLog.Begin("Shared analysis watch", $"file={item.FileName}");
            try
            {
                var (report, failure) = await shared.WaitAsync(ct);
                RecordOutcome(item, report, failure, op);
                FinishItem(item);
            }
            catch (OperationCanceledException) { SetStatus(item, ScanStatus.Cancelled); op.Note("cancelled"); }
            catch (Exception ex)
            {
                ItemWrite(() => item.Error = ex.Message);
                SetStatus(item, ScanStatus.Failed);
                op.Fail(ex.Message);
                FinishItem(item);
            }
            finally { _pendingAnalyses.TryRemove(watchKey, out _); }
        }, CancellationToken.None);

        _pendingAnalyses[watchKey] = task;
    }

    static readonly TimeSpan ApiWaitForUpload = TimeSpan.FromMinutes(10);
    static readonly TimeSpan ApiWaitForPoll = TimeSpan.FromSeconds(90);

    static bool IsWholeDriveTarget(IEnumerable<string> paths)
    {
        foreach (var raw in paths)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            string trimmed = raw.Trim().Trim('"').TrimEnd('\\', '/');
            if (trimmed.Length == 2 && trimmed[1] == ':') return true;
        }
        return false;
    }

    static (bool ShouldUpload, string SkipReason) EvaluateUpload(ScanItem item, ScanOptions opts, bool isLargeSweep)
    {
        long size = item.SizeBytes;
        if (size == 0) return (false, Strings.SkipReasonNotSubmittedEmpty);
        if (size > AppConstants.MaxUploadBytes) return (false, Strings.SkipReasonNotSubmittedTooLarge);

        switch (opts.UploadPolicy)
        {
            case 0: return (false, Strings.SkipReasonNotSubmittedPolicy);
            case 2: return (true, "");
            default:
                if (!FileClass.IsWorthUploading(item.FilePath))
                    return (false, Strings.SkipReasonNotSubmitted);
                if (isLargeSweep && !opts.ExplicitFileSelection && !item.IsPriorityBoosted)
                    return (false, Strings.SkipReasonNotSubmittedSweep);
                return (true, "");
        }
    }

    static readonly int[] PollDelaysSeconds = [15, 20, 30, 45, 60, 90, 120, 150, 180, 210, 240];
    public static readonly int PollWindowMinutes = PollDelaysSeconds.Sum() / 60;

    async Task<VtFileReport?> PollUntilCompleteAsync(string analysisId, string sha256, ScanItem item, CancellationToken ct)
    {
        for (int i = 0; i < PollDelaysSeconds.Length; i++)
        {
            ct.ThrowIfCancellationRequested();
            await _pause.WaitWhilePausedAsync(ct);
            await Task.Delay(TimeSpan.FromSeconds(PollDelaysSeconds[i]), ct);

            var (gotKey, info) = await _apiCoord.GetAnalysisAsync(analysisId, item.UrgentOrder, item.PriorityTier, ApiWaitForPoll, ct);
            if (!gotKey || info == null)
            {
                ItemWrite(() => item.Detail = Strings.PollWaitingForQuota);
                continue;
            }
            ItemWrite(() => item.Detail = string.Format(Strings.PollProgressDetailFormat, info.Status, i + 1));
            if (info.IsCompleted)
            {
                var (gotReportKey, finished) = await _apiCoord.LookupFileReportAsync(
                    sha256, ApiWorkKind.Poll, item.UrgentOrder, item.PriorityTier, ApiWaitForPoll, ct);
                if (finished != null) return finished;
                if (gotReportKey)
                {
                    await Task.Delay(TimeSpan.FromSeconds(3), ct);
                    (_, finished) = await _apiCoord.LookupFileReportAsync(
                        sha256, ApiWorkKind.Poll, item.UrgentOrder, item.PriorityTier, ApiWaitForPoll, ct);
                    if (finished != null) return finished;
                }
                if (!gotReportKey && BrowserSessionFactory.IsRuntimeAvailable)
                    return await GuiScrapeService.LookupAsync(sha256, ct, TimeSpan.FromSeconds(30));
                return null;
            }
        }
        Log($"Analysis {analysisId} for {item.FileName} still unfinished after {PollWindowMinutes} min.", LogLevel.Warning);
        return null;
    }

    // ---- progress bookkeeping ----

    void SetStatus(ScanItem item, ScanStatus status) => ItemWrite(() => item.Status = status);

    void Complete(ScanItem item, VtFileReport report)
    {
        SetStatus(item, ScanStatus.Completed);
        PendingOutbox.Remove(item.FilePath);
    }

    void TrustSkip(ScanItem item, string reason, string? publisher)
    {
        ItemWrite(() => { item.SkipReason = reason; item.Publisher = publisher; item.Status = ScanStatus.TrustedSkipped; });
        Log($"VT skipped (trusted): {item.FileName} — {reason}", LogLevel.Info);
    }

    /// <summary>Reconciles all counters authoritatively from the live session rows so in-place rescans,
    /// live appends, and promotions never drift or reset the progress bar.</summary>
    void RecountCounters()
    {
        int total = 0, done = 0, mal = 0, susp = 0, clean = 0, unk = 0, fail = 0, skip = 0, signed = 0;
        lock (_itemsLock)
        {
            total = _allItems.Count;
            foreach (var it in _allItems)
            {
                switch (it.Status)
                {
                    case ScanStatus.Completed:
                        done++;
                        switch (VerdictClassifier.Of(it.Report))
                        {
                            case VerdictClass.Malicious:
                                bool topBand = it.Report != null && ReferenceEquals(VerdictCategories.Classify(it.Report.DetectionCount), VerdictCategories.All[^1]);
                                if (topBand) mal++; else susp++;
                                break;
                            case VerdictClass.Suspicious: susp++; break;
                            case VerdictClass.Clean: clean++; break;
                            default: unk++; break;
                        }
                        break;
                    case ScanStatus.TrustedSkipped:
                        done++; signed++; break;
                    case ScanStatus.Skipped:
                        done++; skip++; break;
                    case ScanStatus.Failed:
                        done++; fail++; break;
                    case ScanStatus.Cancelled:
                        done++; break;
                }
            }
        }
        Volatile.Write(ref _total, total);
        Volatile.Write(ref _done, done);
        Volatile.Write(ref _malicious, mal);
        Volatile.Write(ref _suspicious, susp);
        Volatile.Write(ref _clean, clean);
        Volatile.Write(ref _unknown, unk);
        Volatile.Write(ref _failed, fail);
        Volatile.Write(ref _skipped, skip);
        Volatile.Write(ref _signedSkipped, signed);
    }

    /// <summary>Adds a standalone lookup item (e.g. manual Hash Lookup) to the session cleanly.</summary>
    public void AddManualItem(ScanItem item)
    {
        lock (_itemsLock)
        {
            if (!_allItems.Contains(item)) _allItems.Add(item);
        }
        UiPost(() =>
        {
            if (!Items.Contains(item)) Items.Add(item);
        });
        RecountCounters();
        ReportProgress();
    }

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

    void ItemWrite(Action write)
    {
        if (Volatile.Read(ref _quietItems) == 1)
        {
            try { write(); } catch (Exception ex) { Log("Item write failed: " + ex.Message, LogLevel.Warning); }
        }
        else UiPost(write);
    }

    sealed class Restore(Action onDispose) : IDisposable
    {
        int _done;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) == 1) return;
            try { onDispose(); } catch (Exception ex) { Log("Restore failed: " + ex.Message, LogLevel.Warning); }
        }
    }

    void BulkAdd(List<ScanItem> toAdd)
    {
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
    int _shownAwaiting = -1, _shownAnalyses = -1;
    bool _shownPaused;
    long _shownHeldTicks;

    void FlushProgress()
    {
        int awaiting = NetworkQueueDepth, analyses = _pendingAnalyses.Count;
        bool paused = _pause.IsPaused;
        long held = Interlocked.Read(ref _channelsHeldUntilTicks);
        bool shapeChanged = awaiting != _shownAwaiting || analyses != _shownAnalyses || paused != _shownPaused || held != _shownHeldTicks;
        bool etaTick = IsRunning && Volatile.Read(ref _done) < Volatile.Read(ref _total)
            && (_stopwatch.ElapsedMilliseconds - Volatile.Read(ref _lastProgressEmitMs)) >= 1000;
        if (Interlocked.Exchange(ref _progressDirty, 0) == 1 || shapeChanged || etaTick)
        {
            (_shownAwaiting, _shownAnalyses, _shownPaused, _shownHeldTicks) = (awaiting, analyses, paused, held);
            ReportProgress();
        }
    }

    (double Rate, TimeSpan? Remaining) EstimateProgress(int total, int done)
    {
        bool keylessAvailable = (_currentOpts?.ForceKeyless == true || Settings.KeylessGuiLookup) && BrowserSessionFactory.IsRuntimeAvailable;
        return _eta.Estimate(
            total,
            done,
            NetworkQueueDepth,
            _pendingAnalyses.Count,
            Interlocked.Read(ref _channelsHeldUntilTicks),
            _rotator.GetQuotaSnapshot(),
            keylessAvailable,
            keylessParked: false,
            _pause.IsPaused);
    }

    void ResetCounters() { _total = _done = _malicious = _suspicious = _clean = _unknown = _failed = _skipped = _signedSkipped = 0; }

    void ReportProgress()
    {
        Volatile.Write(ref _lastProgressEmitMs, _stopwatch.ElapsedMilliseconds);
        int total = Volatile.Read(ref _total), done = Volatile.Read(ref _done);
        var p = new OverallProgress
        {
            Total = total,
            Done = done,
            Malicious = Volatile.Read(ref _malicious),
            Suspicious = Volatile.Read(ref _suspicious),
            Clean = Volatile.Read(ref _clean),
            Unknown = Volatile.Read(ref _unknown),
            Failed = Volatile.Read(ref _failed),
            Skipped = Volatile.Read(ref _skipped),
            SignedSkipped = Volatile.Read(ref _signedSkipped),
            AwaitingLookup = NetworkQueueDepth,
            AnalysesPending = _pendingAnalyses.Count,
            Paused = _pause.IsPaused,
        };
        long held = Interlocked.Read(ref _channelsHeldUntilTicks);
        if (held > DateTime.UtcNow.Ticks) p.NetworkHeldUntilUtc = new DateTime(held, DateTimeKind.Utc);
        var (rate, rem) = EstimateProgress(total, done);
        p.Elapsed = _stopwatch.Elapsed;
        p.FilesPerSec = rate;
        p.Remaining = rem;
        UiPost(() => { try { ProgressChanged?.Invoke(p); } catch (Exception ex) { Log("ProgressChanged handler failed: " + ex.Message, LogLevel.Warning); } });
    }
}
