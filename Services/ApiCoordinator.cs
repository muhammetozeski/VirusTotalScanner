namespace VirusTotalScanner;

/// <summary>API work classes ordered by intrinsic urgency (lower = served sooner).</summary>
internal enum ApiWorkKind
{
    /// <summary>Checking status or fetching completed report for an already-uploaded analysis.</summary>
    Poll = 0,
    /// <summary>Submitting an unknown (404) file — only the API can upload files.</summary>
    Upload = 1,
    /// <summary>Hash lookup for a QueryCell whose browser resistance reached 100/100.</summary>
    ExhaustedLookup = 2,
    /// <summary>Hash lookup admitted early while API load was low enough for the cell's resistance.</summary>
    AssistLookup = 3,
}

/// <summary>
/// Central API manager with continuous, scale-invariant load scoring (0..100) and a priority-ordered
/// dispatch queue.
///
/// Key properties:
///   - No arbitrary hardcoded queue-count cutoffs: load pressure L in [0, 100] is computed from actual
///     sustainable key throughput (4 req/min/key), immediate minute-window room, daily quota utilization,
///     and weighted queued work (uploads weigh 4x because they also require analysis polls).
///   - Cells asking for lookup admission are admitted iff R == 100 (exhausted all browser options) or
///     R >= L (their resistance effort matches or exceeds current API pressure).
///   - Urgent/priority-boosted items (user "Yeniden/Şimdi Tara") jump to the front of waiting API queues
///     without EVER cancelling or interrupting an in-flight upload or request.
/// </summary>
internal sealed class ApiCoordinator
{
    readonly KeyRotator _rotator;
    readonly VtApiClient _api;

    // Priority queue for waiting API slot acquisitions (not for cancelling active work!)
    readonly object _qLock = new();
    readonly PriorityQueue<Waiter, WaitKey> _waiters = new();
    long _waiterSeq;
    int _pendingUploads;
    int _pendingPolls;
    int _pendingLookups;
    int _activeCalls;
    int _activeUploads;
    int _maxConcurrentUploads = 2;

    // Dedicated concurrency gate for actual HTTP upload streams (re-sized safely when idle or clamped)
    readonly object _upLock = new();
    readonly PriorityQueue<UploadWaiter, WaitKey> _uploadWaiters = new();

    readonly record struct WaitKey(
        int ClassRank,      // 0 = Poll, 1 = Urgent user boost, 2 = Upload, 3 = ExhaustedLookup, 4 = AssistLookup
        long NegUrgent,     // more recently promoted urgent item first
        int FileTier,       // exe(0) < dll(1) < bat(2) < ps1(4) < lnk(6) < ...
        long Seq) : IComparable<WaitKey>
    {
        public int CompareTo(WaitKey other)
        {
            int c = ClassRank.CompareTo(other.ClassRank);
            if (c != 0) return c;
            c = NegUrgent.CompareTo(other.NegUrgent);
            if (c != 0) return c;
            c = FileTier.CompareTo(other.FileTier);
            return c != 0 ? c : Seq.CompareTo(other.Seq);
        }
    }

    sealed class Waiter(ApiWorkKind kind, TaskCompletionSource<bool> tcs, CancellationToken ct)
    {
        public ApiWorkKind Kind { get; } = kind;
        public TaskCompletionSource<bool> Tcs { get; } = tcs;
        public CancellationToken Ct { get; } = ct;
        public bool Cancelled;
    }

    sealed class UploadWaiter(TaskCompletionSource<bool> tcs, CancellationToken ct)
    {
        public TaskCompletionSource<bool> Tcs { get; } = tcs;
        public CancellationToken Ct { get; } = ct;
        public bool Cancelled;
    }

    public ApiCoordinator(KeyRotator rotator, VtApiClient api)
    {
        _rotator = rotator;
        _api = api;
    }

    public bool HasUsableKeys => _rotator.HasUsableKeys;
    public int PendingUploadCount => Volatile.Read(ref _pendingUploads);
    public int PendingLookupCount => Volatile.Read(ref _pendingLookups);
    public int PendingPollCount => Volatile.Read(ref _pendingPolls);
    public int ActiveUploadCount => Volatile.Read(ref _activeUploads);

    public void ConfigureConcurrency(int maxUploads)
    {
        lock (_upLock)
        {
            _maxConcurrentUploads = Math.Max(1, maxUploads);
            PumpUploadWaitersLocked();
        }
    }

    /// <summary>
    /// Computes the balanced, scale-invariant API load pressure L in [0, 100]:
    ///   - m: live minute-window utilization across keys with daily room (cubic m^3: near 0 while keys sit
    ///        at 0/4..2/4 so use-it-or-lose-it minute slots are actually used, then ramps sharply at 3/4..4/4
    ///        to reserve the final buffer for uploads, polls, and high-resistance cells).
    ///   - q: queue drain time beyond ImmediateRoom relative to VT's 60s window.
    ///   - u: convex upload-protection pressure (light when 1-2 uploads exist with plenty of room, strong
    ///        when uploads saturate the minute window).
    ///   - d: convex daily-quota protection d^4 (near 0 at 20-50% daily usage, rises steeply above 75%).
    ///   - Combined via noisy-OR, plus a reset-wait floor when ImmediateRoom == 0.
    /// </summary>
    public double ComputeLoadScore()
    {
        var snap = _rotator.GetQuotaSnapshot();
        if (snap.UsableKeys <= 0 || snap.DailyRemaining <= 0) return 100.0;

        int up = Volatile.Read(ref _pendingUploads) + Volatile.Read(ref _activeUploads);
        int poll = Volatile.Read(ref _pendingPolls);
        int look = Volatile.Read(ref _pendingLookups);

        double weightedWork = (4.0 * up) + (2.0 * poll) + (1.0 * look);
        double sustainedRate = Math.Max(1e-3, snap.KeysWithDailyRoom * (AppConstants.RatePerMinute / 60.0));
        double overflow = Math.Max(0.0, weightedWork - snap.ImmediateRoom);
        double drainSec = overflow / sustainedRate;

        const double windowSec = 60.0;
        double q = drainSec / (drainSec + windowSec);

        // Live minute-window utilization (cubic): 0/4..2/4 stays low (0..11) so idle minute slots don't
        // expire unused; 3/4..4/4 climbs steeply (36..85+) to guard headroom for uploads and deep resistance.
        double mRaw = snap.MinuteAllowed > 0
            ? Math.Clamp(1.0 - ((double)snap.ImmediateRoom / snap.MinuteAllowed), 0.0, 1.0)
            : 1.0;
        double m = mRaw * mRaw * mRaw;

        // Convex upload protection: 1-2 uploads on 56 free slots barely nudges L; heavy upload queues guard API strongly.
        double uRaw = (4.0 * up) / ((4.0 * up) + snap.ImmediateRoom + 1.0);
        double u = uRaw * uRaw;

        // Convex daily conservation (d^4): negligible at 20-50% daily usage, kicks in strongly past 75-85%.
        double dRaw = snap.DailyAllowed > 0
            ? Math.Clamp(1.0 - ((double)snap.DailyRemaining / snap.DailyAllowed), 0.0, 1.0)
            : 0.0;
        double d = dRaw * dRaw * dRaw * dRaw;

        double baseLoad = 100.0 * (1.0 - (1.0 - q) * (1.0 - 0.85 * m) * (1.0 - 0.80 * u) * (1.0 - 0.85 * d));

        if (snap.ImmediateRoom <= 0 && snap.SoonestResetUtc is { } reset)
        {
            double waitSec = Math.Max(0.0, (reset - DateTime.UtcNow).TotalSeconds);
            double waitFloor = 100.0 * (waitSec / (waitSec + 25.0));
            baseLoad = Math.Max(baseLoad, waitFloor);
        }

        return Math.Clamp(baseLoad, 0.0, 100.0);
    }

    /// <summary>
    /// Decides whether a QueryCell with resistance score <paramref name="resistanceScore"/> (0..100)
    /// may enter the API lookup queue right now.
    ///   - No usable keys or daily quota completely empty -> false (keep using browser).
    ///   - ResistanceScore >= 100 (cell exhausted all non-API options) -> true (unconditional admission).
    ///   - Otherwise -> true iff ResistanceScore >= ComputeLoadScore().
    /// </summary>
    public bool TryAdmitLookup(double resistanceScore, out double currentLoadScore)
    {
        currentLoadScore = ComputeLoadScore();
        var snap = _rotator.GetQuotaSnapshot();
        if (snap.UsableKeys <= 0 || snap.DailyRemaining <= 0) return false;
        if (resistanceScore >= 99.9) return true;
        return resistanceScore >= currentLoadScore;
    }

    /// <summary>Queued, priority-ordered API file report lookup.</summary>
    public async Task<(bool Served, VtFileReport? Report)> LookupFileReportAsync(
        string sha256,
        ApiWorkKind kind,
        long urgentOrder,
        int fileTier,
        TimeSpan maxWait,
        CancellationToken ct)
    {
        if (!_rotator.HasUsableKeys) return (false, null);
        return await ExecuteQueuedCallAsync(
            kind, urgentOrder, fileTier,
            key => _api.GetFileReportAsync(sha256, key, ct),
            maxWait, ct);
    }

    /// <summary>Queued, priority-ordered API file upload. Never cancels an active upload when a higher-priority
    /// item arrives — the urgent item simply takes the next free upload &amp; API slot.</summary>
    public async Task<(bool Served, string? AnalysisId)> UploadFileAsync(
        string filePath,
        long urgentOrder,
        int fileTier,
        IProgress<UploadProgress>? progress,
        TimeSpan maxWait,
        CancellationToken ct)
    {
        if (!_rotator.HasUsableKeys) return (false, null);

        Interlocked.Increment(ref _pendingUploads);
        bool acquiredUploadSlot = false;
        try
        {
            await WaitUploadSlotAsync(urgentOrder, fileTier, ct);
            acquiredUploadSlot = true;
            return await ExecuteQueuedCallAsync(
                ApiWorkKind.Upload, urgentOrder, fileTier,
                key => _api.UploadFileAsync(filePath, key, progress, ct),
                maxWait, ct, countAsPending: false);
        }
        finally
        {
            Interlocked.Decrement(ref _pendingUploads);
            if (acquiredUploadSlot) ReleaseUploadSlot();
        }
    }

    /// <summary>Highest-priority API call for polling an already-submitted analysis.</summary>
    public async Task<(bool Served, VtAnalysisInfo? Info)> GetAnalysisAsync(
        string analysisId,
        long urgentOrder,
        int fileTier,
        TimeSpan maxWait,
        CancellationToken ct)
    {
        if (!_rotator.HasUsableKeys) return (false, null);
        return await ExecuteQueuedCallAsync(
            ApiWorkKind.Poll, urgentOrder, fileTier,
            key => _api.GetAnalysisAsync(analysisId, key, ct),
            maxWait, ct);
    }

    async Task<(bool Served, T? Value)> ExecuteQueuedCallAsync<T>(
        ApiWorkKind kind,
        long urgentOrder,
        int fileTier,
        Func<string, Task<T>> call,
        TimeSpan maxWait,
        CancellationToken ct,
        bool countAsPending = true)
    {
        if (countAsPending) BumpKind(kind, +1);
        bool hasDispatchSlot = false;
        try
        {
            await WaitDispatchSlotAsync(kind, urgentOrder, fileTier, ct);
            hasDispatchSlot = true;
            return await CallWithKeyRotationAsync(call, maxWait, ct);
        }
        finally
        {
            if (hasDispatchSlot) ReleaseDispatchSlot();
            if (countAsPending) BumpKind(kind, -1);
        }
    }

    void BumpKind(ApiWorkKind kind, int delta)
    {
        switch (kind)
        {
            case ApiWorkKind.Poll: Interlocked.Add(ref _pendingPolls, delta); break;
            case ApiWorkKind.Upload: Interlocked.Add(ref _pendingUploads, delta); break;
            default: Interlocked.Add(ref _pendingLookups, delta); break;
        }
    }

    int MaxParallelApiCalls => Math.Max(2, Math.Min(16, Math.Max(2, _rotator.UsableKeyCount * 2)));

    Task WaitDispatchSlotAsync(ApiWorkKind kind, long urgentOrder, int fileTier, CancellationToken ct)
    {
        lock (_qLock)
        {
            if (_activeCalls < MaxParallelApiCalls && _waiters.Count == 0)
            {
                _activeCalls++;
                return Task.CompletedTask;
            }
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var w = new Waiter(kind, tcs, ct);
            var key = MakeKey(kind, urgentOrder, fileTier, ++_waiterSeq);
            _waiters.Enqueue(w, key);
            if (ct.CanBeCanceled)
            {
                ct.Register(() =>
                {
                    lock (_qLock) w.Cancelled = true;
                    tcs.TrySetCanceled(ct);
                });
            }
            return tcs.Task;
        }
    }

    void ReleaseDispatchSlot()
    {
        lock (_qLock)
        {
            _activeCalls = Math.Max(0, _activeCalls - 1);
            while (_activeCalls < MaxParallelApiCalls && _waiters.Count > 0)
            {
                var next = _waiters.Dequeue();
                if (next.Cancelled || next.Ct.IsCancellationRequested) continue;
                _activeCalls++;
                if (next.Tcs.TrySetResult(true)) continue;
                _activeCalls--;
            }
        }
    }

    Task WaitUploadSlotAsync(long urgentOrder, int fileTier, CancellationToken ct)
    {
        lock (_upLock)
        {
            if (_activeUploads < _maxConcurrentUploads && _uploadWaiters.Count == 0)
            {
                _activeUploads++;
                return Task.CompletedTask;
            }
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var w = new UploadWaiter(tcs, ct);
            var key = MakeKey(ApiWorkKind.Upload, urgentOrder, fileTier, ++_waiterSeq);
            _uploadWaiters.Enqueue(w, key);
            if (ct.CanBeCanceled)
            {
                ct.Register(() =>
                {
                    lock (_upLock) w.Cancelled = true;
                    tcs.TrySetCanceled(ct);
                });
            }
            return tcs.Task;
        }
    }

    void ReleaseUploadSlot()
    {
        lock (_upLock)
        {
            _activeUploads = Math.Max(0, _activeUploads - 1);
            PumpUploadWaitersLocked();
        }
    }

    void PumpUploadWaitersLocked()
    {
        while (_activeUploads < _maxConcurrentUploads && _uploadWaiters.Count > 0)
        {
            var next = _uploadWaiters.Dequeue();
            if (next.Cancelled || next.Ct.IsCancellationRequested) continue;
            _activeUploads++;
            if (next.Tcs.TrySetResult(true)) continue;
            _activeUploads--;
        }
    }

    static WaitKey MakeKey(ApiWorkKind kind, long urgentOrder, int fileTier, long seq)
    {
        // Polls of already-uploaded files stay class 0 so they don't time out;
        // user-promoted urgent items jump to class 1 ahead of normal uploads/lookups.
        int classRank = kind == ApiWorkKind.Poll ? 0
            : urgentOrder > 0 ? 1
            : kind == ApiWorkKind.Upload ? 2
            : kind == ApiWorkKind.ExhaustedLookup ? 3
            : 4;
        return new WaitKey(classRank, -urgentOrder, fileTier, seq);
    }

    async Task<(bool Served, T? Value)> CallWithKeyRotationAsync<T>(Func<string, Task<T>> call, TimeSpan maxWait, CancellationToken ct)
    {
        int maxAttempts = Math.Max(2, Math.Min(_rotator.UsableKeyCount + 2, 16));
        var deadline = maxWait == Timeout.InfiniteTimeSpan ? DateTime.MaxValue : DateTime.UtcNow + maxWait;

        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            var left = deadline == DateTime.MaxValue ? Timeout.InfiniteTimeSpan : deadline - DateTime.UtcNow;
            if (left != Timeout.InfiniteTimeSpan && left <= TimeSpan.Zero) return (false, default);

            string? key = await _rotator.AcquireAsync(left, ct);
            if (key == null) return (false, default);

            try
            {
                var value = await call(key).WaitAsync(ct);
                _rotator.ReportSuccess(key);
                return (true, value);
            }
            catch (VtRateLimitException ex) { _rotator.ReportRateLimited(key, ex.RetryAfter); }
            catch (VtAuthException ex) { _rotator.ReportAuthError(key, ex); }
            catch (HttpRequestException ex)
            {
                Log("VirusTotal API transport failure: " + ex.Message, LogLevel.Warning);
                return (false, default);
            }
            catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
            {
                Log("VirusTotal API request timed out: " + ex.Message, LogLevel.Warning);
                return (false, default);
            }
            catch (VtApiException ex) when (ex.StatusCode is { } sc && (int)sc >= 500)
            {
                Log($"VirusTotal API server error {(int)sc}: {ex.Message}", LogLevel.Warning);
                return (false, default);
            }
        }
        return (false, default);
    }
}
