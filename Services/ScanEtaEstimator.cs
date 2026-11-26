using System.Collections.Concurrent;

namespace VirusTotalScanner;

/// <summary>
/// Multi-stage, size- and quota-aware ETA estimator for <see cref="ScanScheduler"/>.
///
/// Models the actual parallel scan pipeline instead of dividing remaining file count by a naive
/// rolling files/sec window:
///   1) Local disk stage (1 worker): affine in file count + bytes (signature/cache overhead + hashing MB/s).
///   2) Network lookup stage (W workers + API/keyless quota): uses Empirical Bayes (Beta-Binomial) to
///      estimate what share of remaining disk files will reach VirusTotal, combined with exact active
///      queue depth, API minute-window burst/sustained replenishment rate, and any active hold-off.
///   3) Upload &amp; cloud-analysis tail: tracks live remaining bytes of in-flight uploads (divided by
///      EWMA upload bandwidth) plus the parallel makespan max_j(remaining_poll_j) of in-flight VT
///      analyses and expected future uploads.
///   4) Asymmetric EWMA smoothing + steady between-tick countdown so the displayed ETA never jumps
///      wildly when a cached batch or a single huge file finishes.
/// </summary>
internal sealed class ScanEtaEstimator
{
    readonly object _lock = new();
    readonly System.Diagnostics.Stopwatch _clock = new();

    // Run geometry
    int _totalFiles;
    long _totalKnownBytes;      // exact sum of all file sizes when cheaply pre-computed (<= PreSizeLimit files)
    bool _hasExactTotalBytes;
    int _concurrency = 1;
    int _maxUploads = 1;
    bool _uploadsPossible;

    // Local stage progress & EWMA rates
    int _localProcessed;        // files that have completed the local stage (either finished locally or queued to net)
    int _handedToNet;           // subset of _localProcessed that needed VT network lookup
    long _localBytesProcessed;  // exact bytes of files that have passed the local stage
    double _ewmaHashBps = 250.0 * 1024 * 1024;    // prior: 250 MB/s SSD SHA-256 + MD5
    double _ewmaLocalOverheadSec = 0.015;         // prior: 15 ms per file (trust/cache/open)
    double _ewmaFileBytes = 512.0 * 1024;         // prior: 512 KB average file size (used when total bytes unknown)
    bool _hasHashSample;
    bool _hasOverheadSample;
    bool _hasSizeSample;

    // Network lookup stage metrics
    int _netCompleted;          // network lookups that returned a verdict or 404
    int _netUploaded;           // subset of _netCompleted that triggered a file upload
    double _ewmaLookupSec = 0.55;                 // prior: ~550 ms API lookup
    double _ewmaKeylessSec = 3.5;                 // prior: ~3.5 s keyless lookup
    bool _hasLookupSample;

    // Upload bandwidth & cloud analysis duration
    double _ewmaUploadBps = 2.0 * 1024 * 1024;    // prior: 2 MB/s upload speed
    bool _hasUploadBpsSample;
    double _ewmaPollSec = 42.0;                   // prior: ~42 s VirusTotal analysis time
    bool _hasPollSample;

    // Live in-flight uploads and cloud analyses (keyed by item sequence / watch key)
    readonly ConcurrentDictionary<long, (long TotalBytes, long BytesSent)> _activeUploads = new();
    readonly ConcurrentDictionary<string, long> _activePolls = new(StringComparer.Ordinal); // key -> start elapsed ms

    // Smoothed ETA state (for steady, jitter-free display)
    double _smoothedRemSec = -1;
    double _lastEstimateAtSec;

    // Rolling throughput for display (files/sec over recent completions, blended with overall)
    readonly Queue<long> _recentDoneMs = new();

    const int PreSizeLimit = 2500;

    public void Reset(IReadOnlyList<ScanItem> items, ScanOptions opts, bool isLargeSweep)
    {
        lock (_lock)
        {
            _clock.Restart();
            _totalFiles = items.Count;
            _concurrency = Math.Max(1, Math.Max(opts.MaxConcurrency, BrowserSessionFactory.DesiredConcurrency()));
            _maxUploads = Math.Max(1, opts.MaxUploads);
            _uploadsPossible = opts.UploadPolicy == 2 || (opts.UploadPolicy == 1 && (!isLargeSweep || opts.ExplicitFileSelection));

            _localProcessed = 0;
            _handedToNet = 0;
            _localBytesProcessed = 0;
            _netCompleted = 0;
            _netUploaded = 0;
            _smoothedRemSec = -1;
            _lastEstimateAtSec = 0;
            _recentDoneMs.Clear();
            _activeUploads.Clear();
            _activePolls.Clear();

            // Pre-sum file sizes for small/medium scans (fast, <15 ms for <=2500 files) so ETA knows
            // upfront whether 500 MB of binaries are waiting behind ten 4 KB scripts.
            if (items.Count <= PreSizeLimit)
            {
                long sum = 0;
                int valid = 0;
                for (int i = 0; i < items.Count; i++)
                {
                    long sz = items[i].SizeBytes;
                    if (sz >= 0) { sum += sz; valid++; }
                }
                _totalKnownBytes = sum;
                _hasExactTotalBytes = true;
                if (valid > 0) { _ewmaFileBytes = (double)sum / valid; _hasSizeSample = true; }
            }
            else
            {
                _totalKnownBytes = 0;
                _hasExactTotalBytes = false;
            }
        }
    }

    /// <summary>Updates total tracked items/bytes when new items are appended or rescanned in place mid-run.</summary>
    public void AddPendingWork(IReadOnlyList<ScanItem> added)
    {
        lock (_lock)
        {
            _totalFiles += added.Count;
            if (_hasExactTotalBytes)
            {
                foreach (var it in added)
                {
                    long sz = it.SizeBytes;
                    if (sz >= 0) _totalKnownBytes += sz;
                }
            }
        }
    }

    public void RecordLocalStage(long fileBytes, double totalSec, double hashSec, bool hashedFromDisk, bool sentToNetwork)
    {
        long bytes = Math.Max(0, fileBytes);
        lock (_lock)
        {
            _localProcessed++;
            if (sentToNetwork) _handedToNet++;
            _localBytesProcessed += bytes;

            if (!_hasSizeSample) { _ewmaFileBytes = Math.Max(1024, bytes); _hasSizeSample = true; }
            else _ewmaFileBytes = 0.90 * _ewmaFileBytes + 0.10 * bytes;

            // Update disk hashing speed only on meaningful reads (>= 256 KB, >= 2 ms) so tiny files
            // don't distort MB/s with open/close syscall noise.
            if (hashedFromDisk && bytes >= 256 * 1024 && hashSec >= 0.002)
            {
                double bps = Math.Clamp(bytes / hashSec, 5.0 * 1024 * 1024, 4000.0 * 1024 * 1024);
                _ewmaHashBps = _hasHashSample ? 0.75 * _ewmaHashBps + 0.25 * bps : bps;
                _hasHashSample = true;
            }

            double overhead = Math.Max(0.0005, totalSec - (hashedFromDisk ? hashSec : 0));
            overhead = Math.Min(overhead, 5.0);
            _ewmaLocalOverheadSec = _hasOverheadSample ? 0.85 * _ewmaLocalOverheadSec + 0.15 * overhead : overhead;
            _hasOverheadSample = true;
        }
    }

    public void RecordLookup(double seconds, bool viaKeyless, bool triggeredUpload)
    {
        double clamped = Math.Clamp(seconds, 0.05, 60.0);
        lock (_lock)
        {
            _netCompleted++;
            if (triggeredUpload) _netUploaded++;
            if (viaKeyless)
                _ewmaKeylessSec = 0.75 * _ewmaKeylessSec + 0.25 * clamped;
            else
            {
                _ewmaLookupSec = _hasLookupSample ? 0.75 * _ewmaLookupSec + 0.25 * clamped : clamped;
                _hasLookupSample = true;
            }
        }
    }

    public void UpdateUploadProgress(long itemKey, long totalBytes, long bytesSent, double bytesPerSecond)
    {
        _activeUploads[itemKey] = (Math.Max(0, totalBytes), Math.Max(0, bytesSent));
        if (bytesPerSecond >= 16 * 1024)
        {
            double clamped = Math.Clamp(bytesPerSecond, 32 * 1024, 500.0 * 1024 * 1024);
            lock (_lock)
            {
                _ewmaUploadBps = _hasUploadBpsSample ? 0.80 * _ewmaUploadBps + 0.20 * clamped : clamped;
                _hasUploadBpsSample = true;
            }
        }
    }

    public void EndUpload(long itemKey) => _activeUploads.TryRemove(itemKey, out _);

    public void BeginPoll(string watchKey) => _activePolls[watchKey] = _clock.ElapsedMilliseconds;

    public void EndPoll(string watchKey, bool completed)
    {
        if (!_activePolls.TryRemove(watchKey, out long startMs)) return;
        if (!completed) return;
        double durSec = Math.Clamp((_clock.ElapsedMilliseconds - startMs) / 1000.0, 5.0, 900.0);
        lock (_lock)
        {
            _ewmaPollSec = _hasPollSample ? 0.70 * _ewmaPollSec + 0.30 * durSec : durSec;
            _hasPollSample = true;
        }
    }

    public void RecordItemDone()
    {
        lock (_lock)
        {
            _recentDoneMs.Enqueue(_clock.ElapsedMilliseconds);
            while (_recentDoneMs.Count > 30) _recentDoneMs.Dequeue();
        }
    }

    /// <summary>Computes live files/sec and the mathematically modeled remaining time.</summary>
    public (double FilesPerSec, TimeSpan? Remaining) Estimate(
        int total,
        int done,
        int awaitingLookup,
        int activePollCount,
        long channelsHeldUntilTicks,
        KeyQuotaSnapshot quota,
        bool keylessAvailable,
        bool keylessParked,
        bool paused)
    {
        lock (_lock)
        {
            double nowSec = _clock.ElapsedMilliseconds / 1000.0;
            int leftTotal = Math.Max(0, total - done);

            // Display rate: recent completion window, falling back to overall average
            double rate = 0;
            if (_recentDoneMs.Count >= 2)
            {
                long span = _recentDoneMs.Last() - _recentDoneMs.First();
                if (span > 0) rate = (_recentDoneMs.Count - 1) / (span / 1000.0);
            }
            else if (done > 0 && nowSec > 0.1)
            {
                rate = done / nowSec;
            }

            if (leftTotal == 0)
            {
                _smoothedRemSec = 0;
                _lastEstimateAtSec = nowSec;
                return (rate, TimeSpan.Zero);
            }

            if (paused)
            {
                _lastEstimateAtSec = nowSec;
                return (rate, _smoothedRemSec >= 0 ? TimeSpan.FromSeconds(_smoothedRemSec) : null);
            }

            // ---- Stage 1: Remaining local disk work (1 worker, affine in count + bytes) ----
            int diskRem = Math.Max(0, _totalFiles - _localProcessed);
            double diskRemBytes = _hasExactTotalBytes
                ? Math.Max(0, _totalKnownBytes - _localBytesProcessed)
                : diskRem * _ewmaFileBytes;
            double tDisk = diskRem > 0
                ? (diskRem * _ewmaLocalOverheadSec) + (diskRemBytes / Math.Max(1.0, _ewmaHashBps))
                : 0.0;

            // ---- Stage 2: Remaining network lookups (queued + Empirical Bayes share of remaining disk files) ----
            // Beta(1.5, 1.5) prior stabilizes early estimates and converges quickly to true folder hit rate.
            double pNet = (_handedToNet + 1.5) / (_localProcessed + 3.0);
            int activeUploadCount = _activeUploads.Count;
            int inFlightLookup = Math.Max(0, leftTotal - diskRem - activePollCount - activeUploadCount);
            double expectedNetRem = Math.Max(awaitingLookup, inFlightLookup) + (diskRem * pNet);

            double tNet = ComputeNetworkStageSeconds(expectedNetRem, channelsHeldUntilTicks, quota, keylessAvailable, keylessParked);

            // ---- Stage 3: Active uploads + expected future uploads ----
            double activeUploadRemBytes = 0;
            foreach (var kv in _activeUploads)
                activeUploadRemBytes += Math.Max(0, kv.Value.TotalBytes - kv.Value.BytesSent);

            double effUpBps = Math.Max(32.0 * 1024, _ewmaUploadBps);
            double tUploadActive = activeUploadRemBytes / effUpBps;

            double tUploadFuture = 0;
            double expectedFutureUploads = 0;
            if (_uploadsPossible && expectedNetRem > 0.5)
            {
                // Empirical Bayes upload probability (Beta(0.5, 3.5) prior -> ~12.5% initially, converges fast)
                double pUp = (_netUploaded + 0.5) / (_netCompleted + 4.0);
                expectedFutureUploads = expectedNetRem * pUp;
                double avgBytes = Math.Min(_ewmaFileBytes, AppConstants.MaxUploadBytes);
                double futureUploadBytes = expectedFutureUploads * avgBytes;
                tUploadFuture = futureUploadBytes / effUpBps;
                // Each upload also consumes ~1 upload + ~2-3 poll API requests
                if (quota.UsableKeys > 0 && expectedFutureUploads >= 1.0)
                {
                    double extraReqs = expectedFutureUploads * 3.0;
                    double apiSustained = Math.Max(0.05, quota.UsableKeys * (AppConstants.RatePerMinute / 60.0));
                    tUploadFuture = Math.Max(tUploadFuture, extraReqs / apiSustained);
                }
            }

            // ---- Stage 4: Cloud analysis polling tail (parallel makespan across all in-flight polls) ----
            double tPollActive = 0;
            long nowMs = _clock.ElapsedMilliseconds;
            foreach (var kv in _activePolls)
            {
                double elapsedPoll = Math.Max(0, (nowMs - kv.Value) / 1000.0);
                // Conditional remaining wait: smooth tail if a file takes longer than average
                double remForThis = elapsedPoll < _ewmaPollSec
                    ? Math.Max(4.0, _ewmaPollSec - elapsedPoll)
                    : Math.Max(8.0, Math.Min(120.0, 0.35 * _ewmaPollSec));
                if (remForThis > tPollActive) tPollActive = remForThis;
            }

            double tPollFutureTail = (activeUploadRemBytes > 0 || expectedFutureUploads >= 0.65)
                ? _ewmaPollSec
                : 0.0;

            // ---- Pipeline makespan ----
            // Disk and network lookups overlap in parallel; upload transfers overlap with lookups;
            // cloud analysis polling forms a parallel tail after the last upload finishes.
            double tPipelineBody = Math.Max(tDisk, tNet + tUploadActive + tUploadFuture);
            double tRaw = Math.Max(tPipelineBody + tPollFutureTail, tPollActive);
            tRaw = Math.Clamp(tRaw, 1.0, TimeSpan.FromDays(99).TotalSeconds);

            // ---- Asymmetric smoothing + smooth countdown between ticks ----
            double dt = Math.Max(0, nowSec - _lastEstimateAtSec);
            _lastEstimateAtSec = nowSec;

            if (_smoothedRemSec < 0)
            {
                _smoothedRemSec = tRaw;
            }
            else
            {
                // First project previous estimate forward by elapsed wall time dt
                double projected = Math.Max(1.0, _smoothedRemSec - dt);
                // Adapt faster when the new estimate is lower (real progress), smoothly when higher
                double alpha = tRaw < projected ? 0.35 : 0.22;
                _smoothedRemSec = (1.0 - alpha) * projected + alpha * tRaw;
            }

            return (rate, TimeSpan.FromSeconds(Math.Max(1.0, Math.Ceiling(_smoothedRemSec))));
        }
    }

    double ComputeNetworkStageSeconds(
        double expectedNetRem,
        long channelsHeldUntilTicks,
        KeyQuotaSnapshot quota,
        bool keylessAvailable,
        bool keylessParked)
    {
        if (expectedNetRem <= 0.01) return 0.0;

        var nowUtc = DateTime.UtcNow;
        double holdSec = channelsHeldUntilTicks > nowUtc.Ticks
            ? (new DateTime(channelsHeldUntilTicks, DateTimeKind.Utc) - nowUtc).TotalSeconds
            : 0.0;

        // Browser-first effective throughput (parallel ephemeral zero-cookie browsers)
        int browserConc = BrowserSessionFactory.DesiredConcurrency();
        double browserRate = (keylessAvailable && !keylessParked)
            ? Math.Max(1, browserConc) / Math.Max(0.8, _ewmaKeylessSec)
            : 0.0;

        if (quota.UsableKeys <= 0 || quota.DailyRemaining <= 0)
        {
            double rate = Math.Max(0.05, browserRate);
            return holdSec + (expectedNetRem / rate);
        }

        // Concurrency-limited API burst rate (assistant + fallback)
        double apiConcRate = Math.Min(_concurrency, Math.Max(1, quota.UsableKeys * 2)) / Math.Max(0.15, _ewmaLookupSec);
        // Sustained per-minute API replenishment rate across all keys with daily room left
        double apiSustainedRate = quota.KeysWithDailyRoom * (AppConstants.RatePerMinute / 60.0);

        // Browser-first architecture: browser cells serve primary lookups while API assists/handles overflow
        if (browserRate > 0)
        {
            double combinedRate = browserRate + Math.Min(apiConcRate, apiSustainedRate) * 0.5;
            return holdSec + (expectedNetRem / Math.Max(0.08, combinedRate));
        }

        // Browser disabled -> pure API path
        if (expectedNetRem <= quota.ImmediateRoom)
            return holdSec + (expectedNetRem / Math.Max(0.1, apiConcRate));

        double burstSec = quota.ImmediateRoom > 0 ? quota.ImmediateRoom / Math.Max(0.1, apiConcRate) : 0.0;
        double afterBurst = Math.Max(0.0, expectedNetRem - quota.ImmediateRoom);

        double resetWaitSec = 0.0;
        if (quota.ImmediateRoom == 0 && quota.SoonestResetUtc is { } reset && reset > nowUtc)
            resetWaitSec = (reset - nowUtc).TotalSeconds;

        double paceSec = afterBurst / Math.Max(0.05, Math.Min(apiConcRate, apiSustainedRate));
        return holdSec + resetWaitSec + burstSec + paceSec;
    }
}

/// <summary>Point-in-time snapshot of API key quota availability for ETA and API load modeling.</summary>
internal readonly record struct KeyQuotaSnapshot(
    int UsableKeys,
    int KeysWithDailyRoom,
    long ImmediateRoom,
    long MinuteAllowed,
    long DailyRemaining,
    long DailyAllowed,
    DateTime? SoonestResetUtc);
