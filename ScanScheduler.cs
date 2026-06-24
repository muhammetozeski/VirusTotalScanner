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
    SemaphoreSlim? _uploadGate; // limits how many files upload to VT in parallel (set per run)
    ConcurrentDictionary<string, SemaphoreSlim>? _md5Gates; // per-run: one lookup per identical content

    /// <summary>Marshals an action to the UI thread (set by the GUI; direct call by default/CLI).</summary>
    public Action<Action> UiPost { get; set; } = a => a();

    public BindingList<ScanItem> Items { get; } = [];

    public event Action<OverallProgress>? ProgressChanged;
    public event Action<ScanItem>? ItemFinished;
    public event Action? Started;
    public event Action? Finished;

    public bool IsRunning { get; private set; }
    public bool IsPaused => _pause.IsPaused;

    // aggregate counters
    int _total, _done, _malicious, _suspicious, _clean, _failed, _skipped, _signedSkipped;

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

    public async Task RunAsync(IEnumerable<string> paths, ScanOptions opts, CancellationToken externalCt = default)
    {
        if (IsRunning) { Log("Scan already running; ignoring new request.", LogLevel.Warning); return; }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        var ct = _cts.Token;
        IsRunning = true;
        ResetCounters();
        _stopwatch.Restart();
        lock (_rateLock) _recent.Clear();
        UiPost(() => Items.Clear());
        try { Started?.Invoke(); } catch (Exception ex) { Log("Started handler failed: " + ex.Message, LogLevel.Warning); }

        var archiveTemps = new List<string>(); // temp folders from archive expansion, cleaned in finally
        try
        {
            if (Settings.ResumeInterruptedScans) ScanSessionStore.SaveRunning(paths, opts.Recurse, opts.BypassTrust);
            KnownGoodDb.Reload();
            var safe = SelectionEnumerator.ParseExtensions(Settings.SafeExtensions);
            var oversize = new List<string>();
            var files = await Task.Run(() => SelectionEnumerator.Expand(
                paths, safe, opts.Recurse, opts.ApplySafeFilter, opts.MaxFileSizeBytes, oversize), ct);

            // Archive expansion: swap each ZIP-family archive for its extracted members so each member
            // is hashed and looked up on its own (no upload). Archives we cannot open stay as-is.
            if (opts.ExpandArchives)
                files = await Task.Run(() => ExpandArchives(files, archiveTemps), ct);

            // Risk-weighted ordering: scan the likeliest-malicious files first (cheap local signals).
            if (Settings.RiskWeightedOrdering && files.Count > 1)
                files = await Task.Run(() => files.OrderByDescending(RiskScorer.Score).ToList(), ct);

            _total = files.Count;
            var items = files.Select(f => new ScanItem(f)).ToList();
            UiPost(() => { foreach (var it in items) Items.Add(it); });

            // Ledger: show each size-skipped file as a row so the user sees what was excluded and why.
            if (oversize.Count > 0)
            {
                int capMb = (int)(opts.MaxFileSizeBytes / (1024 * 1024));
                var skipped = oversize.Select(f => new ScanItem(f) { Status = ScanStatus.Skipped, SkipReason = $"çok büyük (>{capMb} MB)" }).ToList();
                UiPost(() => { foreach (var it in skipped) Items.Add(it); });
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
            _md5Gates = new ConcurrentDictionary<string, SemaphoreSlim>(StringComparer.OrdinalIgnoreCase);
            var po = new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, opts.MaxConcurrency), CancellationToken = ct };
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
            IsRunning = false;
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
                if (trust.Trusted) ProductSignerRegistry.RecordTrusted(item.FilePath, trust.Publisher);
                if (TrustService.ShouldSkip(trust, Settings.TrustMicrosoftOnly, Settings.TrustPublisherAllowList))
                {
                    TrustSkip(item, trust.Reason, trust.Publisher);
                    return;
                }
            }

            SetStatus(item, ScanStatus.Hashing);
            var (md5, sha256) = await HashService.ComputeAsync(item.FilePath, ct);
            UiPost(() => { item.Md5 = md5; item.Sha256 = sha256; });

            // --no-trust (BypassTrust) forces a fresh scan: ignore the local cache too.
            if (opts.UseCache && !opts.BypassTrust)
            {
                var cached = _cache.TryGet(md5, opts.CacheDays, opts.ThreatCacheDays);
                if (cached != null)
                {
                    UiPost(() => { item.Report = cached; item.FromCache = true; });
                    Complete(item, cached);
                    return;
                }
            }

            // Known-good list check needs the hash, so it stays after hashing.
            if (opts.SkipTrusted && !opts.BypassTrust && KnownGoodDb.Contains(md5, sha256))
            {
                TrustSkip(item, "Bilinen temiz (yerel liste)", null);
                return;
            }

            // In-scan dedup: serialize lookups of identical content within one run so duplicate
            // files (node_modules, bundled runtimes, repeated installers) share a single VT/GUI
            // lookup. The first item caches the report; the rest get the cache hit here.
            var dedupGate = _md5Gates!.GetOrAdd(md5, _ => new SemaphoreSlim(1, 1));
            await dedupGate.WaitAsync(ct);
            VtFileReport? report;
            try
            {
                var dup = (opts.UseCache && !opts.BypassTrust) ? _cache.TryGet(md5, opts.CacheDays, opts.ThreatCacheDays) : null;
                if (dup != null) { UiPost(() => item.FromCache = true); report = dup; }
                else report = await DoLookupAsync(item, md5, sha256, opts, ct);
            }
            finally { dedupGate.Release(); }

            if (report == null)
            {
                item.Error = "VT'de bulunamadı veya sorgu sonuç vermedi (yükleme için API anahtarı gerekir).";
                SetStatus(item, ScanStatus.Failed);
                Bump(ref _failed);
            }
            else
            {
                UiPost(() => item.Report = report);
                Complete(item, report);
            }
        }
        catch (OperationCanceledException)
        {
            SetStatus(item, ScanStatus.Cancelled);
        }
        catch (Exception ex)
        {
            UiPost(() => item.Error = ex.Message);
            SetStatus(item, ScanStatus.Failed);
            Bump(ref _failed);
            Log($"Scan failed for {item.FileName}: {ex}", LogLevel.Error);
        }
        finally
        {
            DoneOne();
            try { ItemFinished?.Invoke(item); } catch (Exception ex) { Log("ItemFinished handler failed: " + ex.Message, LogLevel.Warning); }
        }
    }

    /// <summary>The resilient lookup chain for one file (GUI first, then API + upload, GUI last
    /// resort), caching the result. Held under a per-md5 gate so duplicates in a run share it.</summary>
    async Task<VtFileReport?> DoLookupAsync(ScanItem item, string md5, string sha256, ScanOptions opts, CancellationToken ct)
    {
        await _pause.WaitWhilePausedAsync(ct);
        SetStatus(item, ScanStatus.LookingUp);

        bool preferGui = Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable;
        VtFileReport? report = null;

        if (preferGui)
            report = await GuiScrapeService.LookupAsync(sha256, ct).WaitAsync(ct);

        if (report == null && _rotator.HasUsableKeys)
        {
            report = await CallWithRotation(key => _api.GetFileReportAsync(md5, key, ct), ct);
            if (report == null)
            {
                await _pause.WaitWhilePausedAsync(ct);
                SetStatus(item, ScanStatus.Uploading);
                var progress = new ActionProgress<UploadProgress>(p => UiPost(() =>
                {
                    item.Progress = (int)Math.Round(p.Percent);
                    item.Detail = $"Yükleniyor… {p.Percent:F0}%  {FormatBytes(p.BytesSent)}/{FormatBytes(p.TotalBytes)}  ({FormatBytes(p.BytesPerSecond)}/s)";
                }));
                await _uploadGate!.WaitAsync(ct);
                string analysisId;
                try { analysisId = await CallWithRotation(key => _api.UploadFileAsync(item.FilePath, key, progress, ct), ct); }
                finally { _uploadGate.Release(); }
                SetStatus(item, ScanStatus.Polling);
                report = await PollUntilCompleteAsync(analysisId, sha256, item, ct);
            }
        }

        // Last resort: API was off/exhausted -> try the GUI engine once.
        if (report == null && !preferGui && GuiScrapeService.IsRuntimeAvailable)
            report = await GuiScrapeService.LookupAsync(sha256, ct).WaitAsync(ct);

        if (report != null && opts.UseCache && report.TotalEngines > 0)
            _cache.Put(md5, report, item.FilePath);

        return report;
    }

    async Task<VtFileReport?> PollUntilCompleteAsync(string analysisId, string sha256, ScanItem item, CancellationToken ct)
    {
        const int maxPolls = 60; // ~ up to 15 min at 15s
        for (int i = 0; i < maxPolls; i++)
        {
            ct.ThrowIfCancellationRequested();
            await _pause.WaitWhilePausedAsync(ct);
            await Task.Delay(TimeSpan.FromSeconds(15), ct);

            var info = await CallWithRotation(key => _api.GetAnalysisAsync(analysisId, key, ct), ct);
            UiPost(() => item.Detail = $"Analiz bekleniyor… (durum: {info.Status}, {i + 1}. yoklama)");
            if (info.IsCompleted)
                return await CallWithRotation(key => _api.GetFileReportAsync(sha256, key, ct), ct);
        }
        return null;
    }

    /// <summary>Runs a VT call, rotating keys on 429/auth failures and waiting when exhausted.</summary>
    async Task<T> CallWithRotation<T>(Func<string, Task<T>> call, CancellationToken ct)
    {
        int maxAttempts = Math.Max(2, _rotator.UsableKeyCount * 2 + 3);
        VtApiException? last = null;
        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            string key = await _rotator.AcquireAsync(ct);
            try
            {
                // WaitAsync guarantees cancellation wins on time even if a slow HTTP path honors the token late (principle 43).
                return await call(key).WaitAsync(ct);
            }
            catch (VtRateLimitException ex) { last = ex; _rotator.ReportRateLimited(key, ex.RetryAfter); }
            catch (VtAuthException ex) { last = ex; _rotator.ReportAuthError(key); }
        }
        throw last ?? new VtApiException("All keys failed for the request.");
    }

    // ---- progress bookkeeping ----

    void SetStatus(ScanItem item, ScanStatus status) => UiPost(() => item.Status = status);

    void Complete(ScanItem item, VtFileReport report)
    {
        SetStatus(item, ScanStatus.Completed);
        // Bucket by the user's verdict categories: highest band -> malicious, any other threat
        // band -> suspicious, else clean.
        if (report.TotalEngines > 0 && report.IsMalicious)
        {
            bool topBand = ReferenceEquals(VerdictCategories.Classify(report.DetectionCount), VerdictCategories.All[^1]);
            if (topBand) Bump(ref _malicious); else Bump(ref _suspicious);
        }
        else Bump(ref _clean);
    }

    void TrustSkip(ScanItem item, string reason, string? publisher)
    {
        UiPost(() => { item.SkipReason = reason; item.Publisher = publisher; item.Status = ScanStatus.TrustedSkipped; });
        Bump(ref _signedSkipped);
        Log($"VT skipped (trusted): {item.FileName} — {reason}", LogLevel.Info);
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
    void Bump(ref int counter) { Interlocked.Increment(ref counter); }

    void ResetCounters() { _total = _done = _malicious = _suspicious = _clean = _failed = _skipped = _signedSkipped = 0; }

    void ReportProgress()
    {
        var p = new OverallProgress
        {
            Total = _total,
            Done = _done,
            Malicious = _malicious,
            Suspicious = _suspicious,
            Clean = _clean,
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
