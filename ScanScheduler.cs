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

    public ScanScheduler(KeyRotator rotator, VtApiClient api, HashCache cache)
    {
        _rotator = rotator;
        _api = api;
        _cache = cache;
    }

    public void Pause() { _pause.Pause(); Log("Scan paused.", LogLevel.Info); }
    public void Resume() { _pause.Resume(); Log("Scan resumed.", LogLevel.Info); }
    public void Cancel() { try { _cts?.Cancel(); } catch { } Log("Scan cancel requested.", LogLevel.Info); }

    public async Task RunAsync(IEnumerable<string> paths, ScanOptions opts, CancellationToken externalCt = default)
    {
        if (IsRunning) { Log("Scan already running; ignoring new request.", LogLevel.Warning); return; }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        var ct = _cts.Token;
        IsRunning = true;
        ResetCounters();
        UiPost(() => Items.Clear());
        try { Started?.Invoke(); } catch { }

        try
        {
            if (Settings.ResumeInterruptedScans) ScanSessionStore.SaveRunning(paths, opts.Recurse, opts.BypassTrust);
            KnownGoodDb.Reload();
            var safe = SelectionEnumerator.ParseExtensions(Settings.SafeExtensions);
            var files = await Task.Run(() => SelectionEnumerator.Expand(paths, safe, opts.Recurse, opts.ApplySafeFilter), ct);

            _total = files.Count;
            var items = files.Select(f => new ScanItem(f)).ToList();
            UiPost(() => { foreach (var it in items) Items.Add(it); });
            ReportProgress();

            if (items.Count == 0)
            {
                Log("Nothing to scan.", LogLevel.Warning);
                return;
            }

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
            ScanSessionStore.Clear(); // normal finish or cancel — only a crash leaves it for resume
            _cache.Flush();
            IsRunning = false;
            try { Finished?.Invoke(); } catch (Exception ex) { Log("Finished handler failed: " + ex.Message, LogLevel.Warning); }
            Log("Scan finished.", LogLevel.Info);
        }
    }

    async Task ProcessAsync(ScanItem item, ScanOptions opts, CancellationToken ct)
    {
        try
        {
            await _pause.WaitWhilePausedAsync(ct);
            SetStatus(item, ScanStatus.Hashing);
            var (md5, sha256) = await HashService.ComputeAsync(item.FilePath, ct);
            UiPost(() => { item.Md5 = md5; item.Sha256 = sha256; });

            // --no-trust (BypassTrust) forces a fresh scan: ignore the local cache too.
            if (opts.UseCache && !opts.BypassTrust)
            {
                var cached = _cache.TryGet(md5, opts.CacheDays);
                if (cached != null)
                {
                    UiPost(() => { item.Report = cached; item.FromCache = true; });
                    Complete(item, cached);
                    return;
                }
            }

            // Keyless, zero-quota skip: user known-good list, then a trusted code signature.
            // A trusted signature means vouched-for provenance, NOT "clean" — so it never
            // counts as clean and never shows the green banner.
            if (opts.SkipTrusted && !opts.BypassTrust)
            {
                if (KnownGoodDb.Contains(md5, sha256)) { TrustSkip(item, "Bilinen temiz (yerel liste)", null); return; }

                var trust = TrustService.Evaluate(item.FilePath);
                if (TrustService.ShouldSkip(trust, Settings.TrustMicrosoftOnly, Settings.TrustPublisherAllowList))
                {
                    TrustSkip(item, trust.Reason, trust.Publisher);
                    return;
                }
            }

            await _pause.WaitWhilePausedAsync(ct);
            SetStatus(item, ScanStatus.LookingUp);

            // Keyless mode: query via the GUI (WebView2), no API key / no quota. Lookup-only.
            bool useKeyless = (Settings.KeylessGuiLookup || !_rotator.HasUsableKeys) && GuiScrapeService.IsRuntimeAvailable;

            VtFileReport? report;
            bool keylessNotFound = false;
            if (useKeyless)
            {
                report = await GuiScrapeService.LookupAsync(sha256, ct);
                keylessNotFound = report == null;
            }
            else
            {
                report = await CallWithRotation(key => _api.GetFileReportAsync(md5, key, ct), ct);
                if (report == null)
                {
                    // Unknown to VT -> upload and analyze (needs a key).
                    await _pause.WaitWhilePausedAsync(ct);
                    SetStatus(item, ScanStatus.Uploading);
                    var progress = new ActionProgress<UploadProgress>(p => UiPost(() =>
                    {
                        item.Progress = (int)Math.Round(p.Percent);
                        item.Detail = $"Yükleniyor… {p.Percent:F0}%  {FormatBytes(p.BytesSent)}/{FormatBytes(p.TotalBytes)}  ({FormatBytes(p.BytesPerSecond)}/s)";
                    }));

                    string analysisId = await CallWithRotation(key => _api.UploadFileAsync(item.FilePath, key, progress, ct), ct);

                    SetStatus(item, ScanStatus.Polling);
                    report = await PollUntilCompleteAsync(analysisId, sha256, item, ct);
                }
            }

            // Cache any real report (clean or not) so re-scans skip VT. Never cache a 404 (report == null).
            if (report != null && opts.UseCache && report.TotalEngines > 0)
                _cache.Put(md5, report);

            if (report == null)
            {
                item.Error = keylessNotFound
                    ? "VT'de yok veya anahtarsız sorgu engellendi (yükleme için API anahtarı gerekir)."
                    : "Analiz zaman aşımına uğradı.";
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
            try { ItemFinished?.Invoke(item); } catch { }
        }
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
                return await call(key);
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
        if (report.Malicious > 0) Bump(ref _malicious);
        else if (report.Suspicious > 0) Bump(ref _suspicious);
        else Bump(ref _clean);
    }

    void TrustSkip(ScanItem item, string reason, string? publisher)
    {
        UiPost(() => { item.SkipReason = reason; item.Publisher = publisher; item.Status = ScanStatus.TrustedSkipped; });
        Bump(ref _signedSkipped);
        Log($"VT skipped (trusted): {item.FileName} — {reason}", LogLevel.Info);
    }

    void DoneOne() { Interlocked.Increment(ref _done); ReportProgress(); }
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
        UiPost(() => { try { ProgressChanged?.Invoke(p); } catch { } });
    }
}
