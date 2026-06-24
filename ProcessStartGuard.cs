using System.Management;

namespace VirusTotalScanner;

/// <summary>
/// Real-time process-launch guard: subscribes to the WMI Win32_ProcessStartTrace event and runs each
/// newly-launched executable through the same cheap-signal pipeline the download watcher uses (trust
/// pre-filter → cache → keyless GUI for a genuine unknown). A malicious hit raises <see cref="ThreatFound"/>
/// (the form wires it into auto-quarantine + a toast). Off by default; needs admin for the trace, so it
/// degrades gracefully (logs + stays off) when not elevated. Steady state spends zero quota.
/// </summary>
internal sealed class ProcessStartGuard : IDisposable
{
    readonly HashCache _cache;
    readonly HashSet<string> _inflight = new(StringComparer.OrdinalIgnoreCase);
    readonly object _lock = new();
    ManagementEventWatcher? _watcher;

    public event Action<ScanItem>? ThreatFound;
    public bool IsRunning => _watcher != null;

    public ProcessStartGuard(HashCache cache) => _cache = cache;

    /// <summary>Start watching. Returns false (and logs) if not elevated or WMI is unavailable.</summary>
    public bool Start()
    {
        Stop();
        if (!AdminHelper.IsRunningAsAdmin())
        {
            Log("Process-start guard needs admin rights for the WMI trace; not started.", LogLevel.Warning);
            return false;
        }
        try
        {
            _watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            _watcher.EventArrived += OnProcessStarted;
            _watcher.Start();
            Log("Process-start guard active.", LogLevel.Info);
            return true;
        }
        catch (Exception ex)
        {
            Log("Process-start guard failed to start: " + ex.Message, LogLevel.Warning);
            _watcher = null;
            return false;
        }
    }

    public void Stop()
    {
        try { _watcher?.Stop(); _watcher?.Dispose(); } catch { }
        _watcher = null;
    }

    void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            int pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
            if (pid <= 0) return;
            string? path = null;
            try { using var p = System.Diagnostics.Process.GetProcessById(pid); path = p.MainModule?.FileName; }
            catch { /* short-lived / protected / access-denied — nothing we can check */ }
            if (!string.IsNullOrEmpty(path) && File.Exists(path)) _ = VerdictAsync(path);
        }
        catch (Exception ex) { Log("Process-start handler failed: " + ex.Message, LogLevel.Warning); }
    }

    async Task VerdictAsync(string path)
    {
        lock (_lock) { if (!_inflight.Add(path)) return; }
        try
        {
            var trust = TrustService.Evaluate(path);
            if (TrustService.ShouldSkip(trust, Settings.TrustMicrosoftOnly, Settings.TrustPublisherAllowList)) return;

            var (md5, sha) = await HashService.ComputeAsync(path);
            var report = _cache.TryGet(md5, Settings.HashCacheDays)
                ?? (GuiScrapeService.IsRuntimeAvailable ? await GuiScrapeService.LookupAsync(sha) : null);
            if (report != null && report.TotalEngines > 0) _cache.Put(md5, report, path);

            if (report?.IsMalicious == true)
                ThreatFound?.Invoke(new ScanItem(path) { Report = report, Md5 = md5, Sha256 = sha, OriginNote = "çalıştırılırken yakalandı" });
        }
        catch (Exception ex) { Log("Process-start verdict failed for " + path + ": " + ex.Message, LogLevel.Warning); }
        finally { lock (_lock) { _inflight.Remove(path); } }
    }

    public void Dispose() => Stop();
}
