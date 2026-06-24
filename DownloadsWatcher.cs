namespace VirusTotalScanner;

/// <summary>
/// Event-driven proactive guard: a FileSystemWatcher on chosen folders (default Downloads + Desktop)
/// that scans new executable-class files the moment they land — before the user double-clicks. It
/// reuses the normal pipeline order (trust pre-filter clears signed files silently, cache covers the
/// rest, only a genuine unknown hits the keyless GUI engine), so steady state spends zero quota.
/// A flagged file raises <see cref="ThreatFound"/> (the form shows a tray toast).
/// </summary>
internal sealed class DownloadsWatcher : IDisposable
{
    static readonly HashSet<string> ExecExts = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".dll", ".com", ".lnk", ".zip", ".7z", ".rar", ".iso" };

    readonly List<FileSystemWatcher> _watchers = [];
    readonly HashSet<string> _inflight = new(StringComparer.OrdinalIgnoreCase);
    readonly object _lock = new();
    readonly HashCache _cache;

    public event Action<ScanItem>? ThreatFound;
    public int Seen, Cleared, Flagged;

    public DownloadsWatcher(HashCache cache) => _cache = cache;

    public static List<string> DefaultFolders() =>
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
    ];

    public bool IsRunning => _watchers.Count > 0;

    public void Start(IEnumerable<string> folders)
    {
        Stop();
        foreach (var f in folders.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(f)) continue;
            try
            {
                var w = new FileSystemWatcher(f)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size,
                    EnableRaisingEvents = true,
                };
                w.Created += (_, e) => _ = HandleAsync(e.FullPath);
                w.Renamed += (_, e) => _ = HandleAsync(e.FullPath);
                _watchers.Add(w);
            }
            catch (Exception ex) { Log($"Downloads watch start failed for {f}: {ex.Message}", LogLevel.Warning); }
        }
        Log($"Downloads watch active on {_watchers.Count} folder(s).", LogLevel.Info);
    }

    public void Stop()
    {
        foreach (var w in _watchers) { try { w.Dispose(); } catch { } }
        _watchers.Clear();
    }

    async Task HandleAsync(string path)
    {
        if (!ExecExts.Contains(Path.GetExtension(path))) return;
        lock (_lock) { if (!_inflight.Add(path)) return; }
        try
        {
            if (!await WaitStableAsync(path)) return;
            Interlocked.Increment(ref Seen);

            // Most download-borne malware arrives zipped: expand archives and scan each member through the
            // same pipeline, instead of hashing the container blob (whose hash never matches a VT report,
            // so a packed payload was silently cleared).
            if (ArchiveExpander.IsArchive(path) && ArchiveExpander.IsExpandable(path))
            {
                string? tempDir = null;
                try
                {
                    var members = ArchiveExpander.ExpandToTemp(path, out tempDir);
                    foreach (var m in members)
                        await VerdictOne(m, containerPath: path, originNote: "› " + Path.GetFileName(m));
                }
                finally { if (tempDir != null) ArchiveExpander.CleanupTemp(tempDir); }
                return;
            }

            await VerdictOne(path, containerPath: path, originNote: null);
        }
        catch (Exception ex) { Log($"Downloads watch scan failed for {path}: {ex.Message}", LogLevel.Warning); }
        finally { lock (_lock) { _inflight.Remove(path); } }
    }

    /// <summary>Verdict for one file via the cheap-signal order (signed→cache→keyless). On a hit, the
    /// threat is raised against <paramref name="containerPath"/> — the file the user actually downloaded
    /// (so quarantine targets the .zip), labelled with the offending inner member via originNote.</summary>
    async Task VerdictOne(string path, string containerPath, string? originNote)
    {
        var trust = TrustService.Evaluate(path);
        if (TrustService.ShouldSkip(trust, Settings.TrustMicrosoftOnly, Settings.TrustPublisherAllowList))
        { Interlocked.Increment(ref Cleared); return; }

        var (md5, sha) = await HashService.ComputeAsync(path);
        var report = _cache.TryGet(md5, Settings.HashCacheDays)
            ?? (GuiScrapeService.IsRuntimeAvailable ? await GuiScrapeService.LookupAsync(sha) : null);
        if (report != null && report.TotalEngines > 0) _cache.Put(md5, report, path);

        if (report?.IsMalicious == true)
        {
            Interlocked.Increment(ref Flagged);
            ThreatFound?.Invoke(new ScanItem(containerPath) { Report = report, Md5 = md5, Sha256 = sha, OriginNote = originNote });
        }
        else Interlocked.Increment(ref Cleared);
    }

    /// <summary>Waits until the file stops growing and is readable (a download has finished), or gives up.</summary>
    static async Task<bool> WaitStableAsync(string path)
    {
        long last = -1;
        for (int i = 0; i < 24; i++) // up to ~12s
        {
            try
            {
                if (!File.Exists(path)) return false;
                long len = new FileInfo(path).Length;
                using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) { }
                if (len == last && len > 0) return true;
                last = len;
            }
            catch { /* still being written / locked */ }
            await Task.Delay(500);
        }
        return last > 0;
    }

    public void Dispose() => Stop();
}
