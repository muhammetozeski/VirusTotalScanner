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

    /// <summary>Verdict the exec-class files that landed in the watched folders while the watcher was off
    /// (app closed, or WatchDownloads just toggled on) — bounded to files modified after <paramref
    /// name="sinceUtc"/> so it's cheap, reusing the full per-file pipeline (HandleAsync).</summary>
    public async Task CatchUpAsync(IEnumerable<string> folders, DateTime sinceUtc)
    {
        foreach (var folder in folders.Where(f => !string.IsNullOrWhiteSpace(f) && Directory.Exists(f)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string[] files;
            try { files = Directory.GetFiles(folder, "*", SearchOption.TopDirectoryOnly); }
            catch (Exception ex) { Log($"Catch-up enumerate failed for {folder}: {ex.Message}", LogLevel.Warning); continue; }
            foreach (var f in files)
            {
                if (!ExecExts.Contains(Path.GetExtension(f))) continue;
                try { if (File.GetLastWriteTimeUtc(f) <= sinceUtc) continue; } catch { continue; }
                await HandleAsync(f);
            }
        }
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
    // Documents/media whose extension a lure file hides BEHIND its real exec extension (invoice.pdf.exe).
    static readonly HashSet<string> LureFronts = new(StringComparer.OrdinalIgnoreCase)
    { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3", ".csv", ".html" };

    /// <summary>The double-extension masquerade: the real extension is exec-class and the name BEFORE it
    /// ends in a document/media extension (invoice.pdf.exe, photo.jpg.scr). Dangerous by naming alone.</summary>
    static bool IsDoubleExtensionLure(string path)
    {
        if (!ExecExts.Contains(Path.GetExtension(path))) return false;
        return LureFronts.Contains(Path.GetExtension(Path.GetFileNameWithoutExtension(path)));
    }

    async Task VerdictOne(string path, string containerPath, string? originNote)
    {
        // A double-extension lure is a threat by its name alone — never silently trust-skip it.
        bool lure = IsDoubleExtensionLure(path);
        var trust = TrustService.Evaluate(path);
        if (!lure && TrustService.ShouldSkip(trust, Settings.TrustMicrosoftOnly, Settings.TrustPublisherAllowList))
        { Interlocked.Increment(ref Cleared); return; }

        var (md5, sha) = await HashService.ComputeAsync(path);
        var report = _cache.TryGet(md5, Settings.HashCacheDays)
            ?? (GuiScrapeService.IsRuntimeAvailable ? await GuiScrapeService.LookupAsync(sha) : null);
        if (report != null && report.TotalEngines > 0) _cache.Put(md5, report, path);

        // Flag if VT says malicious OR the name is a lure (catches brand-new payloads no engine has yet).
        if (report?.IsMalicious == true || lure)
        {
            Interlocked.Increment(ref Flagged);
            string? note = lure ? "çift uzantı tuzağı" + (originNote != null ? " " + originNote : "") : originNote;
            ThreatFound?.Invoke(new ScanItem(containerPath) { Report = report, Md5 = md5, Sha256 = sha, OriginNote = note });
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
