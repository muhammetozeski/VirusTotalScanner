namespace VirusTotalScanner;

/// <summary>
/// Timed copies of the hash cache into a folder the user picks. The cache is the most expensive
/// thing this app owns — every entry cost VirusTotal quota that cannot be bought back — so losing
/// cache.json to a disk error, a bad shutdown or a wrong click is the one failure worth insuring
/// against. Backups are timestamped and never overwrite each other; only the oldest are trimmed.
/// </summary>
internal static class CacheBackupService
{
    const string Prefix = "cache-";
    const string Suffix = ".json";

    static System.Threading.Timer? _timer;
    static readonly object _lock = new();
    static DateTime _lastBackupUtc = DateTime.MinValue;

    /// <summary>Path of the most recent successful backup, for the settings card.</summary>
    public static string? LastBackupPath { get; private set; }
    public static DateTime? LastBackupLocal { get; private set; }

    /// <summary>(Re)arms the timer from the current settings. Safe to call whenever they change.</summary>
    public static void Reschedule()
    {
        lock (_lock)
        {
            try { _timer?.Dispose(); } catch (Exception ex) { Log("Cache backup timer dispose failed: " + ex.Message, LogLevel.Warning); }
            _timer = null;

            int hours = Settings.CacheBackupHours.Value;
            string folder = (Settings.CacheBackupFolder.Value ?? "").Trim();
            if (hours <= 0 || folder.Length == 0)
            {
                Log("Cache backup timer off (no folder or interval 0).", LogLevel.Info);
                return;
            }

            var period = TimeSpan.FromHours(Math.Min(hours, 24 * 30));
            try
            {
                // First run soon after start so a machine that is only on for an hour a day still gets one.
                _timer = new System.Threading.Timer(_ => RunTimed(), null, TimeSpan.FromMinutes(2), period);
                Log($"Cache backup scheduled every {hours}h into {folder}.", LogLevel.Info);
            }
            catch (Exception ex) { Log("Cache backup schedule failed: " + ex, LogLevel.Error); }
        }
    }

    static void RunTimed()
    {
        try
        {
            // Don't stack backups if the timer fires while a previous one is still fresh.
            lock (_lock)
            {
                int hours = Math.Max(1, Settings.CacheBackupHours.Value);
                if (DateTime.UtcNow - _lastBackupUtc < TimeSpan.FromHours(hours) - TimeSpan.FromMinutes(5)) return;
            }
            if (BackupNow(out string path, out string err))
                UiStatusHub.Report(Strings.StatusSourceCacheBackup, string.Format(Strings.CacheBackupDoneFormat, path));
            else
                UiStatusHub.Report(Strings.StatusSourceCacheBackup, string.Format(Strings.CacheBackupFailedFormat, err), StatusSeverity.Warning);
        }
        catch (Exception ex) { Log("Timed cache backup failed: " + ex, LogLevel.Error); }
    }

    /// <summary>Writes one timestamped copy now. Returns false with a reason the user can act on.</summary>
    public static bool BackupNow(out string writtenPath, out string error)
    {
        writtenPath = "";
        error = "";
        string folder = (Settings.CacheBackupFolder.Value ?? "").Trim();
        if (folder.Length == 0) { error = Strings.CacheBackupNoFolder; return false; }

        try
        {
            // Flush first: an in-memory-only entry is exactly the one worth keeping.
            try { AppServices.Cache.Flush(); }
            catch (Exception ex) { Log("Cache flush before backup failed: " + ex.Message, LogLevel.Warning); }

            string source = ConfigPathResolver.HashCachePath;
            if (!File.Exists(source)) { error = string.Format(Strings.CacheBackupNoSourceFormat, source); return false; }

            Directory.CreateDirectory(folder);
            string dest = Path.Combine(folder, Prefix + DateTime.Now.ToString("yyyyMMdd-HHmmss") + Suffix);
            File.Copy(source, dest, overwrite: false);

            writtenPath = dest;
            LastBackupPath = dest;
            LastBackupLocal = DateTime.Now;
            lock (_lock) _lastBackupUtc = DateTime.UtcNow;
            Log($"Hash cache backed up to {dest} ({new FileInfo(dest).Length} bytes, {AppServices.Cache.Count} entries).", LogLevel.Info);

            Prune(folder);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            Log("Cache backup failed: " + ex, LogLevel.Error);
            // Last-ditch: try the app's own data folder so the copy exists SOMEWHERE.
            try
            {
                string fallbackDir = Path.Combine(ConfigPathResolver.DataFolder, "cache-backups");
                Directory.CreateDirectory(fallbackDir);
                string fallback = Path.Combine(fallbackDir, Prefix + DateTime.Now.ToString("yyyyMMdd-HHmmss") + Suffix);
                File.Copy(ConfigPathResolver.HashCachePath, fallback, overwrite: false);
                writtenPath = fallback;
                LastBackupPath = fallback;
                LastBackupLocal = DateTime.Now;
                error = string.Format(Strings.CacheBackupFellBackFormat, ex.Message, fallback);
                Log("Cache backup fell back to " + fallback, LogLevel.Warning);
                return true;
            }
            catch (Exception inner) { Log("Fallback cache backup ALSO failed: " + inner, LogLevel.Error); }
            return false;
        }
        finally
        {
            Log("Cache backup attempt finished for folder: " + folder, LogLevel.Debug);
        }
    }

    static void Prune(string folder)
    {
        try
        {
            int keep = Settings.CacheBackupKeep.Value;
            if (keep <= 0) return;
            var files = new DirectoryInfo(folder).GetFiles(Prefix + "*" + Suffix)
                .OrderByDescending(f => f.LastWriteTimeUtc).ToList();
            for (int i = keep; i < files.Count; i++)
            {
                try { files[i].Delete(); Log("Old cache backup removed: " + files[i].Name, LogLevel.Info); }
                catch (Exception ex) { Log($"Old cache backup '{files[i].Name}' could not be removed: {ex.Message}", LogLevel.Warning); }
            }
        }
        catch (Exception ex) { Log("Cache backup prune failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Existing backups in the configured folder, newest first (for the settings card).</summary>
    public static List<FileInfo> Existing()
    {
        try
        {
            string folder = (Settings.CacheBackupFolder.Value ?? "").Trim();
            if (folder.Length == 0 || !Directory.Exists(folder)) return [];
            return new DirectoryInfo(folder).GetFiles(Prefix + "*" + Suffix)
                .OrderByDescending(f => f.LastWriteTimeUtc).ToList();
        }
        catch (Exception ex) { Log("Cache backup listing failed: " + ex.Message, LogLevel.Warning); return []; }
    }

    /// <summary>Replaces the live cache with a backup file (after copying the current one aside first,
    /// so a wrong restore is itself undoable).</summary>
    public static bool Restore(string backupPath, out string error)
    {
        error = "";
        try
        {
            if (!File.Exists(backupPath)) { error = string.Format(Strings.CacheBackupNoSourceFormat, backupPath); return false; }

            string live = ConfigPathResolver.HashCachePath;
            if (File.Exists(live))
            {
                string aside = live + ".before-restore-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
                try { File.Copy(live, aside, overwrite: false); Log("Current cache kept at " + aside, LogLevel.Info); }
                catch (Exception ex) { Log("Pre-restore copy failed: " + ex.Message, LogLevel.Warning); }
            }

            File.Copy(backupPath, live, overwrite: true);
            AppServices.Cache.Load();
            Log($"Hash cache restored from {backupPath}; {AppServices.Cache.Count} entries in memory.", LogLevel.Info);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            Log("Cache restore failed: " + ex, LogLevel.Error);
            return false;
        }
    }
}
