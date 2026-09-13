using System.Collections.Concurrent;
using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>
/// Remembers "this exact path, this size, this write time had these hashes", so a repeat scan does
/// not read the whole disk again just to arrive at the same digests.
///
/// Hashing is the one unavoidable cost of the local stage: the verdict cache is keyed by hash, so
/// every file has to be read end-to-end before the cache can even be consulted. On a 340,000-file
/// sweep that is hundreds of gigabytes, and it is paid again on every restart, every resume and every
/// re-scan — while the answer is almost always identical.
///
/// The identity used is path + length + last-write-time. That is the same bet every backup tool
/// makes; a file rewritten with byte-identical length AND an unchanged timestamp would be missed, so
/// the whole thing can be switched off, and any scan that bypasses trust (a deliberate re-check)
/// ignores it and hashes for real.
/// </summary>
internal static class FingerprintCache
{
    sealed class Entry
    {
        public long Size { get; set; }
        public long WriteUtcTicks { get; set; }
        public string Md5 { get; set; } = "";
        public string Sha256 { get; set; } = "";
    }

    static readonly ConcurrentDictionary<string, Entry> _map = new(StringComparer.OrdinalIgnoreCase);
    static readonly object _saveLock = new();
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };
    static DateTime _lastSaveUtc = DateTime.MinValue;
    static volatile bool _dirty;
    static long _hits, _misses;

    static string FilePath => Path.Combine(ConfigPathResolver.DataFolder, "fingerprints.json");

    public static int Count => _map.Count;
    public static long Hits => Interlocked.Read(ref _hits);
    public static long Misses => Interlocked.Read(ref _misses);

    static Task _loaded = Task.CompletedTask;

    /// <summary>
    /// Starts reading the store in the background and returns at once. The file holds a quarter of a
    /// million entries (78 MB) and was read on the start-up thread as one string — over a second before
    /// the window could appear, and a 150 MB allocation. Until the read finishes a lookup simply misses
    /// and the file is hashed for real; nothing is written back until it has finished, so a save can
    /// never replace the store with the few entries added in the meantime.
    /// </summary>
    public static void Load() => _loaded = Task.Run(LoadCore);

    static void LoadCore()
    {
        using var op = OpLog.Begin("Fingerprint cache load", FilePath);
        try
        {
            if (!File.Exists(FilePath)) { op.Note("no file yet"); return; }
            Dictionary<string, Entry>? map;
            using (var fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16))
                map = JsonSerializer.Deserialize<Dictionary<string, Entry>>(fs, JsonOpts);
            if (map != null)
                foreach (var (k, v) in map)
                    if (!string.IsNullOrEmpty(v.Md5)) _map.TryAdd(k, v); // an entry hashed while loading is newer
            op.Ok($"{_map.Count} entr(ies)");
        }
        catch (Exception ex)
        {
            Log("Fingerprint cache load failed: " + ex.Message, LogLevel.Warning);
            AtomicFile.BackupCorrupt(FilePath);
            op.Fail(ex.Message);
        }
    }

    /// <summary>The hashes for this file if it has not changed since they were computed.</summary>
    public static (string Md5, string Sha256)? TryGet(string path, FileInfo? info = null)
    {
        try
        {
            if (!_map.TryGetValue(path, out var e)) { Interlocked.Increment(ref _misses); return null; }
            info ??= new FileInfo(path);
            if (!info.Exists || info.Length != e.Size || info.LastWriteTimeUtc.Ticks != e.WriteUtcTicks)
            {
                Interlocked.Increment(ref _misses);
                return null;
            }
            Interlocked.Increment(ref _hits);
            return (e.Md5, e.Sha256);
        }
        catch (Exception ex)
        {
            Log($"Fingerprint read failed for '{path}': {ex.Message}", LogLevel.Debug);
            Interlocked.Increment(ref _misses);
            return null;
        }
    }

    public static void Put(string path, string md5, string sha256)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return;
            _map[path] = new Entry
            {
                Size = info.Length,
                WriteUtcTicks = info.LastWriteTimeUtc.Ticks,
                Md5 = md5,
                Sha256 = sha256,
            };
            _dirty = true;
            MaybeSave();
        }
        catch (Exception ex) { Log($"Fingerprint write failed for '{path}': {ex.Message}", LogLevel.Debug); }
    }

    static int _saveRunning;

    /// <summary>
    /// Saves in the background when the last save is 30 seconds old. The save used to run right here, on
    /// the scan worker that happened to add an entry, and every other caller queued on the lock behind
    /// it: 850 ms of a stopped scan every 30 seconds with the store at 250,000 entries.
    /// </summary>
    public static void MaybeSave()
    {
        if (!_dirty || !_loaded.IsCompleted || DateTime.UtcNow - _lastSaveUtc < TimeSpan.FromSeconds(30)) return;
        if (Interlocked.Exchange(ref _saveRunning, 1) == 1) return;
        _ = Task.Run(() =>
        {
            try { lock (_saveLock) { if (_dirty) WriteUnderLock(); } }
            catch (Exception ex) { Log("Fingerprint cache background save failed: " + ex.Message, LogLevel.Warning); }
            finally { Interlocked.Exchange(ref _saveRunning, 0); }
        });
    }

    public static void Flush()
    {
        try { _loaded.Wait(); } // the store on disk is only replaced by a map that holds all of it
        catch (Exception ex) { Log("Fingerprint cache load had failed before the flush: " + ex.Message, LogLevel.Warning); }
        lock (_saveLock)
        {
            if (!_dirty) return;
            WriteUnderLock();
        }
    }

    static void WriteUnderLock()
    {
        using var op = OpLog.Begin("Fingerprint cache save", $"{_map.Count} entr(ies)");
        try
        {
            Directory.CreateDirectory(ConfigPathResolver.DataFolder);
            // Cleared before the write, not after: an entry added while the file is being written marks
            // the store dirty again instead of being forgotten by the next check.
            _dirty = false;
            _lastSaveUtc = DateTime.UtcNow;
            AtomicFile.Write(FilePath, fs => JsonSerializer.Serialize(fs, _map, JsonOpts));
            op.Ok($"hits={Hits} misses={Misses}");
        }
        catch (Exception ex)
        {
            _dirty = true; // not on disk; the next save tries again
            Log("Fingerprint cache save failed: " + ex.Message, LogLevel.Warning);
            op.Fail(ex.Message);
        }
    }

    /// <summary>Drops entries whose file is gone, so the map does not grow forever across scans.</summary>
    public static int PruneMissing()
    {
        using var op = OpLog.Begin("Fingerprint cache prune", $"{_map.Count} entr(ies)");
        int removed = 0;
        try
        {
            _loaded.Wait(); // pruning a half-loaded map would miss everything still being read
            foreach (var path in _map.Keys.ToList())
            {
                try { if (!File.Exists(path) && _map.TryRemove(path, out _)) removed++; }
                catch (Exception ex) { Log($"Fingerprint prune check failed for '{path}': {ex.Message}", LogLevel.Debug); }
            }
            if (removed > 0) { _dirty = true; Flush(); }
            op.Ok($"{removed} removed");
        }
        catch (Exception ex) { Log("Fingerprint prune failed: " + ex.Message, LogLevel.Warning); op.Fail(ex.Message); }
        return removed;
    }
}
