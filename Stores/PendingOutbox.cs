using System.Text.Json;

namespace VirusTotalScanner;

internal sealed class PendingEntry
{
    public string Path { get; set; } = "";
    public DateTime AddedUtc { get; set; }
}

/// <summary>
/// Offline self-heal: files whose VT lookup couldn't complete because the machine was offline are
/// remembered here (pending.json) and re-scanned automatically when connectivity returns (or at
/// startup). Distinguished from a genuine "not found on VT" by checking network availability at the
/// time of failure, so 404s don't pile up forever. Thread-safe; best-effort.
/// </summary>
internal static class PendingOutbox
{
    static readonly string FilePath = System.IO.Path.Combine(ConfigPathResolver.DataFolder, "pending.json");
    const int MaxEntries = 2000;
    static readonly object Lock = new();
    static List<PendingEntry>? _entries;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static event Action? Changed;

    static List<PendingEntry> Entries { get { lock (Lock) { return _entries ??= Load(); } } }

    public static int Count { get { lock (Lock) { return Entries.Count; } } }
    public static IReadOnlyList<string> Paths() { lock (Lock) { return Entries.Select(e => e.Path).ToList(); } }

    public static void Add(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        lock (Lock)
        {
            if (Entries.Any(e => string.Equals(e.Path, path, StringComparison.OrdinalIgnoreCase))) return;
            Entries.Add(new PendingEntry { Path = path, AddedUtc = DateTime.UtcNow });
            if (Entries.Count > MaxEntries) Entries.RemoveRange(0, Entries.Count - MaxEntries);
            _dirty = true;
            MaybeSave();
        }
        Changed?.Invoke();
    }

    public static void Remove(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        lock (Lock)
        {
            if (Entries.RemoveAll(e => string.Equals(e.Path, path, StringComparison.OrdinalIgnoreCase)) == 0) return;
            _dirty = true;
            MaybeSave();
        }
        Changed?.Invoke();
    }

    // A scan with the keys spent adds every file it could not ask about, and each add rewrote the whole
    // file — up to 2,000 indented entries, half a megabyte, once per file, from every network worker at
    // once. Adds and removes now mark the store dirty and it is written at most every five seconds, plus
    // once when a scan ends and when the app exits.
    static bool _dirty;          // guarded by Lock
    static DateTime _lastSaveUtc; // guarded by Lock

    static void MaybeSave() // caller holds Lock
    {
        if (_dirty && DateTime.UtcNow - _lastSaveUtc >= TimeSpan.FromSeconds(5)) Save();
    }

    /// <summary>Writes any add or remove still waiting for its throttled save.</summary>
    public static void Flush()
    {
        lock (Lock) { if (_dirty) Save(); }
    }

    public static void Clear() { lock (Lock) { if (Entries.Count == 0) return; Entries.Clear(); Save(); } Changed?.Invoke(); }

    /// <summary>True when there is something to retry and the network is back.</summary>
    public static bool ShouldRetry() =>
        Count > 0 && System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable();

    /// <summary>Drop entries whose file no longer exists (moved/deleted) so the outbox doesn't grow stale.</summary>
    public static void PruneMissing()
    {
        lock (Lock)
        {
            int before = Entries.Count;
            Entries.RemoveAll(e => !File.Exists(e.Path));
            if (Entries.Count != before) Save();
        }
    }

    static List<PendingEntry> Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<List<PendingEntry>>(File.ReadAllText(FilePath)) ?? []; }
        catch (Exception ex) { Log("Pending outbox load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return [];
    }

    static void Save() // caller holds Lock
    {
        _lastSaveUtc = DateTime.UtcNow;
        try
        {
            Directory.CreateDirectory(ConfigPathResolver.DataFolder);
            AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_entries, JsonOpts));
            _dirty = false;
        }
        catch (Exception ex) { Log("Pending outbox save failed: " + ex.Message, LogLevel.Warning); }
    }
}
