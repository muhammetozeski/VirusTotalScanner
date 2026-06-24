using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>One file the user has explicitly vouched is clean (a false-positive they recognize, their
/// own niche tool, a packed game launcher…). Keyed by hash so it survives moves/renames.</summary>
internal sealed class AllowlistEntry
{
    public string Hash { get; set; } = "";   // sha256 preferred, else md5
    public string? Md5 { get; set; }
    public string FileName { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTime AddedUtc { get; set; }

    [System.Text.Json.Serialization.JsonIgnore] public DateTime AddedLocal => AddedUtc.ToLocalTime();
}

/// <summary>
/// User-writable allowlist (allowlist.json): files the user marked "this is clean" from inside the app,
/// so they stop being re-flagged on every scan. Unlike <see cref="KnownGoodDb"/> (a read-only external
/// hash file the user points at), this one is editable in-app. A hit makes the scheduler skip the lookup
/// with a "user said clean" reason. Thread-safe; atomic writes; best-effort.
/// </summary>
internal static class AllowlistStore
{
    static readonly string FilePath = System.IO.Path.Combine(ConfigPathResolver.DataFolder, "allowlist.json");
    static readonly object Lock = new();
    static List<AllowlistEntry>? _entries;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static event Action? Changed;

    static List<AllowlistEntry> Entries { get { lock (Lock) { return _entries ??= Load(); } } }

    public static int Count { get { lock (Lock) { return Entries.Count; } } }
    public static IReadOnlyList<AllowlistEntry> All() { lock (Lock) { return [.. Entries]; } }

    /// <summary>True if either hash is on the list (md5 or sha256).</summary>
    public static bool Contains(string? md5, string? sha256)
    {
        lock (Lock)
        {
            if (Entries.Count == 0) return false;
            return Entries.Any(e =>
                (!string.IsNullOrEmpty(sha256) && (string.Equals(e.Hash, sha256, StringComparison.OrdinalIgnoreCase) || string.Equals(e.Md5, sha256, StringComparison.OrdinalIgnoreCase)))
                || (!string.IsNullOrEmpty(md5) && (string.Equals(e.Hash, md5, StringComparison.OrdinalIgnoreCase) || string.Equals(e.Md5, md5, StringComparison.OrdinalIgnoreCase))));
        }
    }

    /// <summary>Add (or update the reason for) a file the user vouched is clean. Returns false if the
    /// item has no hash to key on.</summary>
    public static bool Add(ScanItem item, string reason)
    {
        if (item == null) return false;
        string? hash = !string.IsNullOrEmpty(item.Sha256) ? item.Sha256 : item.Md5;
        if (string.IsNullOrEmpty(hash)) return false;
        lock (Lock)
        {
            var existing = Entries.FirstOrDefault(e => string.Equals(e.Hash, hash, StringComparison.OrdinalIgnoreCase));
            if (existing != null) { existing.Reason = reason; existing.FileName = item.FileName; }
            else Entries.Add(new AllowlistEntry { Hash = hash, Md5 = item.Md5, FileName = item.FileName, Reason = reason, AddedUtc = DateTime.UtcNow });
            Save();
        }
        Changed?.Invoke();
        return true;
    }

    public static void Remove(string? hash)
    {
        if (string.IsNullOrEmpty(hash)) return;
        lock (Lock) { if (Entries.RemoveAll(e => string.Equals(e.Hash, hash, StringComparison.OrdinalIgnoreCase)) == 0) return; Save(); }
        Changed?.Invoke();
    }

    static List<AllowlistEntry> Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<List<AllowlistEntry>>(File.ReadAllText(FilePath)) ?? []; }
        catch (Exception ex) { Log("Allowlist load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return [];
    }

    static void Save() // caller holds Lock
    {
        try { Directory.CreateDirectory(ConfigPathResolver.DataFolder); AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_entries, JsonOpts)); }
        catch (Exception ex) { Log("Allowlist save failed: " + ex.Message, LogLevel.Warning); }
    }
}
