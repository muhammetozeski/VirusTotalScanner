using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalScanner;

/// <summary>One scan event — every scan, even a repeat of the same file. Unlike the hash cache (one
/// row per content, overwritten), this is an append-only log so "when did I scan this and what came
/// back" is answerable.</summary>
internal sealed class HistoryEntry
{
    public DateTime WhenUtc { get; set; }
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public string? Md5 { get; set; }
    public string? Sha256 { get; set; }
    public string Verdict { get; set; } = "";
    public int Detections { get; set; }
    public int Total { get; set; }
    public string Source { get; set; } = "";
    public bool Starred { get; set; }
    public string? Note { get; set; }

    [JsonIgnore] public DateTime WhenLocal => WhenUtc.ToLocalTime();
    [JsonIgnore] public string Ratio => Total > 0 ? $"{Detections}/{Total}" : "";
    [JsonIgnore] public string Star => Starred ? "★" : "☆";
}

/// <summary>
/// Append-only, capped, JSON-backed history of every scan (history.json next to the cache). The
/// backbone the history tab, the "have I scanned this before?" pre-check and the landing dashboard all
/// read from. Thread-safe; failures degrade to an empty log, never crash a scan.
/// </summary>
internal static class ScanHistoryStore
{
    static readonly string FilePath = System.IO.Path.Combine(ConfigPathResolver.DataFolder, "history.json");
    const int MaxEntries = 5000;
    static readonly object Lock = new();
    static List<HistoryEntry>? _entries;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    public static event Action? Changed;

    static List<HistoryEntry> Entries
    {
        get { lock (Lock) { return _entries ??= Load(); } }
    }

    public static IReadOnlyList<HistoryEntry> All() { lock (Lock) { return [.. Entries]; } }

    public static int Count { get { lock (Lock) { return Entries.Count; } } }

    /// <summary>Most recent scan for this MD5, if any — powers the "have I scanned this before?" check.</summary>
    public static HistoryEntry? LastByMd5(string? md5)
    {
        if (string.IsNullOrEmpty(md5)) return null;
        lock (Lock) { return Entries.LastOrDefault(e => string.Equals(e.Md5, md5, StringComparison.OrdinalIgnoreCase)); }
    }

    public static void Record(ScanItem item, string source)
    {
        if (item == null) return;
        // Only log items that reached a terminal state (not mid-scan transitions).
        if (item.Status is ScanStatus.Queued or ScanStatus.Hashing or ScanStatus.LookingUp
            or ScanStatus.Uploading or ScanStatus.Polling) return;

        var e = new HistoryEntry
        {
            WhenUtc = DateTime.UtcNow,
            Name = item.FileName,
            Path = item.FilePath,
            Md5 = item.Md5,
            Sha256 = item.Sha256,
            Verdict = item.Verdict.Length > 0 ? item.Verdict : item.Status.ToString(),
            Detections = item.Report?.DetectionCount ?? 0,
            Total = item.Report?.TotalEngines ?? 0,
            Source = source,
        };

        lock (Lock)
        {
            Entries.Add(e);
            if (Entries.Count > MaxEntries) Entries.RemoveRange(0, Entries.Count - MaxEntries);
            Save();
        }
        Changed?.Invoke();
    }

    public static void Clear()
    {
        lock (Lock) { Entries.Clear(); Save(); }
        Changed?.Invoke();
    }

    /// <summary>Persist an in-place edit (star toggle, note) and notify listeners.</summary>
    public static void Persist()
    {
        lock (Lock) { Save(); }
        Changed?.Invoke();
    }

    static List<HistoryEntry> Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<List<HistoryEntry>>(File.ReadAllText(FilePath)) ?? [];
        }
        catch (Exception ex) { Log("History load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return [];
    }

    static void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigPathResolver.DataFolder);
            AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_entries, JsonOpts));
        }
        catch (Exception ex) { Log("History save failed: " + ex.Message, LogLevel.Warning); }
    }
}
