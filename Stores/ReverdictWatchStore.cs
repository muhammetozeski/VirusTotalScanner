using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>A file being watched for a verdict change — the borderline ones (a 0-1/72 today that may
/// turn malicious next week as VirusTotal catches up).</summary>
internal sealed class WatchEntry
{
    public string? Sha256 { get; set; }
    public string? Md5 { get; set; }
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public int LastDetections { get; set; }
    public int LastTotal { get; set; }
    public DateTime AddedUtc { get; set; }
    public DateTime LastCheckedUtc { get; set; }
}

/// <summary>
/// A small, persisted watch list (watch.json) of borderline files re-queried on a slow cadence so a
/// file that scanned clean/low today but turns malicious later is caught — closing the gap between
/// scheduled sweeps and the specific files the user was unsure about. Thread-safe; best-effort.
/// </summary>
internal static class ReverdictWatchStore
{
    static readonly string FilePath = System.IO.Path.Combine(ConfigPathResolver.DataFolder, "watch.json");
    static readonly object Lock = new();
    static List<WatchEntry>? _entries;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static event Action? Changed;

    static List<WatchEntry> Entries { get { lock (Lock) { return _entries ??= Load(); } } }

    public static IReadOnlyList<WatchEntry> List() { lock (Lock) { return [.. Entries]; } }
    public static int Count { get { lock (Lock) { return Entries.Count; } } }
    public static bool Contains(string? sha256) { if (string.IsNullOrEmpty(sha256)) return false; lock (Lock) { return Entries.Any(e => string.Equals(e.Sha256, sha256, StringComparison.OrdinalIgnoreCase)); } }

    public static void Add(ScanItem item)
    {
        if (string.IsNullOrEmpty(item.Sha256)) return;
        lock (Lock)
        {
            if (Entries.Any(e => string.Equals(e.Sha256, item.Sha256, StringComparison.OrdinalIgnoreCase))) return;
            Entries.Add(new WatchEntry
            {
                Sha256 = item.Sha256,
                Md5 = item.Md5,
                Name = item.FileName,
                Path = item.FilePath,
                LastDetections = item.Report?.DetectionCount ?? 0,
                LastTotal = item.Report?.TotalEngines ?? 0,
                AddedUtc = DateTime.UtcNow,
                LastCheckedUtc = DateTime.UtcNow,
            });
            Save();
        }
        Changed?.Invoke();
    }

    public static void Remove(string? sha256)
    {
        if (string.IsNullOrEmpty(sha256)) return;
        lock (Lock) { Entries.RemoveAll(e => string.Equals(e.Sha256, sha256, StringComparison.OrdinalIgnoreCase)); Save(); }
        Changed?.Invoke();
    }

    public static void Update(WatchEntry entry) { lock (Lock) { Save(); } Changed?.Invoke(); }

    static List<WatchEntry> Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<List<WatchEntry>>(File.ReadAllText(FilePath)) ?? []; }
        catch (Exception ex) { Log("Watch load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return [];
    }

    static void Save()
    {
        try { Directory.CreateDirectory(ConfigPathResolver.DataFolder); AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_entries, JsonOpts)); }
        catch (Exception ex) { Log("Watch save failed: " + ex.Message, LogLevel.Warning); }
    }
}

/// <summary>Re-queries every watched file (keyless GUI, zero quota) and reports any whose detection
/// count climbed — the escalations worth alerting on.</summary>
internal static class WatchService
{
    public static async Task<List<(WatchEntry Entry, int Old, int New)>> CheckAllAsync(CancellationToken ct = default)
    {
        var escalations = new List<(WatchEntry, int, int)>();
        if (!(Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable)) return escalations;

        foreach (var e in ReverdictWatchStore.List())
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(e.Sha256)) continue;
            try
            {
                var r = await GuiScrapeService.LookupAsync(e.Sha256);
                if (r == null) continue;
                int now = r.DetectionCount;
                if (now > e.LastDetections) escalations.Add((e, e.LastDetections, now));
                e.LastDetections = now;
                e.LastTotal = r.TotalEngines;
                e.LastCheckedUtc = DateTime.UtcNow;
                ReverdictWatchStore.Update(e);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log("Watch re-check failed for " + e.Name + ": " + ex.Message, LogLevel.Warning); }
        }
        return escalations;
    }
}
