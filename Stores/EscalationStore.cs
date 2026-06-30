using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalScanner;

/// <summary>One confirmed clean→threat flip: a file the user once cleared that VirusTotal later flags.</summary>
internal sealed class EscalationRecord
{
    public string Hash { get; set; } = ""; // sha256
    public string Name { get; set; } = "";
    public int OldDetections { get; set; }
    public int OldTotal { get; set; }
    public int NewDetections { get; set; }
    public int NewTotal { get; set; }
    public DateTime FirstScanUtc { get; set; }
    public DateTime FlipUtc { get; set; }

    [JsonIgnore] public DateTime FlipLocal => FlipUtc.ToLocalTime();
    [JsonIgnore] public string OldRatio => OldTotal > 0 ? $"{OldDetections}/{OldTotal}" : OldDetections.ToString();
    [JsonIgnore] public string NewRatio => NewTotal > 0 ? $"{NewDetections}/{NewTotal}" : NewDetections.ToString();
}

/// <summary>
/// Durable ledger of clean→threat flips (escalations.json). "A file I cleared later turned malicious" is
/// the highest-value signal this app produces, but it used to evaporate when the re-verdict dialog closed.
/// Persisting it lets the user see WHICH past-trusted files went bad and when. Atomic writes; corrupt-backup.
/// </summary>
internal static class EscalationStore
{
    static readonly string FilePath = System.IO.Path.Combine(ConfigPathResolver.DataFolder, "escalations.json");
    static readonly object Lock = new();
    static List<EscalationRecord>? _records;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static event Action? Changed;

    static List<EscalationRecord> Records { get { lock (Lock) { return _records ??= Load(); } } }
    public static int Count { get { lock (Lock) { return Records.Count; } } }
    public static IReadOnlyList<EscalationRecord> All() { lock (Lock) { return [.. Records]; } }

    /// <summary>Record a confirmed flip. Deduped by hash; the first observed flip is kept (not overwritten).</summary>
    public static void Add(string? sha256, string name, int oldDet, int oldTotal, int newDet, int newTotal, DateTime firstScanUtc)
    {
        if (string.IsNullOrEmpty(sha256)) return;
        bool changed = false;
        lock (Lock)
        {
            if (Records.Any(r => string.Equals(r.Hash, sha256, StringComparison.OrdinalIgnoreCase))) return;
            Records.Add(new EscalationRecord
            {
                Hash = sha256, Name = name,
                OldDetections = oldDet, OldTotal = oldTotal,
                NewDetections = newDet, NewTotal = newTotal,
                FirstScanUtc = firstScanUtc, FlipUtc = DateTime.UtcNow,
            });
            Save();
            changed = true;
        }
        if (changed) Changed?.Invoke();
    }

    static List<EscalationRecord> Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<List<EscalationRecord>>(File.ReadAllText(FilePath)) ?? []; }
        catch (Exception ex) { Log("Escalation store load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return [];
    }

    static void Save() // caller holds Lock
    {
        try { Directory.CreateDirectory(ConfigPathResolver.DataFolder); AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_records, JsonOpts)); }
        catch (Exception ex) { Log("Escalation store save failed: " + ex.Message, LogLevel.Warning); }
    }
}
