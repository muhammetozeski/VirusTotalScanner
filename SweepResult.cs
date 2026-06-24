using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>Machine-readable outcome of a scheduled sweep, written by the CLI (--sweep-result) so the
/// GUI can surface "the nightly sweep found N threats" instead of leaving a silent HTML report.</summary>
internal sealed class SweepResult
{
    public DateTime WhenUtc { get; set; }
    public int Scanned { get; set; }
    public int Threats { get; set; }
    public List<string> ThreatPaths { get; set; } = [];
}

internal static class SweepResultStore
{
    static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };

    public static void Write(string path, IEnumerable<ScanItem> items)
    {
        var list = items.ToList();
        var threats = list.Where(i => i.Report?.IsMalicious == true).ToList();
        var result = new SweepResult
        {
            WhenUtc = DateTime.UtcNow,
            Scanned = list.Count,
            Threats = threats.Count,
            ThreatPaths = threats.Select(i => i.FilePath).Where(p => !string.IsNullOrEmpty(p)).Distinct().ToList(),
        };
        AtomicFile.WriteAllText(path, JsonSerializer.Serialize(result, Opts));
    }

    public static SweepResult? TryRead(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<SweepResult>(File.ReadAllText(path)) : null; }
        catch { return null; }
    }
}
