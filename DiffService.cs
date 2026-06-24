using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>
/// Compares the current scan against a previously-saved <c>--report json</c> artifact, keyed by
/// sha256, to find what changed since the baseline (a green CI run). Used by the <c>--diff</c> CLI
/// gate so CI fails only on a brand-new artifact or a verdict that got worse — not on the steady
/// state. Pure local: it reads two report shapes, no VT calls.
/// </summary>
internal static class DiffService
{
    public sealed record Delta(int New, int Regressed, int Unchanged, List<string> NewFiles, List<string> RegressedFiles);

    public static Delta? Compare(IReadOnlyList<ScanItem> current, string baselinePath)
    {
        var baseline = LoadBaseline(baselinePath);
        if (baseline == null) return null;

        int @new = 0, regressed = 0, unchanged = 0;
        var newFiles = new List<string>();
        var regFiles = new List<string>();

        foreach (var i in current)
        {
            if (i.Report == null || string.IsNullOrEmpty(i.Sha256)) continue;
            int cur = i.Report.DetectionCount;
            if (!baseline.TryGetValue(i.Sha256!, out int prev)) { @new++; newFiles.Add($"{i.FilePath} ({cur} tespit)"); }
            else if (cur > prev || (prev == 0 && cur > 0)) { regressed++; regFiles.Add($"{i.FilePath} ({prev} → {cur})"); }
            else unchanged++;
        }
        return new Delta(@new, regressed, unchanged, newFiles, regFiles);
    }

    /// <summary>Loads sha256 -> detection-count from a ReportWriter JSON artifact.</summary>
    static Dictionary<string, int>? LoadBaseline(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (doc.RootElement.TryGetProperty("items", out var items) && items.ValueKind == JsonValueKind.Array)
            {
                foreach (var it in items.EnumerateArray())
                {
                    string? sha = it.TryGetProperty("sha256", out var s) ? s.GetString() : null;
                    if (string.IsNullOrEmpty(sha)) continue;
                    int mal = it.TryGetProperty("malicious", out var m) && m.TryGetInt32(out var mv) ? mv : 0;
                    int sus = it.TryGetProperty("suspicious", out var su) && su.TryGetInt32(out var sv) ? sv : 0;
                    map[sha!] = mal + sus;
                }
            }
            return map;
        }
        catch (Exception ex) { Log("Diff baseline load failed: " + ex.Message, LogLevel.Warning); return null; }
    }
}
