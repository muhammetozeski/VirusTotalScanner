namespace VirusTotalScanner;

/// <summary>
/// Folder-level situational awareness from the local cache: when a file is flagged, answer
/// "did it arrive alone?" by listing the other files in its directory that were already scanned
/// (with their verdicts) and counting the ones never scanned yet. Pure local — no VT calls.
/// </summary>
internal static class NeighborsService
{
    public sealed record Neighbor(string Path, string Verdict, int Detections, int Total, DateTime? FirstSeenUtc, bool Exists);

    public sealed record FolderNeighbors(string Folder, List<Neighbor> Cached, List<string> NeverScanned);

    public static FolderNeighbors? Build(string filePath, HashCache cache)
    {
        string folder = SafeDir(filePath);
        if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return null;

        // Cache entries whose last-seen path sits in this folder (excluding the file itself).
        var cached = cache.Snapshot()
            .Where(e => !string.IsNullOrEmpty(e.LastPath))
            .Where(e => string.Equals(SafeDir(e.LastPath!), folder, StringComparison.OrdinalIgnoreCase))
            .Where(e => !string.Equals(e.LastPath, filePath, StringComparison.OrdinalIgnoreCase))
            .Select(e => new Neighbor(
                e.LastPath!,
                e.Report?.Verdict ?? VerdictCategories.Classify(e.Detections).Name,
                e.Detections, e.TotalEngines,
                e.Report?.FirstSeenUtc,
                File.Exists(e.LastPath!)))
            .OrderByDescending(n => n.Detections)
            .ThenBy(n => n.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var known = new HashSet<string>(cached.Select(n => n.Path), StringComparer.OrdinalIgnoreCase) { filePath };
        var neverScanned = new List<string>();
        try
        {
            foreach (var f in Directory.EnumerateFiles(folder))
                if (!known.Contains(f)) neverScanned.Add(f);
        }
        catch (Exception ex) { Log("Neighbors enumerate failed: " + ex.Message, LogLevel.Warning); }

        return new FolderNeighbors(folder, cached, neverScanned);
    }

    static string SafeDir(string p) { try { return Path.GetDirectoryName(p) ?? ""; } catch { return ""; } }
}
