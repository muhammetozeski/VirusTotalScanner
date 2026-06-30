namespace VirusTotalScanner;

/// <summary>Location-keyed companion to <see cref="RecurrenceService"/>: directories that keep producing
/// DIFFERENT threats (2+ distinct content hashes, or threats on 2+ distinct days). Where RecurrenceService
/// tracks the same content recurring, this exposes a live SOURCE — a dropper, a synced folder, a shared
/// download directory — so the action is "close the source / rescan the folder", not just delete one file.
/// Fully local over the append-only scan history; no VirusTotal calls.</summary>
internal static class ThreatHotspotService
{
    internal sealed class Hotspot
    {
        public string Directory { get; init; } = "";
        public int DistinctThreats { get; init; }   // distinct content hashes flagged here
        public int Events { get; init; }
        public DateTime FirstUtc { get; init; }
        public DateTime LastUtc { get; init; }
        public IReadOnlyList<string> Samples { get; init; } = [];

        public string Span => $"{FirstUtc.ToLocalTime():yyyy-MM-dd} → {LastUtc.ToLocalTime():yyyy-MM-dd}";
        public string SamplesText => string.Join("  |  ", Samples.Take(4)) + (Samples.Count > 4 ? $"  (+{Samples.Count - 4})" : "");
    }

    public static List<Hotspot> Find()
    {
        var threats = ScanHistoryStore.All().Where(h => VerdictCategories.IsThreat(h.Detections) && !string.IsNullOrEmpty(h.Path));
        var result = new List<Hotspot>();
        foreach (var g in threats.GroupBy(DirOf, StringComparer.OrdinalIgnoreCase))
        {
            if (g.Key.Length == 0) continue;
            var events = g.OrderBy(h => h.WhenUtc).ToList();
            int distinctHashes = events.Select(KeyOf).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            int distinctDays = events.Select(h => h.WhenUtc.Date).Distinct().Count();
            // A hotspot = the same folder spawning different threats, or threats on different days.
            if (distinctHashes < 2 && distinctDays < 2) continue;
            result.Add(new Hotspot
            {
                Directory = g.Key,
                DistinctThreats = distinctHashes,
                Events = events.Count,
                FirstUtc = events[0].WhenUtc,
                LastUtc = events[^1].WhenUtc,
                Samples = events.Select(h => h.Name).Where(n => !string.IsNullOrEmpty(n)).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            });
        }
        return result.OrderByDescending(h => h.DistinctThreats).ThenByDescending(h => h.LastUtc).ToList();
    }

    static string DirOf(HistoryEntry h) { try { return Path.GetDirectoryName(h.Path!) ?? ""; } catch { return ""; } }
    static string KeyOf(HistoryEntry h) => !string.IsNullOrEmpty(h.Md5) ? h.Md5 : !string.IsNullOrEmpty(h.Sha256) ? h.Sha256! : h.Name;
}
