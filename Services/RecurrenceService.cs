namespace VirusTotalScanner;

/// <summary>Finds threats that keep coming BACK — the same content (md5/sha256, or name when the hash is
/// missing) flagged across two or more SEPARATE scan events. Unlike <see cref="FamilyClusterService"/>,
/// which dedupes by hash (same content counted once), this COUNTS the repeats, because the recurrence is
/// the signal: the source (a dropper, a synced folder, a re-downloading installer) is still live. Fully
/// local over the append-only scan history — no VirusTotal calls.</summary>
internal static class RecurrenceService
{
    internal sealed class Recurrence
    {
        public string Name { get; init; } = "";
        public int Events { get; init; }                          // how many separate scan events flagged it
        public DateTime FirstUtc { get; init; }
        public DateTime LastUtc { get; init; }
        public IReadOnlyList<string> Paths { get; init; } = [];
        public string? LastPath { get; init; }

        public string Span => $"{FirstUtc.ToLocalTime():yyyy-MM-dd} → {LastUtc.ToLocalTime():yyyy-MM-dd}";
        public int Locations => Paths.Count;
        public string PathsText => string.Join("  |  ", Paths.Take(4)) + (Paths.Count > 4 ? $"  (+{Paths.Count - 4})" : "");
    }

    public static List<Recurrence> Find()
    {
        var threats = ScanHistoryStore.All().Where(h => VerdictCategories.IsThreat(h.Detections));
        var result = new List<Recurrence>();
        foreach (var g in threats.GroupBy(KeyOf, StringComparer.OrdinalIgnoreCase))
        {
            var events = g.OrderBy(h => h.WhenUtc).ToList();
            // Recurrence = the same content flagged in 2+ distinct scan events (separate timestamps).
            if (events.Select(h => h.WhenUtc).Distinct().Count() < 2) continue;
            var paths = events.Select(h => h.Path).Where(p => !string.IsNullOrEmpty(p))
                .Distinct(StringComparer.OrdinalIgnoreCase).Select(p => p!).ToList();
            result.Add(new Recurrence
            {
                Name = events[^1].Name,
                Events = events.Count,
                FirstUtc = events[0].WhenUtc,
                LastUtc = events[^1].WhenUtc,
                Paths = paths,
                LastPath = events.Select(h => h.Path).LastOrDefault(p => !string.IsNullOrEmpty(p)),
            });
        }
        return result.OrderByDescending(r => r.Events).ThenByDescending(r => r.LastUtc).ToList();
    }

    static string KeyOf(HistoryEntry h) =>
        !string.IsNullOrEmpty(h.Md5) ? "md5:" + h.Md5
        : !string.IsNullOrEmpty(h.Sha256) ? "sha:" + h.Sha256
        : "name:" + h.Name.Trim().ToLowerInvariant();
}
