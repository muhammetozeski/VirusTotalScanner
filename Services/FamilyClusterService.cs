namespace VirusTotalScanner;

/// <summary>
/// Correlates the whole local cache by malware family: groups DISTINCT hashes that resolve to the
/// same normalized Family token (e.g. "Swrort"), so a polymorphic campaign that produced a fresh
/// hash on each infection shows up as one cluster instead of N unrelated unknowns. Pure in-memory
/// group-by over cache.json — no VT calls, no quota.
/// </summary>
internal static class FamilyClusterService
{
    public sealed record Cluster(string Family, int Members, List<string> Paths, DateTime? FirstSeen, DateTime? LastSeen, int MinDetections, int MaxDetections);

    public static List<Cluster> Build(HashCache cache)
    {
        var clusters = new List<Cluster>();
        var byFamily = cache.Snapshot()
            .Where(e => e.Report?.Family is { Length: > 0 })
            .GroupBy(e => e.Report!.Family!, StringComparer.OrdinalIgnoreCase);

        foreach (var g in byFamily)
        {
            // One entry per distinct content hash — different files, same family.
            var distinct = g.GroupBy(e => e.Md5, StringComparer.OrdinalIgnoreCase).Select(x => x.First()).ToList();
            if (distinct.Count < 2) continue;

            var paths = distinct.Where(e => !string.IsNullOrEmpty(e.LastPath))
                .Select(e => e.LastPath!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var firsts = distinct.Select(e => e.Report?.FirstSeenUtc).Where(d => d.HasValue).Select(d => d!.Value).ToList();
            var dets = distinct.Select(e => e.Detections).ToList();

            clusters.Add(new Cluster(
                g.Key, distinct.Count, paths,
                firsts.Count > 0 ? firsts.Min() : null,
                firsts.Count > 0 ? firsts.Max() : null,
                dets.Count > 0 ? dets.Min() : 0,
                dets.Count > 0 ? dets.Max() : 0));
        }
        return clusters.OrderByDescending(c => c.Members).ToList();
    }
}
