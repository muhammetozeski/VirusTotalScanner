namespace VirusTotalScanner;

/// <summary>One file from the scan history that was once clean/low but is flagged now.</summary>
internal sealed class ReverdictEscalation
{
    public required HistoryEntry Entry { get; init; }
    public int OldDetections { get; init; }
    public int NewDetections { get; init; }
    public int NewTotal { get; init; }

    public string Name => Entry.Name;
    public string? Path => Entry.Path;
    public DateTime FirstSeenLocal => Entry.WhenLocal;
    public string OldRatio => Entry.Total > 0 ? $"{OldDetections}/{Entry.Total}" : OldDetections.ToString();
    public string NewRatio => NewTotal > 0 ? $"{NewDetections}/{NewTotal}" : NewDetections.ToString();
}

/// <summary>
/// Reconciles the append-only scan history against fresh VirusTotal verdicts: every file the user once
/// cleared (clean/low) that is STILL on disk gets re-queried keyless (zero quota), and the ones that have
/// since turned malicious are returned with their old→new ratio. Distinct from RecheckService (which only
/// re-checks the hash cache) and WatchService (which only re-checks the tiny manual watch list) — this
/// mines the full history, the richest population to re-verify as VirusTotal catches up to fresh malware.
/// </summary>
internal static class HistoryReverdictService
{
    public static async Task<List<ReverdictEscalation>> CheckAsync(Action<int, int>? progress = null, CancellationToken ct = default)
    {
        var result = new List<ReverdictEscalation>();
        if (!(Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable)) return result;

        // Once-clean/low, hash known, file still present; one row per content (latest scan of it).
        var candidates = ScanHistoryStore.All()
            .Where(e => !VerdictCategories.IsThreat(e.Detections)
                && !string.IsNullOrEmpty(e.Sha256)
                && !string.IsNullOrEmpty(e.Path) && File.Exists(e.Path!))
            .GroupBy(e => e.Sha256!, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(e => e.WhenUtc).First())
            .ToList();

        int done = 0;
        foreach (var e in candidates)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var r = await GuiScrapeService.LookupAsync(e.Sha256!, ct);
                if (r != null && VerdictCategories.IsThreat(r.DetectionCount) && r.DetectionCount > e.Detections)
                {
                    result.Add(new ReverdictEscalation { Entry = e, OldDetections = e.Detections, NewDetections = r.DetectionCount, NewTotal = r.TotalEngines });
                    // Persist the flip so it survives the dialog being closed (deduped by hash; first flip kept).
                    EscalationStore.Add(e.Sha256, e.Name, e.Detections, e.Total, r.DetectionCount, r.TotalEngines, e.WhenUtc);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log("History re-verdict failed for " + e.Name + ": " + ex.Message, LogLevel.Warning); }
            progress?.Invoke(++done, candidates.Count);
        }
        return result;
    }
}
