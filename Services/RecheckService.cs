namespace VirusTotalScanner;

/// <summary>
/// Re-checks previously-scanned (cached) files for verdict changes: a file that was clean weeks
/// ago can be flagged later as engines catch up. The sweep is keyless (drives the WebView2 GUI
/// engine), so it spends no API quota. One batch, one confirmation — not a per-file nag.
/// </summary>
internal static class RecheckService
{
    /// <summary>A verdict that moved between the cached scan and now.</summary>
    public sealed record Change(string? Sha256, string? Url, string OldVerdict, int OldDetections,
        string NewVerdict, int NewDetections)
    {
        public bool GotWorse => NewDetections > OldDetections;
    }

    /// <summary>Cached entries old enough to be worth re-checking.</summary>
    public static IReadOnlyList<HashCacheEntry> DueForRecheck(HashCache cache, int olderThanDays)
    {
        var cutoff = DateTime.UtcNow - TimeSpan.FromDays(Math.Max(0, olderThanDays));
        return cache.Snapshot()
            .Where(e => !string.IsNullOrEmpty(e.Sha256) && e.CachedUtc <= cutoff)
            .OrderBy(e => e.CachedUtc)
            .ToList();
    }

    /// <summary>Re-looks-up each due entry (keyless), refreshes the cache, and returns the verdict
    /// changes. <paramref name="onProgress"/> is called with (done, total) after each lookup.</summary>
    public static async Task<List<Change>> RunAsync(
        HashCache cache, IReadOnlyList<HashCacheEntry> due, Action<int, int>? onProgress, CancellationToken ct)
    {
        var changes = new List<Change>();
        if (!GuiScrapeService.IsRuntimeAvailable)
        {
            Log("Recheck skipped: keyless GUI runtime not available.", LogLevel.Warning);
            return changes;
        }

        int done = 0;
        foreach (var e in due)
        {
            ct.ThrowIfCancellationRequested();
            VtFileReport? fresh = null;
            try { fresh = await GuiScrapeService.LookupAsync(e.Sha256!, ct); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log($"Recheck lookup failed for {e.Sha256}: {ex.Message}", LogLevel.Warning); }

            onProgress?.Invoke(++done, due.Count);
            if (fresh == null || fresh.TotalEngines == 0) continue;

            int oldDet = e.Detections;
            string oldVerdict = e.Report?.Verdict ?? VerdictCategories.Classify(oldDet).Name;
            cache.Put(e.Md5, fresh);

            if (fresh.DetectionCount != oldDet || !string.Equals(fresh.Verdict, oldVerdict, StringComparison.Ordinal))
                changes.Add(new Change(e.Sha256, fresh.ReportUrl, oldVerdict, oldDet, fresh.Verdict, fresh.DetectionCount));
        }
        cache.Flush();
        return changes;
    }
}
