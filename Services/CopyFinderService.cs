using System.Diagnostics;

namespace VirusTotalScanner;

/// <summary>
/// Finds every other on-disk copy of a known file by exact content (SHA-256). A two-stage funnel
/// keeps it fast: stage 1 lists candidates of the same byte size (via the Everything CLI <c>es</c>,
/// or a scoped folder walk as fallback); stage 2 hashes only those and keeps exact matches. No VT
/// calls — it reuses the verdict already in hand, so it is free and offline.
/// </summary>
internal static class CopyFinderService
{
    const int MaxCandidates = 5000;

    public static async Task<List<string>> FindCopiesAsync(
        string targetPath, string sha256, long size, Action<int, int>? onProgress, CancellationToken ct)
    {
        var matches = new List<string>();
        if (string.IsNullOrEmpty(sha256) || size <= 0) return matches;

        var candidates = EverythingBySize(size);
        if (candidates.Count == 0) candidates = ScopedWalk(size, ct);

        int done = 0;
        foreach (var c in candidates)
        {
            ct.ThrowIfCancellationRequested();
            onProgress?.Invoke(++done, candidates.Count);
            if (string.Equals(c, targetPath, StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                if (!File.Exists(c)) continue;
                var (_, sha) = await HashService.ComputeAsync(c, ct);
                if (string.Equals(sha, sha256, StringComparison.OrdinalIgnoreCase)) matches.Add(c);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { Log($"Copy-finder hash failed for {c}: {ex.Message}", LogLevel.Warning); }
        }
        return matches;
    }

    /// <summary>Stage 1: ask Everything for files of this exact byte size. Empty if es is absent.</summary>
    static List<string> EverythingBySize(long size)
    {
        var result = new List<string>();
        try
        {
            using var p = new Process();
            p.StartInfo.FileName = "es";
            p.StartInfo.ArgumentList.Add("file:");        // files only — skip same-"size" folders
            p.StartInfo.ArgumentList.Add($"size:{size}");
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            string? line;
            while ((line = p.StandardOutput.ReadLine()) != null)
            {
                line = line.Trim();
                if (line.Length > 0 && File.Exists(line)) result.Add(line);
                if (result.Count >= MaxCandidates) break;
            }
            p.WaitForExit(15000);
            Log($"Everything found {result.Count} size-{size} candidate(s).", LogLevel.Info);
        }
        catch (Exception ex) { Log("Everything (es) unavailable, will scope-walk: " + ex.Message, LogLevel.Info); }
        return result;
    }

    /// <summary>Fallback stage 1: walk common drop folders for same-size files.</summary>
    static List<string> ScopedWalk(long size, CancellationToken ct)
    {
        var result = new List<string>();
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
        }.Distinct();

        var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var root in roots)
        {
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) continue;
            try
            {
                foreach (var f in Directory.EnumerateFiles(root, "*", opts))
                {
                    if (ct.IsCancellationRequested) return result;
                    try { if (new FileInfo(f).Length == size) result.Add(f); } catch { }
                    if (result.Count >= MaxCandidates) return result;
                }
            }
            catch (Exception ex) { Log("Copy-finder scoped walk failed for " + root + ": " + ex.Message, LogLevel.Warning); }
        }
        return result;
    }
}
