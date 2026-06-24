using System.Diagnostics;

namespace VirusTotalScanner;

/// <summary>One executable that landed on disk, with where/when it came from and (if known) its verdict.</summary>
internal sealed class TimelineFile
{
    public string Path { get; init; } = "";
    public string Name => System.IO.Path.GetFileName(Path);
    public DateTime ArrivalLocal { get; init; }
    public string? Host { get; init; }       // download origin (Zone.Identifier), if any
    public bool FromInternet { get; init; }
    public string Verdict { get; set; } = "?";
    public int Detections { get; set; } = -1; // -1 = not looked up / unknown
    public bool Known => Detections >= 0;
}

/// <summary>A day's worth of arrivals — the unit of the timeline.</summary>
internal sealed class TimelineDay
{
    public DateOnly Day { get; init; }
    public List<TimelineFile> Files { get; } = [];
    public int Count => Files.Count;
    public int Threats => Files.Count(f => f.Detections > 0);
    public int FromNet => Files.Count(f => f.FromInternet);
    public string DayText => Day.ToString("yyyy-MM-dd (ddd)");
}

/// <summary>
/// Machine-wide chronological triage on a new axis: time-of-arrival. Enumerates executables with the
/// Everything CLI (<c>es</c>), reads each file's creation time and download origin (Zone.Identifier),
/// and buckets them into day-level clusters. A verdict is attached from the local hash cache only
/// (zero quota, no VT calls) so a low/known-bad file shows up next to everything else that arrived the
/// same day — answering "what landed around the time things went wrong?". Bounded by a day window and
/// a hard file cap; fully cancellable; falls back to a scoped walk if <c>es</c> is absent.
/// </summary>
internal static class IncidentTimelineService
{
    const int MaxFiles = 6000;
    const long MaxHashBytes = 256L * 1024 * 1024; // don't hash >256MB just for a cache peek

    static readonly string[] Extensions =
        ["exe", "com", "scr", "msi", "bat", "cmd", "ps1", "vbs", "js", "jar", "dll", "cpl"];

    public static async Task<List<TimelineDay>> BuildAsync(
        HashCache cache, int daysBack, Action<int, int>? progress, CancellationToken ct)
    {
        var sinceUtc = DateTime.Now.AddDays(-daysBack);
        var paths = Enumerate(sinceUtc);
        if (paths.Count == 0) paths = ScopedWalk(sinceUtc, ct);

        var files = new List<TimelineFile>(paths.Count);
        int done = 0, total = paths.Count;
        foreach (var p in paths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var fi = new FileInfo(p);
                if (!fi.Exists || fi.CreationTime < sinceUtc) { progress?.Invoke(++done, total); continue; }

                var zone = ZoneIdentifier.Read(p);
                var tf = new TimelineFile
                {
                    Path = p,
                    ArrivalLocal = fi.CreationTime,
                    Host = zone?.HostUrl,
                    FromInternet = zone?.FromInternet == true,
                };

                // Verdict from the cache only (free). Hashing is the cost, so skip oversized files.
                if (fi.Length <= MaxHashBytes)
                {
                    try
                    {
                        var (md5, _) = await HashService.ComputeAsync(p, ct);
                        var report = cache.TryGet(md5, int.MaxValue);
                        if (report != null) { tf.Verdict = report.Verdict; tf.Detections = report.DetectionCount; }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { /* unreadable/locked — leave unknown */ }
                }

                files.Add(tf);
            }
            catch { /* skip unreadable entries */ }
            progress?.Invoke(++done, total);
        }

        return files
            .GroupBy(f => DateOnly.FromDateTime(f.ArrivalLocal))
            .OrderByDescending(g => g.Key)
            .Select(g =>
            {
                var day = new TimelineDay { Day = g.Key };
                day.Files.AddRange(g.OrderByDescending(f => f.Detections).ThenBy(f => f.ArrivalLocal));
                return day;
            })
            .ToList();
    }

    /// <summary>Stage 1: ask Everything for executables created on/after the window start.</summary>
    static List<string> Enumerate(DateTime sinceLocal)
    {
        var result = new List<string>();
        try
        {
            using var p = new Process();
            p.StartInfo.FileName = "es";
            p.StartInfo.ArgumentList.Add("file:");
            p.StartInfo.ArgumentList.Add("ext:" + string.Join(";", Extensions));
            p.StartInfo.ArgumentList.Add($"dc:>={sinceLocal:yyyy/MM/dd}"); // date-created filter
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
                if (result.Count >= MaxFiles) break;
            }
            p.WaitForExit(20000);
            Log($"Timeline: Everything found {result.Count} executable(s) since {sinceLocal:yyyy-MM-dd}.", LogLevel.Info);
        }
        catch (Exception ex) { Log("Timeline: Everything (es) unavailable, will scope-walk: " + ex.Message, LogLevel.Info); }
        return result;
    }

    /// <summary>Fallback when es is absent: walk common drop folders for recent executables.</summary>
    static List<string> ScopedWalk(DateTime sinceLocal, CancellationToken ct)
    {
        var result = new List<string>();
        var exts = new HashSet<string>(Extensions.Select(e => "." + e), StringComparer.OrdinalIgnoreCase);
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads",
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };
        foreach (var root in roots.Distinct().Where(Directory.Exists))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    if (!exts.Contains(Path.GetExtension(f))) continue;
                    try { if (new FileInfo(f).CreationTime >= sinceLocal) result.Add(f); } catch { }
                    if (result.Count >= MaxFiles) return result;
                }
            }
            catch { /* access denied on a subtree — skip */ }
        }
        return result;
    }
}
