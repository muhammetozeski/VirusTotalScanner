namespace VirusTotalScanner;

/// <summary>One recently-downloaded file, enriched with where it came from, whether it's signed, and
/// its cached verdict (if known) — the at-a-glance "what did I download, from where, and which are
/// still unchecked?" ledger.</summary>
internal sealed class DownloadItem
{
    public string Path { get; init; } = "";
    public string Name => System.IO.Path.GetFileName(Path);
    public DateTime ArrivalLocal { get; init; }
    public string? Host { get; init; }
    public string Signature { get; init; } = "";
    public string Verdict { get; set; } = "—";
    public int Detections { get; set; } = -1; // -1 = not yet scanned / unknown
    public bool Scanned => Detections >= 0;
}

/// <summary>
/// Builds the Downloads-triage ledger from the Downloads + Desktop folders: recent executable-class
/// files with their Zone.Identifier origin host, Authenticode signature status, and cached verdict
/// (cache-only, zero quota). Reuses the same building blocks as the rest of the app; fully cancellable.
/// </summary>
internal static class DownloadsTriageService
{
    const int MaxFiles = 400;
    const long MaxHashBytes = 256L * 1024 * 1024;

    static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
        ".com", ".dll", ".cpl", ".zip", ".7z", ".rar", ".iso", ".apk", ".lnk", ".nupkg",
    };

    public static IReadOnlyList<string> Folders() =>
    [
        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
    ];

    public static async Task<List<DownloadItem>> BuildAsync(HashCache cache, int daysBack, Action<int, int>? progress, CancellationToken ct)
    {
        var since = DateTime.Now.AddDays(-daysBack);
        var paths = new List<string>();
        foreach (var folder in Folders().Distinct().Where(Directory.Exists))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var f in Directory.EnumerateFiles(folder, "*", SearchOption.TopDirectoryOnly))
                {
                    if (!Extensions.Contains(System.IO.Path.GetExtension(f))) continue;
                    try { if (new FileInfo(f).CreationTime >= since) paths.Add(f); } catch { }
                    if (paths.Count >= MaxFiles) break;
                }
            }
            catch { /* access denied — skip the folder */ }
        }
        paths = paths.Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(p => { try { return new FileInfo(p).CreationTime; } catch { return DateTime.MinValue; } })
            .ToList();

        var cachedSizes = cache.CachedSizes(); // size pre-filter: skip hashing files that can't be cache hits
        var list = new List<DownloadItem>(paths.Count);
        int done = 0;
        foreach (var p in paths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var fi = new FileInfo(p);
                var zone = ZoneIdentifier.Read(p);
                var trust = TrustService.Evaluate(p);
                var di = new DownloadItem
                {
                    Path = p,
                    ArrivalLocal = fi.CreationTime,
                    Host = zone?.HostUrl,
                    Signature = trust.Trusted ? string.Format(Strings.DownloadsTriageSignedFormat, trust.Publisher ?? Strings.DetailSignedFallback) : Strings.TrustUnsigned,
                };
                if (fi.Length <= MaxHashBytes && cachedSizes.Contains(fi.Length))
                {
                    try
                    {
                        var md5 = await HashService.ComputeMd5Async(p, ct);
                        var r = cache.TryGet(md5, int.MaxValue);
                        if (r != null) { di.Verdict = r.Verdict; di.Detections = r.DetectionCount; }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { }
                }
                list.Add(di);
            }
            catch { }
            progress?.Invoke(++done, paths.Count);
        }
        return list;
    }
}
