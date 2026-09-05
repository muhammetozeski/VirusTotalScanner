using System.Diagnostics;
using System.Text;

namespace VirusTotalScanner;

/// <summary>
/// A fully local dry run: walks the selection exactly as a real scan would and reports how each file
/// WOULD be decided, without a single network call.
///
/// It exists to answer the only question that matters before starting a disk-wide sweep: how many
/// files actually need VirusTotal? A free key allows 500 lookups a day, so "337,021 files" and
/// "9,400 files that need a lookup" are completely different propositions, and until this existed
/// there was no way to tell them apart except by running the scan for a day and watching.
///
/// It also reports what a different trust setting would buy, because "Microsoft only" versus "any
/// valid signature" is usually the single biggest lever on that number.
/// </summary>
internal static class ScanPlanRunner
{
    sealed class Tally
    {
        public int Total;
        public int SafeExtension;
        public int Oversize;
        public int TrustedSkipped;      // skipped by the CURRENT trust settings
        public int SignedButNotSkipped; // valid signature, excluded only by "Microsoft only"
        public int KnownGood;
        public int Allowlisted;
        public int Cached;
        public int NeedsLookupCode;     // unknown and code-shaped -> a lookup, maybe a submission
        public int NeedsLookupOther;    // unknown and not code-shaped -> a lookup only
        public long BytesToHash;
    }

    public static async Task<int> RunAsync(List<string> paths, bool recurse, CancellationToken ct = default)
    {
        using var op = OpLog.Begin("Scan plan", $"{paths.Count} target(s) recurse={recurse}");
        if (paths.Count == 0) { Console.Error.WriteLine("no path given"); op.Fail("no path"); return 2; }

        var safe = SelectionEnumerator.ParseExtensions(Settings.SafeExtensions);
        var oversize = new List<string>();
        var missing = new List<string>();
        long maxBytes = Math.Max(0, (long)Settings.MaxFileSizeMB.Value) * 1024 * 1024;

        op.Step("walking the selection");
        var sw = Stopwatch.StartNew();
        var files = await Task.Run(() => SelectionEnumerator.Expand(
            paths, safe, recurse, Settings.SkipSafeExtensionsOnScan, maxBytes, oversize, missing), ct);
        op.Step($"walk done: {files.Count} file(s) in {sw.ElapsedMilliseconds} ms");

        var t = new Tally { Total = files.Count, Oversize = oversize.Count };
        KnownGoodDb.Reload();

        int done = 0;
        var lockObj = new object();
        await Task.Run(() => Parallel.ForEach(files,
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount, CancellationToken = ct },
            file =>
            {
                var local = Classify(file);
                lock (lockObj)
                {
                    t.SafeExtension += local.SafeExtension;
                    t.TrustedSkipped += local.TrustedSkipped;
                    t.SignedButNotSkipped += local.SignedButNotSkipped;
                    t.KnownGood += local.KnownGood;
                    t.Allowlisted += local.Allowlisted;
                    t.Cached += local.Cached;
                    t.NeedsLookupCode += local.NeedsLookupCode;
                    t.NeedsLookupOther += local.NeedsLookupOther;
                    t.BytesToHash += local.BytesToHash;
                }
                int n = Interlocked.Increment(ref done);
                if (n % 20000 == 0) Log($"Scan plan: classified {n}/{files.Count}", LogLevel.Info);
            }), ct);

        string report = Render(t, missing, sw.Elapsed);
        Console.WriteLine(report);
        TryWrite(report);
        op.Ok($"{t.NeedsLookupCode + t.NeedsLookupOther} file(s) would need VirusTotal");
        return 0;
    }

    /// <summary>Classifies one file the way the scheduler would, in the same order, using only local
    /// signals. Hashing is the expensive part, so it is done ONCE and only when the cheap checks did
    /// not already settle the file — exactly like the real scan.</summary>
    static Tally Classify(string file)
    {
        var t = new Tally();
        try
        {
            // 1) trusted signature — read from the file handle, no hash needed
            if (Settings.TrustSkipSigned)
            {
                var trust = TrustService.Evaluate(file);
                if (TrustService.ShouldSkip(trust, Settings.TrustMicrosoftOnly, Settings.TrustPublisherAllowList))
                {
                    t.TrustedSkipped = 1;
                    return t;
                }
                // Valid signature that the "Microsoft only" switch is throwing away — the number that
                // says what relaxing that setting would buy.
                if (trust.Trusted) t.SignedButNotSkipped = 1;
            }

            // 2) folder suppression is path-only
            if (FolderSuppressionStore.Contains(file)) { t.TrustedSkipped = 1; return t; }

            // 3) everything below needs the hash
            long size = 0;
            try { size = new FileInfo(file).Length; } catch (Exception ex) { Log($"Plan: size read failed for '{file}': {ex.Message}", LogLevel.Debug); }
            t.BytesToHash = size;

            var (md5, sha256) = HashService.ComputeAsync(file).GetAwaiter().GetResult();
            if (KnownGoodDb.Contains(md5, sha256)) { t.KnownGood = 1; return t; }
            if (AllowlistStore.Contains(md5, sha256)) { t.Allowlisted = 1; return t; }
            if (Settings.UseLocalHashCache && AppServices.Cache.TryGet(md5, Settings.HashCacheDays, Settings.ThreatCacheDays) != null)
            { t.Cached = 1; return t; }

            if (FileClass.IsWorthUploading(file)) t.NeedsLookupCode = 1; else t.NeedsLookupOther = 1;
        }
        catch (Exception ex)
        {
            Log($"Plan: classifying '{file}' failed: {ex.Message}", LogLevel.Debug);
            t.NeedsLookupOther = 1; // unknown is the honest bucket for a file we could not read
        }
        return t;
    }

    static string Render(Tally t, List<string> missing, TimeSpan elapsed)
    {
        int needs = t.NeedsLookupCode + t.NeedsLookupOther;
        int free = t.TrustedSkipped + t.KnownGood + t.Allowlisted + t.Cached;
        var sb = new StringBuilder();
        sb.AppendLine("Scan plan — " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + $"  (walk + classify took {elapsed.TotalSeconds:F0} s)");
        sb.AppendLine();
        sb.AppendLine($"  files in scope                {t.Total,10:N0}");
        sb.AppendLine($"  over the size cap             {t.Oversize,10:N0}");
        sb.AppendLine($"  targets not found             {missing.Count,10:N0}");
        sb.AppendLine();
        sb.AppendLine("  decided locally, no quota:");
        sb.AppendLine($"    trusted signature           {t.TrustedSkipped,10:N0}");
        sb.AppendLine($"    known-good list             {t.KnownGood,10:N0}");
        sb.AppendLine($"    marked clean by the user    {t.Allowlisted,10:N0}");
        sb.AppendLine($"    already in the cache        {t.Cached,10:N0}");
        sb.AppendLine($"    subtotal                    {free,10:N0}  ({Pct(free, t.Total)})");
        sb.AppendLine();
        sb.AppendLine("  would need VirusTotal:");
        sb.AppendLine($"    code-shaped                 {t.NeedsLookupCode,10:N0}   (lookup, and a submission if unknown)");
        sb.AppendLine($"    other                       {t.NeedsLookupOther,10:N0}   (lookup only under the default upload policy)");
        sb.AppendLine($"    subtotal                    {needs,10:N0}  ({Pct(needs, t.Total)})");
        sb.AppendLine();
        sb.AppendLine($"  bytes to hash                 {FormatBytes(t.BytesToHash),10}");
        sb.AppendLine();

        int keys = AppServices.Vault.Keys.Count(k => !k.Disabled);
        int distinct = AppServices.Vault.Keys.Where(k => !k.Disabled).Select(k => k.Key).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        long perDay = (long)distinct * AppConstants.QuotaPerDay;
        sb.AppendLine($"  usable keys {keys} ({distinct} distinct) → {perDay:N0} lookups a day");
        if (perDay > 0)
            sb.AppendLine($"  at that rate the remaining {needs:N0} lookup(s) take {Math.Ceiling(needs / (double)perDay):N0} day(s) on the API alone.");
        if (t.SignedButNotSkipped > 0)
            sb.AppendLine($"  turning off \"Microsoft only\" would move a further {t.SignedButNotSkipped:N0} validly-signed file(s) into the free bucket.");
        return sb.ToString();
    }

    static string Pct(int part, int total) => total <= 0 ? "0%" : $"{part * 100.0 / total:F1}%";

    static void TryWrite(string report)
    {
        try
        {
            string path = Path.Combine(ConfigPathResolver.DataFolder, "scan-plan-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".txt");
            File.WriteAllText(path, report, new UTF8Encoding(true));
            Console.Error.WriteLine("plan written: " + path);
        }
        catch (Exception ex) { Log("Scan plan write failed: " + ex.Message, LogLevel.Warning); }
    }
}
