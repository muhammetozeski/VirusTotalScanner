using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VirusTotalScanner;

internal sealed class LedgerEntry
{
    public string? Sha256 { get; set; }
    public string? Md5 { get; set; }
    public string Verdict { get; set; } = "";
    public int Detections { get; set; }
    public int Total { get; set; }
    public string? ReportUrl { get; set; }
    public DateTime? FirstSeenUtc { get; set; }
    public string? VettedBy { get; set; }
    public DateTime VettedAtUtc { get; set; }
}

internal sealed class Ledger
{
    public string? Machine { get; set; }
    public string? Integrity { get; set; }
    public List<LedgerEntry> Entries { get; set; } = [];
}

/// <summary>
/// A portable, mergeable team verdict ledger over the local cache: export your vetted verdicts to a
/// file a teammate can import, so "we already cleared/flagged this hash" propagates with provenance
/// and a tamper-detection hash — and nobody re-spends quota on a hash someone already vetted. No
/// server, no account; it's a file you share. Pure local read/write over the existing cache model.
/// </summary>
internal static class LedgerService
{
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static int Export(HashCache cache, string path)
    {
        var entries = cache.Snapshot()
            .Where(e => e.Report != null && !string.IsNullOrEmpty(e.Md5))
            .Select(e => new LedgerEntry
            {
                Sha256 = e.Sha256,
                Md5 = e.Md5,
                Verdict = e.Report!.Verdict,
                Detections = e.Detections,
                Total = e.TotalEngines,
                ReportUrl = e.ReportUrl,
                FirstSeenUtc = e.Report.FirstSeenUtc,
                VettedBy = Environment.MachineName,
                VettedAtUtc = e.CachedUtc,
            })
            .ToList();

        var ledger = new Ledger { Machine = Environment.MachineName, Entries = entries, Integrity = Integrity(entries) };
        AtomicFile.WriteAllText(path, JsonSerializer.Serialize(ledger, JsonOpts));
        return entries.Count;
    }

    public static (int Added, int Conflicts, bool IntegrityOk) Import(HashCache cache, string path)
    {
        var ledger = JsonSerializer.Deserialize<Ledger>(File.ReadAllText(path));
        if (ledger == null) return (0, 0, false);
        bool integrityOk = string.Equals(ledger.Integrity, Integrity(ledger.Entries), StringComparison.OrdinalIgnoreCase);

        int added = 0, conflicts = 0;
        foreach (var e in ledger.Entries)
        {
            if (string.IsNullOrEmpty(e.Md5)) continue;
            var existing = cache.TryGet(e.Md5, int.MaxValue);
            if (existing != null) { if (existing.DetectionCount != e.Detections) conflicts++; continue; } // never silently overwrite
            // Seed the local cache so a teammate-vetted hash costs zero lookup for us.
            cache.Put(e.Md5, new VtFileReport
            {
                Sha256 = e.Sha256,
                Md5 = e.Md5,
                Malicious = e.Detections,
                Harmless = Math.Max(0, e.Total - e.Detections),
                FirstSeenUtc = e.FirstSeenUtc,
            });
            added++;
        }
        cache.Flush();
        return (added, conflicts, integrityOk);
    }

    public static (List<string> NewToMe, List<string> Conflicts) Diff(HashCache cache, string path)
    {
        var newToMe = new List<string>();
        var conflicts = new List<string>();
        var ledger = JsonSerializer.Deserialize<Ledger>(File.ReadAllText(path));
        if (ledger == null) return (newToMe, conflicts);
        foreach (var e in ledger.Entries)
        {
            if (string.IsNullOrEmpty(e.Md5)) continue;
            var existing = cache.TryGet(e.Md5, int.MaxValue);
            if (existing == null) newToMe.Add($"{e.Sha256} {e.Verdict} ({e.Detections}/{e.Total})");
            else if (existing.DetectionCount != e.Detections) conflicts.Add($"{e.Sha256}: yerel {existing.DetectionCount} vs onlar {e.Detections}");
        }
        return (newToMe, conflicts);
    }

    static string Integrity(List<LedgerEntry> entries)
    {
        var sb = new StringBuilder();
        foreach (var e in entries.OrderBy(x => x.Sha256, StringComparer.Ordinal))
            sb.Append(e.Sha256).Append('|').Append(e.Detections).Append('\n');
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }
}
