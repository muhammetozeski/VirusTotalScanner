using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>One file the user has explicitly vouched is clean (a false-positive they recognize, their
/// own niche tool, a packed game launcher…). Keyed by hash so it survives moves/renames.</summary>
internal sealed class AllowlistEntry
{
    public string Hash { get; set; } = "";   // sha256 preferred, else md5
    public string? Md5 { get; set; }
    public string FileName { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTime AddedUtc { get; set; }
    public int DetectionCountAtAdd { get; set; }
    public DateTime LastVerifiedUtc { get; set; }
    public bool IsStale { get; set; } // re-validation found this once-clean hash is now flagged

    [System.Text.Json.Serialization.JsonIgnore] public DateTime AddedLocal => AddedUtc.ToLocalTime();
    [System.Text.Json.Serialization.JsonIgnore] public string Health => IsStale ? "⚠ ARTIK İŞARETLİ" : (LastVerifiedUtc == default ? "denetlenmedi" : "temiz");
}

/// <summary>
/// User-writable allowlist (allowlist.json): files the user marked "this is clean" from inside the app,
/// so they stop being re-flagged on every scan. Unlike <see cref="KnownGoodDb"/> (a read-only external
/// hash file the user points at), this one is editable in-app. A hit makes the scheduler skip the lookup
/// with a "user said clean" reason. Thread-safe; atomic writes; best-effort.
/// </summary>
internal static class AllowlistStore
{
    static readonly string FilePath = System.IO.Path.Combine(ConfigPathResolver.DataFolder, "allowlist.json");
    static readonly object Lock = new();
    static List<AllowlistEntry>? _entries;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static event Action? Changed;

    static List<AllowlistEntry> Entries { get { lock (Lock) { return _entries ??= Load(); } } }

    public static int Count { get { lock (Lock) { return Entries.Count; } } }
    public static IReadOnlyList<AllowlistEntry> All() { lock (Lock) { return [.. Entries]; } }

    /// <summary>True if either hash is on the list (md5 or sha256).</summary>
    public static bool Contains(string? md5, string? sha256)
    {
        lock (Lock)
        {
            if (Entries.Count == 0) return false;
            return Entries.Any(e =>
                (!string.IsNullOrEmpty(sha256) && (string.Equals(e.Hash, sha256, StringComparison.OrdinalIgnoreCase) || string.Equals(e.Md5, sha256, StringComparison.OrdinalIgnoreCase)))
                || (!string.IsNullOrEmpty(md5) && (string.Equals(e.Hash, md5, StringComparison.OrdinalIgnoreCase) || string.Equals(e.Md5, md5, StringComparison.OrdinalIgnoreCase))));
        }
    }

    /// <summary>Add (or update the reason for) a file the user vouched is clean. Returns false if the
    /// item has no hash to key on.</summary>
    public static bool Add(ScanItem item, string reason)
    {
        if (item == null) return false;
        string? hash = !string.IsNullOrEmpty(item.Sha256) ? item.Sha256 : item.Md5;
        if (string.IsNullOrEmpty(hash)) return false;
        lock (Lock)
        {
            var existing = Entries.FirstOrDefault(e => string.Equals(e.Hash, hash, StringComparison.OrdinalIgnoreCase));
            if (existing != null) { existing.Reason = reason; existing.FileName = item.FileName; }
            else Entries.Add(new AllowlistEntry { Hash = hash, Md5 = item.Md5, FileName = item.FileName, Reason = reason, AddedUtc = DateTime.UtcNow, DetectionCountAtAdd = item.Report?.DetectionCount ?? 0 });
            Save();
        }
        Changed?.Invoke();
        return true;
    }

    /// <summary>Re-query every allowlisted hash keyless (zero quota). A once-clean hash that VirusTotal now
    /// flags is marked stale (NOT deleted — the skip keeps working until the user acts), so the
    /// noise-reduction list can't silently become a permanent blind spot for a later-compromised build.</summary>
    public static async Task<List<AllowlistEntry>> CheckHealthAsync(Action<int, int>? progress = null, CancellationToken ct = default)
    {
        var newlyStale = new List<AllowlistEntry>();
        if (!(Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable)) return newlyStale;
        var snapshot = All(); // entry references are shared with the live list, so field writes persist
        int done = 0;
        foreach (var e in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            string? hash = !string.IsNullOrEmpty(e.Hash) ? e.Hash : e.Md5;
            if (!string.IsNullOrEmpty(hash))
            {
                try
                {
                    var r = await GuiScrapeService.LookupAsync(hash, ct);
                    e.LastVerifiedUtc = DateTime.UtcNow;
                    if (r != null && VerdictCategories.IsThreat(r.DetectionCount) && !e.IsStale) { e.IsStale = true; newlyStale.Add(e); }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { Log("Allowlist health check failed for " + e.FileName + ": " + ex.Message, LogLevel.Warning); }
            }
            progress?.Invoke(++done, snapshot.Count);
        }
        lock (Lock) { Save(); }
        Changed?.Invoke();
        return newlyStale;
    }

    /// <summary>Clear the stale flag (the user reviewed it and chose to keep trusting the file).</summary>
    public static void MarkReviewed(string? hash)
    {
        if (string.IsNullOrEmpty(hash)) return;
        lock (Lock)
        {
            var e = Entries.FirstOrDefault(x => string.Equals(x.Hash, hash, StringComparison.OrdinalIgnoreCase));
            if (e == null || !e.IsStale) return;
            e.IsStale = false; Save();
        }
        Changed?.Invoke();
    }

    /// <summary>One-pass bulk seed: add every clean (0-detection, hashed) file from the scan history that
    /// isn't already listed, so the user can fill the allowlist without one right-click at a time.</summary>
    public static int ImportCleanFromHistory()
    {
        int added = 0;
        lock (Lock)
        {
            foreach (var h in ScanHistoryStore.All().Where(e => e.Detections == 0 && !string.IsNullOrEmpty(e.Sha256)))
            {
                if (Entries.Any(x => string.Equals(x.Hash, h.Sha256, StringComparison.OrdinalIgnoreCase))) continue;
                Entries.Add(new AllowlistEntry { Hash = h.Sha256!, Md5 = h.Md5, FileName = h.Name, Reason = "Geçmişten içe aktarıldı (temiz)", AddedUtc = DateTime.UtcNow, LastVerifiedUtc = h.WhenUtc });
                added++;
            }
            if (added > 0) Save();
        }
        if (added > 0) Changed?.Invoke();
        return added;
    }

    public static void Remove(string? hash)
    {
        if (string.IsNullOrEmpty(hash)) return;
        lock (Lock) { if (Entries.RemoveAll(e => string.Equals(e.Hash, hash, StringComparison.OrdinalIgnoreCase)) == 0) return; Save(); }
        Changed?.Invoke();
    }

    static List<AllowlistEntry> Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<List<AllowlistEntry>>(File.ReadAllText(FilePath)) ?? []; }
        catch (Exception ex) { Log("Allowlist load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return [];
    }

    static void Save() // caller holds Lock
    {
        try { Directory.CreateDirectory(ConfigPathResolver.DataFolder); AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_entries, JsonOpts)); }
        catch (Exception ex) { Log("Allowlist save failed: " + ex.Message, LogLevel.Warning); }
    }
}
