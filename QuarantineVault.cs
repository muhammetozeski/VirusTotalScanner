using System.Text.Json;

namespace VirusTotalScanner;

internal sealed class QuarantineEntry
{
    public string Id { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public string? Sha256 { get; set; }
    public string? Md5 { get; set; }
    public string Verdict { get; set; } = "";
    public int Detections { get; set; }
    public int Total { get; set; }
    public DateTime QuarantinedUtc { get; set; }
    public string? Origin { get; set; }

    public string FileName => Path.GetFileName(OriginalPath);
}

/// <summary>
/// Reversible quarantine: each quarantined file moves to the quarantine folder under a collision-safe
/// id name, and a JSON manifest records its original path, hashes, verdict-at-quarantine, time and
/// download origin. Restore moves it back to its exact original path. A scanner that flags files will
/// produce false positives, so a one-way bin is wrong — this closes the loop.
/// </summary>
internal static class QuarantineVault
{
    static readonly List<QuarantineEntry> _entries = [];
    static bool _loaded;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    static string Folder => ConfigPathResolver.QuarantineFolder;
    static string ManifestPath => Path.Combine(Folder, "manifest.json");
    static string VaultFile(string id) => Path.Combine(Folder, id + ".VIRUS");

    static void Load()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            if (!File.Exists(ManifestPath)) return;
            var l = JsonSerializer.Deserialize<List<QuarantineEntry>>(File.ReadAllText(ManifestPath));
            if (l != null) _entries.AddRange(l);
        }
        catch (Exception ex) { Log("Quarantine manifest load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(ManifestPath); }
    }

    static void Save()
    {
        try
        {
            Directory.CreateDirectory(Folder);
            AtomicFile.WriteAllText(ManifestPath, JsonSerializer.Serialize(_entries, JsonOpts));
        }
        catch (Exception ex) { Log("Quarantine manifest save failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Moves a file into the vault and records a restorable manifest entry.</summary>
    public static bool Quarantine(string path, VtFileReport? report, string? sha256, string? md5, out string? error)
    {
        Load();
        error = null;
        try
        {
            Directory.CreateDirectory(Folder);
            string? origin = null;
            try { origin = ZoneIdentifier.Read(path)?.HostUrl; } catch { }

            string id = Guid.NewGuid().ToString("N")[..12];
            File.Move(path, VaultFile(id), overwrite: true);

            _entries.Add(new QuarantineEntry
            {
                Id = id,
                OriginalPath = path,
                Sha256 = sha256 ?? report?.Sha256,
                Md5 = md5 ?? report?.Md5,
                Verdict = report?.Verdict ?? "",
                Detections = report?.DetectionCount ?? 0,
                Total = report?.TotalEngines ?? 0,
                QuarantinedUtc = DateTime.UtcNow,
                Origin = origin,
            });
            Save();
            Log($"Quarantined to vault: {path} -> {id}.VIRUS", LogLevel.Warning);
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    public static IReadOnlyList<QuarantineEntry> List()
    {
        Load();
        return _entries.OrderByDescending(e => e.QuarantinedUtc).ToList();
    }

    /// <summary>Moves a held file back to its exact original path and drops the manifest entry.</summary>
    public static bool Restore(QuarantineEntry e, out string? error)
    {
        Load();
        error = null;
        try
        {
            string src = VaultFile(e.Id);
            if (!File.Exists(src)) { error = "Kasa dosyası bulunamadı."; return false; }
            if (File.Exists(e.OriginalPath)) { error = "Orijinal konumda zaten bir dosya var."; return false; }

            string? dir = Path.GetDirectoryName(e.OriginalPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.Move(src, e.OriginalPath, overwrite: false);

            _entries.RemoveAll(x => x.Id == e.Id);
            Save();
            Log($"Restored from vault: {e.Id} -> {e.OriginalPath}", LogLevel.Info);
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    /// <summary>Permanently delete a held .VIRUS file and drop its manifest entry — the destructive final
    /// step of remediation (the caller must confirm; this is irreversible).</summary>
    public static bool Purge(QuarantineEntry e, out string? error)
    {
        Load();
        error = null;
        try
        {
            string src = VaultFile(e.Id);
            if (File.Exists(src)) File.Delete(src);
            _entries.RemoveAll(x => x.Id == e.Id);
            Save();
            Log($"Purged from vault: {e.Id} ({e.FileName})", LogLevel.Info);
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    /// <summary>Permanently delete every entry older than <paramref name="days"/>. Returns the count purged.</summary>
    public static int PurgeOlderThan(int days)
    {
        Load();
        if (days <= 0) return 0;
        var cutoff = DateTime.UtcNow.AddDays(-days);
        int n = 0;
        foreach (var e in _entries.Where(x => x.QuarantinedUtc < cutoff).ToList())
        {
            try { var src = VaultFile(e.Id); if (File.Exists(src)) File.Delete(src); _entries.Remove(e); n++; }
            catch (Exception ex) { Log($"Purge failed for {e.Id}: {ex.Message}", LogLevel.Warning); }
        }
        if (n > 0) { Save(); Log($"Retention purge removed {n} vault entr(ies) older than {days}d.", LogLevel.Info); }
        return n;
    }

    /// <summary>Total on-disk size of the held .VIRUS files — the space a full purge would reclaim.</summary>
    public static long ReclaimableBytes()
    {
        Load();
        long total = 0;
        foreach (var e in _entries)
            try { var f = VaultFile(e.Id); if (File.Exists(f)) total += new FileInfo(f).Length; } catch { }
        return total;
    }
}
