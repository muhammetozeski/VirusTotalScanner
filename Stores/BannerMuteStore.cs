using System.Text.Json;

namespace VirusTotalScanner;

internal sealed class MutedThreat
{
    public string? Md5 { get; set; }
    public string? Sha256 { get; set; }
    public string Name { get; set; } = "";
    public DateTime MutedUtc { get; set; }
}

/// <summary>
/// Hashes the user told the overview banner to stop announcing (banner-mutes.json). Muting is NOT the
/// allowlist: the file keeps its threat verdict everywhere else and stays listed in the history tab —
/// only the full-width "a known threat is still on disk" banner stops re-raising this one file on every
/// launch. Atomic writes; corrupt-backup.
/// </summary>
internal static class BannerMuteStore
{
    static readonly string FilePath = Path.Combine(ConfigPathResolver.DataFolder, "banner-mutes.json");
    static readonly object Lock = new();
    static List<MutedThreat>? _muted;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static event Action? Changed;

    static List<MutedThreat> Muted { get { lock (Lock) { return _muted ??= Load(); } } }
    public static int Count { get { lock (Lock) { return Muted.Count; } } }

    /// <summary>True when either hash of the file was muted. A file with no hash at all can never be
    /// muted, so it keeps warning rather than being silenced by an empty match.</summary>
    public static bool Contains(string? md5, string? sha256)
    {
        if (string.IsNullOrEmpty(md5) && string.IsNullOrEmpty(sha256)) return false;
        lock (Lock)
        {
            return Muted.Any(m =>
                (!string.IsNullOrEmpty(md5) && string.Equals(m.Md5, md5, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(sha256) && string.Equals(m.Sha256, sha256, StringComparison.OrdinalIgnoreCase)));
        }
    }

    public static bool Add(string? md5, string? sha256, string name)
    {
        if (string.IsNullOrEmpty(md5) && string.IsNullOrEmpty(sha256)) return false;
        lock (Lock)
        {
            if (Contains(md5, sha256)) return false;
            Muted.Add(new MutedThreat { Md5 = md5, Sha256 = sha256, Name = name, MutedUtc = DateTime.UtcNow });
            Save();
        }
        Changed?.Invoke();
        return true;
    }

    /// <summary>Un-mutes everything and returns how many were cleared, so the banner can warn again.</summary>
    public static int ClearAll()
    {
        int n;
        lock (Lock)
        {
            n = Muted.Count;
            if (n == 0) return 0;
            Muted.Clear();
            Save();
        }
        Changed?.Invoke();
        return n;
    }

    static List<MutedThreat> Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<List<MutedThreat>>(File.ReadAllText(FilePath)) ?? []; }
        catch (Exception ex) { Log("Banner mute list load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return [];
    }

    static void Save() // caller holds Lock
    {
        try { Directory.CreateDirectory(ConfigPathResolver.DataFolder); AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_muted, JsonOpts)); }
        catch (Exception ex) { Log("Banner mute list save failed: " + ex.Message, LogLevel.Warning); }
    }
}
