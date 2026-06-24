using System.Text.Json;

namespace VirusTotalScanner;

internal sealed class IocRecord
{
    public string Sha256 { get; set; } = "";
    public string? Path { get; set; }
    public bool Malicious { get; set; }
    public List<string> Iocs { get; set; } = [];
}

/// <summary>
/// Persists each file's network IOCs (sandbox DNS hostnames + destination IPs, fetched on demand)
/// and correlates them across files. Shared C2 infrastructure — the same callback domain or IP — is
/// the strongest "same actor / same campaign" signal, and lets a low-detection file that phones the
/// exact server a known-malicious file used be flagged as connected. Pure local, no quota.
/// </summary>
internal static class IocStore
{
    static readonly Dictionary<string, IocRecord> _byHash = new(StringComparer.OrdinalIgnoreCase);
    static bool _loaded;

    static string FilePath => Path.Combine(ConfigPathResolver.ConfigFolder, "ioc-index.json");

    static void Load()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            if (!File.Exists(FilePath)) return;
            var l = JsonSerializer.Deserialize<List<IocRecord>>(File.ReadAllText(FilePath));
            if (l != null) foreach (var r in l) if (!string.IsNullOrEmpty(r.Sha256)) _byHash[r.Sha256] = r;
        }
        catch (Exception ex) { Log("IOC index load failed: " + ex.Message, LogLevel.Warning); }
    }

    static void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigPathResolver.ConfigFolder);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(_byHash.Values.ToList()));
        }
        catch (Exception ex) { Log("IOC index save failed: " + ex.Message, LogLevel.Warning); }
    }

    public static void Record(string? sha256, string? path, bool malicious, IEnumerable<string> iocs)
    {
        Load();
        if (string.IsNullOrWhiteSpace(sha256)) return;
        var clean = iocs.Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => i.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (clean.Count == 0) return;
        _byHash[sha256] = new IocRecord { Sha256 = sha256, Path = path, Malicious = malicious, Iocs = clean };
        Save();
    }

    public sealed record Connection(string Sha256, string? Path, bool Malicious, List<string> Shared);

    public static List<Connection> Connections(string? sha256, IEnumerable<string> iocs)
    {
        Load();
        var mine = new HashSet<string>(iocs.Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => i.Trim()), StringComparer.OrdinalIgnoreCase);
        var result = new List<Connection>();
        if (mine.Count == 0) return result;
        foreach (var r in _byHash.Values)
        {
            if (string.Equals(r.Sha256, sha256, StringComparison.OrdinalIgnoreCase)) continue;
            var shared = r.Iocs.Where(mine.Contains).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (shared.Count > 0) result.Add(new Connection(r.Sha256, r.Path, r.Malicious, shared));
        }
        return result.OrderByDescending(c => c.Malicious).ThenByDescending(c => c.Shared.Count).ToList();
    }
}
