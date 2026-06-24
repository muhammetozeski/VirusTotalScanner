using System.Diagnostics;
using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>
/// Remembers, per product identity (version-resource ProductName), which Authenticode publisher it
/// was seen signed by. Built passively from every trusted file the scanner clears. When a NEW file
/// claims a product that was previously signed by publisher X but is itself unsigned or signed by
/// someone else, that is a strong trojanized-update / impersonation signal — the dangerous case a
/// plain hash/verdict lookup misses. Local, persisted next to the exe, zero quota.
/// </summary>
internal static class ProductSignerRegistry
{
    static readonly Dictionary<string, string> _map = new(StringComparer.OrdinalIgnoreCase);
    static bool _loaded;

    static string FilePath => Path.Combine(ConfigPathResolver.ConfigFolder, "product-signers.json");

    public static void Load()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            if (!File.Exists(FilePath)) return;
            var d = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(FilePath));
            if (d != null) foreach (var kv in d) _map[kv.Key] = kv.Value;
        }
        catch (Exception ex) { Log("Product-signer registry load failed: " + ex.Message, LogLevel.Warning); }
    }

    static void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigPathResolver.ConfigFolder);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(_map));
        }
        catch (Exception ex) { Log("Product-signer registry save failed: " + ex.Message, LogLevel.Warning); }
    }

    static string? ProductKey(string filePath)
    {
        try
        {
            string? p = FileVersionInfo.GetVersionInfo(filePath).ProductName?.Trim();
            return string.IsNullOrWhiteSpace(p) ? null : p;
        }
        catch { return null; }
    }

    /// <summary>Records (or updates) the publisher a trusted product is signed by.</summary>
    public static void RecordTrusted(string filePath, string? publisher)
    {
        Load();
        if (string.IsNullOrWhiteSpace(publisher)) return;
        string? key = ProductKey(filePath);
        if (key == null) return;
        if (!_map.TryGetValue(key, out var existing) || !string.Equals(existing, publisher, StringComparison.OrdinalIgnoreCase))
        {
            _map[key] = publisher;
            Save();
        }
    }

    /// <summary>A warning if this file's product was previously seen signed by a publisher it no
    /// longer matches; null otherwise.</summary>
    public static string? ContinuityWarning(string filePath, TrustResult trust)
    {
        Load();
        string? key = ProductKey(filePath);
        if (key == null || !_map.TryGetValue(key, out var known) || string.IsNullOrWhiteSpace(known)) return null;
        if (trust.Trusted && string.Equals(trust.Publisher, known, StringComparison.OrdinalIgnoreCase)) return null;
        return $"⚠ '{key}' normalde '{known}' tarafından imzalı; bu dosya {(trust.Trusted ? "farklı yayıncı: " + trust.Publisher : "imzasız/geçersiz")} — olası sahte/trojanlı sürüm";
    }
}
