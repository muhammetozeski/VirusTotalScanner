using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>One named snapshot of just the scan-relevant settings.</summary>
internal sealed class ScanProfile
{
    public string Name { get; set; } = "";
    public Dictionary<string, string> Values { get; set; } = new();
}

/// <summary>
/// Named scan profiles: switchable snapshots of only the scan-relevant settings (concurrency, caching,
/// trust-skip, size cap, safe-ext skip, risk ordering), so a power-user can flip between e.g. "deep
/// forensic scan" and "quick downloads check" without toggling the same boxes by hand. Each profile only
/// overwrites its own subset, never the whole config. Atomic JSON, corrupt-backup — modeled on the other
/// stores.
/// </summary>
internal static class ScanProfileStore
{
    static readonly string FilePath = Path.Combine(ConfigPathResolver.DataFolder, "scan-profiles.json");
    static readonly object Lock = new();
    static List<ScanProfile>? _profiles;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    /// <summary>The scan-relevant setting keys a profile captures and applies.</summary>
    public static readonly string[] Keys =
    [
        nameof(Settings.SkipSafeExtensionsOnScan), nameof(Settings.RiskWeightedOrdering),
        nameof(Settings.MaxConcurrentScans), nameof(Settings.MaxConcurrentUploads),
        nameof(Settings.HashCacheDays), nameof(Settings.ThreatCacheDays), nameof(Settings.RecheckPeriodDays),
        nameof(Settings.MaxFileSizeMB), nameof(Settings.TrustSkipSigned), nameof(Settings.TrustMicrosoftOnly),
    ];

    static List<ScanProfile> Profiles { get { lock (Lock) { return _profiles ??= Load(); } } }

    public static IReadOnlyList<ScanProfile> All() { lock (Lock) { return [.. Profiles]; } }

    /// <summary>Save (or overwrite) a profile holding the CURRENT scan-setting values.</summary>
    public static void Save(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        var values = SettingsManager.CaptureSubset(Keys);
        lock (Lock)
        {
            var existing = Profiles.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (existing != null) existing.Values = values;
            else Profiles.Add(new ScanProfile { Name = name.Trim(), Values = values });
            Persist();
        }
    }

    /// <summary>Apply a named profile's captured values. Returns the number of settings applied (0 if missing).</summary>
    public static int Apply(string name)
    {
        ScanProfile? p;
        lock (Lock) { p = Profiles.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase)); }
        return p == null ? 0 : SettingsManager.ApplySubset(p.Values);
    }

    public static void Delete(string name)
    {
        lock (Lock) { Profiles.RemoveAll(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)); Persist(); }
    }

    static List<ScanProfile> Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<List<ScanProfile>>(File.ReadAllText(FilePath)) ?? []; }
        catch (Exception ex) { Log("Scan profiles load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return [];
    }

    static void Persist() // caller holds Lock
    {
        try { Directory.CreateDirectory(ConfigPathResolver.DataFolder); AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_profiles, JsonOpts)); }
        catch (Exception ex) { Log("Scan profiles save failed: " + ex.Message, LogLevel.Warning); }
    }
}
