using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>One plain-Turkish "so what" line distilled from sandbox behaviour. <see cref="Alarm"/> marks
/// the genuinely scary ones (e.g. persistence) so the UI can colour them.</summary>
internal sealed record DigestLine(string Icon, string Text, bool Alarm, IReadOnlyList<string>? Details = null);

internal sealed class BehaviourDigest
{
    public List<DigestLine> Lines { get; set; } = [];
    public bool Any => Lines.Count > 0;
}

/// <summary>Turns raw sandbox behaviour into the one question a non-expert actually has — "what happens to
/// MY PC if I run this" — by grouping the actions into risk buckets and labelling each with its
/// consequence (connects out, drops files, writes a persistence key that survives reboot, starts
/// processes). Digests are cached by sha256 so reopening from history never re-scrapes.</summary>
internal static class BehaviourDigestBuilder
{
    // Registry locations that mean "this runs again after a reboot".
    static readonly string[] PersistMarkers =
        ["\\run", "\\runonce", "currentversion\\run", "userinit", "winlogon", "\\services\\", "\\startup", "image file execution"];

    public static BehaviourDigest Build(VtBehaviour b)
    {
        var d = new BehaviourDigest();
        if (b.Network.Count > 0)
            d.Lines.Add(new("🌐", $"{b.Network.Count} ağ adresine/sunucuya bağlanıyor", false, b.Network.Take(8).ToList()));
        if (b.FilesWritten.Count > 0)
            d.Lines.Add(new("📄", $"{b.FilesWritten.Count} dosya yazıyor/bırakıyor", false, b.FilesWritten.Take(8).ToList()));

        var persistKeys = b.Registry.Where(r => PersistMarkers.Any(m => (r ?? "").ToLowerInvariant().Contains(m))).ToList();
        if (persistKeys.Count > 0)
            d.Lines.Add(new("⛔", "Otomatik başlatma/kalıcılık anahtarı yazıyor — yeniden başlatmada hayatta kalır", true, persistKeys.Take(8).ToList()));
        else if (b.Registry.Count > 0)
            d.Lines.Add(new("🔧", $"{b.Registry.Count} kayıt defteri anahtarı değiştiriyor", false, b.Registry.Take(8).ToList()));

        if (b.Processes.Count > 0)
            d.Lines.Add(new("⚙", $"{b.Processes.Count} başka süreç başlatıyor", false, b.Processes.Take(8).ToList()));

        // Decode MITRE technique ids into plain-Turkish statements grouped by tactic, instead of a bare count.
        foreach (var (tactic, meanings) in MitreGlossary.Decode(b.Mitre))
            d.Lines.Add(new("🎯", $"{tactic}: {string.Join("; ", meanings)}", MitreGlossary.IsAlarmTactic(tactic)));

        if (d.Lines.Count == 0)
            d.Lines.Add(new("✓", "Kayda değer bir sistem etkisi gözlenmedi", false));
        return d;
    }
}

/// <summary>sha256 → digest cache (behaviour-digest.json) so reopening a file from history doesn't
/// re-scrape its sandbox report. Mirrors the other JSON stores: atomic writes, corrupt-file backup.</summary>
internal static class BehaviourDigestCache
{
    static readonly string FilePath = System.IO.Path.Combine(ConfigPathResolver.DataFolder, "behaviour-digest.json");
    static readonly object Lock = new();
    static Dictionary<string, BehaviourDigest>? _map;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    static Dictionary<string, BehaviourDigest> Map { get { lock (Lock) { return _map ??= Load(); } } }

    public static BehaviourDigest? TryGet(string? sha256)
    {
        if (string.IsNullOrEmpty(sha256)) return null;
        lock (Lock) { return Map.TryGetValue(sha256, out var d) ? d : null; }
    }

    public static void Put(string? sha256, BehaviourDigest digest)
    {
        if (string.IsNullOrEmpty(sha256)) return;
        lock (Lock) { Map[sha256] = digest; Save(); }
    }

    static Dictionary<string, BehaviourDigest> Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<Dictionary<string, BehaviourDigest>>(File.ReadAllText(FilePath)) ?? new(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) { Log("Behaviour digest cache load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return new(StringComparer.OrdinalIgnoreCase);
    }

    static void Save() // caller holds Lock
    {
        try { Directory.CreateDirectory(ConfigPathResolver.DataFolder); AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_map, JsonOpts)); }
        catch (Exception ex) { Log("Behaviour digest cache save failed: " + ex.Message, LogLevel.Warning); }
    }
}
