using System.Text.Json;

namespace VirusTotalScanner;

internal enum AutoActionKind { ToastOnly, MarkClean, SuppressFolder, Quarantine }

/// <summary>One post-scan rule: fixed condition fields (no expression language) + an action. First matching
/// rule wins.</summary>
internal sealed class AutoActionRule
{
    public bool BackgroundOnly { get; set; } = true;   // only background catches (watcher/USB), not manual scans
    public int MinDetections { get; set; }             // 0 = any
    public bool RequireFromInternet { get; set; }      // file must carry a Zone.Identifier internet mark
    public int MinLevel { get; set; }                  // 0=any, 1=Caution, 2=Remove (RecommendationService.Level)
    public string FolderPrefix { get; set; } = "";     // empty = any folder
    public AutoActionKind Action { get; set; } = AutoActionKind.ToastOnly;
}

/// <summary>
/// User-defined post-scan auto-action rules (auto-actions.json). The single hidden fixed rule in
/// OnThreatFound (background + DetectionCount threshold → quarantine) becomes one configurable layer: an
/// ordered list evaluated first-match-wins. Empty list ⇒ the built-in behavior is untouched (backward
/// compatible). All conditions and actions reuse signals/paths the app already has — no new remediation
/// logic. Atomic writes; corrupt-backup — modeled on <see cref="FolderSuppressionStore"/>.
/// </summary>
internal static class AutoActionStore
{
    static readonly string FilePath = System.IO.Path.Combine(ConfigPathResolver.DataFolder, "auto-actions.json");
    static readonly object Lock = new();
    static List<AutoActionRule>? _rules;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static event Action? Changed;

    static List<AutoActionRule> Rules { get { lock (Lock) { return _rules ??= Load(); } } }
    public static int Count { get { lock (Lock) { return Rules.Count; } } }
    public static IReadOnlyList<AutoActionRule> All() { lock (Lock) { return [.. Rules]; } }

    /// <summary>The first rule whose conditions all hold, or null. Order is the rule list's order.</summary>
    public static AutoActionRule? FirstMatch(bool background, int detections, bool fromInternet, int level, string? path)
    {
        string p = (path ?? "").Replace('/', '\\');
        lock (Lock)
        {
            if (Rules.Count == 0) return null;
            return Rules.FirstOrDefault(r =>
                (!r.BackgroundOnly || background)
                && detections >= r.MinDetections
                && (!r.RequireFromInternet || fromInternet)
                && level >= r.MinLevel
                && (string.IsNullOrEmpty(r.FolderPrefix) || p.StartsWith(r.FolderPrefix.Replace('/', '\\'), StringComparison.OrdinalIgnoreCase)));
        }
    }

    /// <summary>Replace the whole ordered rule set (from the settings editor).</summary>
    public static void Replace(IEnumerable<AutoActionRule> rules)
    {
        lock (Lock) { _rules = [.. rules]; Save(); }
        Changed?.Invoke();
    }

    static List<AutoActionRule> Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<List<AutoActionRule>>(File.ReadAllText(FilePath)) ?? []; }
        catch (Exception ex) { Log("Auto-actions load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return [];
    }

    static void Save() // caller holds Lock
    {
        try { Directory.CreateDirectory(ConfigPathResolver.DataFolder); AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_rules, JsonOpts)); }
        catch (Exception ex) { Log("Auto-actions save failed: " + ex.Message, LogLevel.Warning); }
    }
}
