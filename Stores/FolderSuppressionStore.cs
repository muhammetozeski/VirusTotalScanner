using System.Text.Json;

namespace VirusTotalScanner;

internal sealed class FolderRule
{
    public string Folder { get; set; } = "";
    public DateTime AddedUtc { get; set; }
    [System.Text.Json.Serialization.JsonIgnore] public DateTime AddedLocal => AddedUtc.ToLocalTime();
}

/// <summary>
/// Path-prefix suppression (folder-allowlist.json): files under a registered folder are skipped, the only
/// mechanism that covers a developer's build output — where every recompile produces a brand-new hash the
/// hash-keyed <see cref="AllowlistStore"/> structurally cannot keep up with. Atomic writes; corrupt-backup.
/// </summary>
internal static class FolderSuppressionStore
{
    static readonly string FilePath = System.IO.Path.Combine(ConfigPathResolver.DataFolder, "folder-allowlist.json");
    static readonly object Lock = new();
    static List<FolderRule>? _rules;
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static event Action? Changed;

    static List<FolderRule> Rules { get { lock (Lock) { return _rules ??= Load(); } } }
    public static int Count { get { lock (Lock) { return Rules.Count; } } }
    public static IReadOnlyList<FolderRule> All() { lock (Lock) { return [.. Rules]; } }

    /// <summary>True if the file lives under any registered folder.</summary>
    public static bool Contains(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return false;
        string full = filePath.Replace('/', '\\');
        lock (Lock)
        {
            if (Rules.Count == 0) return false;
            return Rules.Any(r => !string.IsNullOrEmpty(r.Folder) && full.StartsWith(WithSep(r.Folder), StringComparison.OrdinalIgnoreCase));
        }
    }

    static string WithSep(string folder) { folder = folder.Replace('/', '\\'); return folder.EndsWith('\\') ? folder : folder + "\\"; }

    public static bool Add(string? folder)
    {
        if (string.IsNullOrWhiteSpace(folder)) return false;
        folder = folder.TrimEnd('\\', '/');
        lock (Lock)
        {
            if (Rules.Any(r => string.Equals(r.Folder, folder, StringComparison.OrdinalIgnoreCase))) return false;
            Rules.Add(new FolderRule { Folder = folder, AddedUtc = DateTime.UtcNow });
            Save();
        }
        Changed?.Invoke();
        return true;
    }

    public static void Remove(string? folder)
    {
        if (string.IsNullOrEmpty(folder)) return;
        lock (Lock) { if (Rules.RemoveAll(r => string.Equals(r.Folder, folder, StringComparison.OrdinalIgnoreCase)) == 0) return; Save(); }
        Changed?.Invoke();
    }

    static List<FolderRule> Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<List<FolderRule>>(File.ReadAllText(FilePath)) ?? []; }
        catch (Exception ex) { Log("Folder allowlist load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
        return [];
    }

    static void Save() // caller holds Lock
    {
        try { Directory.CreateDirectory(ConfigPathResolver.DataFolder); AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_rules, JsonOpts)); }
        catch (Exception ex) { Log("Folder allowlist save failed: " + ex.Message, LogLevel.Warning); }
    }
}
