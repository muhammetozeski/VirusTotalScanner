using System.Text.Json;

namespace VirusTotalScanner;

internal sealed class ScanSession
{
    public string[] Paths { get; set; } = [];
    public bool Recurse { get; set; }
    public bool BypassTrust { get; set; }
    public DateTime StartedUtc { get; set; }
}

/// <summary>
/// Persists the root paths of a running scan to scan-session.json (next to the exe) so an
/// interrupted scan can be offered for resume on the next startup. Only written when the user
/// opted in (Settings.ResumeInterruptedScans); cleared when the scan ends normally or is
/// cancelled, so only a crash/kill leaves it behind.
/// </summary>
internal static class ScanSessionStore
{
    static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };
    static string FilePath => Path.Combine(ConfigPathResolver.ConfigFolder, "scan-session.json");

    public static void SaveRunning(IEnumerable<string> paths, bool recurse, bool bypassTrust)
    {
        try
        {
            var s = new ScanSession { Paths = paths.ToArray(), Recurse = recurse, BypassTrust = bypassTrust, StartedUtc = DateTime.UtcNow };
            Directory.CreateDirectory(ConfigPathResolver.ConfigFolder);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(s, Opts));
        }
        catch (Exception ex) { Log("Scan session save failed: " + ex.Message, LogLevel.Warning); }
    }

    public static void Clear()
    {
        try { if (File.Exists(FilePath)) File.Delete(FilePath); }
        catch (Exception ex) { Log("Scan session clear failed: " + ex.Message, LogLevel.Warning); }
    }

    public static ScanSession? TryLoad()
    {
        try { return File.Exists(FilePath) ? JsonSerializer.Deserialize<ScanSession>(File.ReadAllText(FilePath)) : null; }
        catch (Exception ex) { Log("Scan session load failed: " + ex.Message, LogLevel.Warning); return null; }
    }
}
