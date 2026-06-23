namespace VirusTotalScanner;

/// <summary>
/// The set of "major" (high-reputation) antivirus engines, loaded from
/// <see cref="Settings.MajorEnginesList"/>. Used to split a VirusTotal result into major vs
/// minor detections: a few hits from only minor engines usually means a false positive, while
/// any major-engine hit is a strong signal.
/// </summary>
internal static class MajorEngines
{
    static HashSet<string> names = Parse(Settings.MajorEnginesList);

    public static void Load() => names = Parse(Settings.MajorEnginesList);

    public static bool IsMajor(string engineName) =>
        !string.IsNullOrEmpty(engineName) && names.Contains(engineName);

    static HashSet<string> Parse(string csv) =>
        new(csv.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            StringComparer.OrdinalIgnoreCase);
}
