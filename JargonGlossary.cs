namespace VirusTotalScanner;

/// <summary>
/// A tiny static, offline glossary that decodes antivirus jargon in plain Turkish, right where a
/// newcomer meets it: the engine table's Category and Result columns (shown as tooltips). Pure
/// lookup — no network, no key, no lower-layer changes.
/// </summary>
internal static class JargonGlossary
{
    // Properties (not cached fields) so a runtime language switch is reflected in the decoded text.
    static Dictionary<string, string> Categories => new(StringComparer.OrdinalIgnoreCase)
    {
        ["malicious"] = Strings.JcatMalicious,
        ["suspicious"] = Strings.JcatSuspicious,
        ["harmless"] = Strings.JcatHarmless,
        ["undetected"] = Strings.JcatUndetected,
        ["timeout"] = Strings.JcatTimeout,
        ["confirmed-timeout"] = Strings.JcatConfirmedTimeout,
        ["type-unsupported"] = Strings.JcatTypeUnsupported,
        ["failure"] = Strings.JcatFailure,
        ["not-supported"] = Strings.JcatNotSupported,
    };

    // Substring -> plain meaning, scanned over a detection name (e.g. "Trojan.GenericKD.123").
    static (string Needle, string Meaning)[] Morphemes =>
    [
        ("not-a-virus", Strings.JmNotAVirus),
        ("heur", Strings.JmHeur),
        ("generic", Strings.JmGeneric),
        ("gen", Strings.JmGeneric),
        ("trojan", Strings.JmTrojan),
        ("backdoor", Strings.JmBackdoor),
        ("worm", Strings.JmWorm),
        ("ransom", Strings.JmRansom),
        ("downloader", Strings.JmDownloader),
        ("dropper", Strings.JmDropper),
        ("spyware", Strings.JmSpyware),
        ("keylog", Strings.JmKeylog),
        ("rootkit", Strings.JmRootkit),
        ("adware", Strings.JmAdware),
        ("riskware", Strings.JmRiskware),
        ("pua", Strings.JmPua),
        ("pup", Strings.JmPua),
        ("unwanted", Strings.JmUnwanted),
        ("exploit", Strings.JmExploit),
        ("msil", Strings.JmMsil),
        ("win32", Strings.JmWin32),
        ("win64", Strings.JmWin64),
        ("script", Strings.JmScript),
    ];

    public static string Category(string? category) =>
        !string.IsNullOrEmpty(category) && Categories.TryGetValue(category, out var g) ? g : "";

    public static string Result(string? result)
    {
        if (string.IsNullOrWhiteSpace(result)) return "";
        var hits = new List<string>();
        var seen = new HashSet<string>();
        foreach (var (needle, meaning) in Morphemes)
            if (result.Contains(needle, StringComparison.OrdinalIgnoreCase) && seen.Add(meaning))
                hits.Add(meaning);
        return hits.Count == 0 ? "" : string.Join("; ", hits.Take(4));
    }
}
