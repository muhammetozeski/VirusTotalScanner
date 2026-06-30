namespace VirusTotalScanner;

/// <summary>
/// Boils the noisy per-engine detection strings (e.g. "Trojan/Win32.Swrort",
/// "Backdoor.Generic.aoiq", "ti!3572D3...") down to a single most-common malware family token.
/// Different vendors name the same thing differently; the shared core token (here "Swrort") is
/// the useful "what is this" signal. Heuristic, best-effort.
/// </summary>
internal static class DetectionFamily
{
    // Type/platform/heuristic noise tokens that are never the family name.
    static readonly HashSet<string> Noise = new(StringComparer.OrdinalIgnoreCase)
    {
        "trojan", "backdoor", "worm", "virus", "malware", "riskware", "adware", "pup", "pua",
        "spyware", "ransom", "ransomware", "downloader", "dropper", "exploit", "rootkit", "hacktool",
        "win32", "win64", "w32", "w64", "msil", "script", "html", "android", "linux", "macos", "osx",
        "generic", "gen", "genericrl", "heur", "heuristic", "ml", "ai", "ti", "bscope", "variant",
        "application", "unwanted", "suspicious", "susgen", "susp", "agent", "a", "b", "c", "test",
        "behaveslike", "trj", "troj", "program", "potentially", "unsafe", "cloud", "static", "based",
        "malicious", "unsafe", "detected", "detection", "threat", "confidence", "moderate", "high",
        "probably", "header", "headerp", "aidetect", "malware2", "generic", "genericrl", "genericml",
    };

    /// <summary>The dominant family across the detecting engines, with how many engines agree,
    /// or null when nothing meaningful survives normalization.</summary>
    public static (string Family, int Count)? MostCommon(IEnumerable<VtEngineResult> detections)
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in detections)
        {
            string? token = ExtractFamily(d.Result);
            if (token == null) continue;
            counts[token] = counts.GetValueOrDefault(token) + 1;
        }
        if (counts.Count == 0) return null;
        var best = counts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).First();
        return (best.Key, best.Value);
    }

    /// <summary>Pulls the most likely family token out of one detection string.</summary>
    static string? ExtractFamily(string? result)
    {
        if (string.IsNullOrWhiteSpace(result)) return null;
        var tokens = result.Split(['.', '/', ':', '!', '\\', ' ', '-', '(', ')', '[', ']'],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        // Prefer the first alphabetic token that is not noise and not a short hex/number fragment.
        foreach (var t in tokens)
        {
            if (t.Length < 4) continue;
            if (Noise.Contains(t)) continue;
            if (IsHexOrNumeric(t)) continue;
            // Strip a trailing short variant suffix the family rarely needs (e.g. ".aoiq").
            return Capitalize(t);
        }
        return null;
    }

    static bool IsHexOrNumeric(string s)
    {
        bool anyLetter = false;
        foreach (char c in s)
        {
            if (!Uri.IsHexDigit(c)) { if (!char.IsLetterOrDigit(c)) return true; }
            if (char.IsLetter(c)) anyLetter = true;
        }
        // All-hex (like "3572D3") or no letters at all -> not a family.
        bool allHex = s.All(Uri.IsHexDigit);
        return allHex || !anyLetter;
    }

    static string Capitalize(string s) =>
        s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..].ToLowerInvariant();
}
