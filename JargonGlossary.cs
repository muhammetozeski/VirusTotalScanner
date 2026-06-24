namespace VirusTotalScanner;

/// <summary>
/// A tiny static, offline glossary that decodes antivirus jargon in plain Turkish, right where a
/// newcomer meets it: the engine table's Category and Result columns (shown as tooltips). Pure
/// lookup — no network, no key, no lower-layer changes.
/// </summary>
internal static class JargonGlossary
{
    static readonly Dictionary<string, string> Categories = new(StringComparer.OrdinalIgnoreCase)
    {
        ["malicious"] = "Zararlı buldu",
        ["suspicious"] = "Şüpheli buldu (kesin değil)",
        ["harmless"] = "Zararsız (temiz) buldu",
        ["undetected"] = "Hiçbir şey bulamadı (temiz)",
        ["timeout"] = "Zaman aşımı — tarayamadı",
        ["confirmed-timeout"] = "Kesin zaman aşımı — tarayamadı",
        ["type-unsupported"] = "Bu dosya türünü taramıyor",
        ["failure"] = "Tarama başarısız oldu",
        ["not-supported"] = "Desteklenmiyor",
    };

    // Substring -> plain meaning, scanned over a detection name (e.g. "Trojan.GenericKD.123").
    static readonly (string Needle, string Meaning)[] Morphemes =
    [
        ("not-a-virus", "virüs değil (genelde araç/reklam)"),
        ("heur", "sezgisel/tahmini imza (kesin değil)"),
        ("generic", "genel imza (kesin değil)"),
        ("gen", "genel imza (kesin değil)"),
        ("trojan", "truva atı"),
        ("backdoor", "arka kapı"),
        ("worm", "solucan (kendini yayar)"),
        ("ransom", "fidye yazılımı"),
        ("downloader", "başka zararlı indirir"),
        ("dropper", "başka zararlı bırakır"),
        ("spyware", "casus yazılım"),
        ("keylog", "tuş kaydedici"),
        ("rootkit", "gizlenen zararlı (rootkit)"),
        ("adware", "reklam yazılımı"),
        ("riskware", "riskli ama meşru olabilir"),
        ("pua", "istenmeyen program (zararlı olmayabilir)"),
        ("pup", "istenmeyen program (zararlı olmayabilir)"),
        ("unwanted", "istenmeyen program"),
        ("exploit", "açık sömüren (exploit)"),
        ("msil", ".NET programı"),
        ("win32", "Windows 32-bit"),
        ("win64", "Windows 64-bit"),
        ("script", "betik (script)"),
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
