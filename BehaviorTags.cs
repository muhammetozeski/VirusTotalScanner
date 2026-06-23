namespace VirusTotalScanner;

/// <summary>
/// Turns VirusTotal's capability/behavior tags (and the crowd threat label) — both already present
/// in the file report — into a short plain-language "what this file does" line. No sandbox request:
/// it reads the tags VT attaches to the file object. Especially useful on 0-detection files.
/// </summary>
internal static class BehaviorTags
{
    // Ordered substring -> readable label. First match per tag wins; structural-only tags
    // (peexe, signed, 64bits, overlay…) are intentionally ignored — they are not behavior.
    static readonly (string Needle, string Label)[] Map =
    [
        ("detect-debug", "🐞 hata ayıklayıcı tespiti (anti-analiz)"),
        ("anti-debug", "🐞 anti-debug"),
        ("detect-vm", "🖥 sanal makine tespiti"),
        ("checks-vm", "🖥 sanal makine kontrolü"),
        ("checks-network-adapters", "🌐 ağ adaptörlerini kontrol ediyor"),
        ("checks-cpu", "🔍 CPU/donanım kontrolü"),
        ("checks-bios", "🔍 BIOS kontrolü"),
        ("checks-disk", "🔍 disk kontrolü"),
        ("direct-cpu-clock-access", "⏱ CPU saatine doğrudan erişim"),
        ("long-sleeps", "⏱ uzun bekleme (kum havuzu kaçınma)"),
        ("self-delete", "🗑 kendini siliyor"),
        ("persistence", "📌 kalıcılık (autostart)"),
        ("autorun", "📌 autorun"),
        ("runtime-modules", "🧩 çalışma anında modül yükleme"),
        ("create-process", "⚙ süreç başlatıyor"),
        ("spawn-process", "⚙ alt süreç oluşturuyor"),
        ("registry", "🗝 kayıt defteri değişikliği"),
        ("keylogger", "⌨ tuş kaydı"),
        ("contacts-", "🌐 ağ iletişimi"),
        ("communicates", "🌐 ağ iletişimi"),
        ("network", "🌐 ağ etkinliği"),
        ("obfuscated", "📦 gizlenmiş/obfuscate"),
        ("packed", "📦 paketlenmiş"),
        ("exploit", "💥 exploit"),
        ("powershell", "🔧 PowerShell kullanımı"),
        ("cve-", "💥 bilinen açık (CVE)"),
    ];

    public static string? Summarize(IReadOnlyList<string> tags, string? threatLabel)
    {
        var labels = new List<string>();
        var seen = new HashSet<string>();
        foreach (var tag in tags)
        {
            if (string.IsNullOrWhiteSpace(tag)) continue;
            foreach (var (needle, label) in Map)
            {
                if (tag.Contains(needle, StringComparison.OrdinalIgnoreCase) && seen.Add(label))
                {
                    labels.Add(label);
                    break;
                }
            }
        }

        bool hasLabel = !string.IsNullOrWhiteSpace(threatLabel);
        if (labels.Count == 0 && !hasLabel) return null;

        string head = hasLabel ? $"🧬 Sınıf: {threatLabel}" : "🧬 Davranış";
        return labels.Count > 0 ? $"{head}  •  {string.Join("  •  ", labels.Take(8))}" : head;
    }
}
