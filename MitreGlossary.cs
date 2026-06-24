using System.Text.RegularExpressions;

namespace VirusTotalScanner;

/// <summary>Offline decoder for MITRE ATT&CK technique ids → plain-Turkish "what it means", grouped by
/// tactic. Turns the jargon ids in a sandbox report into statements a non-expert can read. Mirrors the
/// shipped <see cref="JargonGlossary"/> pattern: pure local lookup, no quota.</summary>
internal static class MitreGlossary
{
    // technique id (base, no sub-technique suffix) → (tactic heading, one-sentence meaning)
    static readonly Dictionary<string, (string Tactic, string Meaning)> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        ["T1547"] = ("Kalıcılığı sağlama", "Windows açılışta kendini otomatik başlatacak şekilde yerleşiyor"),
        ["T1053"] = ("Kalıcılığı sağlama", "Zamanlanmış görev oluşturarak kalıcı oluyor"),
        ["T1543"] = ("Kalıcılığı sağlama", "Bir sistem servisi kurarak kalıcı oluyor"),
        ["T1546"] = ("Kalıcılığı sağlama", "Bir olay tetikleyicisine kendini bağlıyor (açılışta çalışır)"),
        ["T1055"] = ("Savunmayı atlatma", "Kendini başka bir sürecin içine enjekte ediyor (gizlenme)"),
        ["T1027"] = ("Savunmayı atlatma", "Kodunu gizliyor/şifreliyor, analizden kaçıyor"),
        ["T1112"] = ("Savunmayı atlatma", "Kayıt defterini değiştiriyor"),
        ["T1070"] = ("Savunmayı atlatma", "İzlerini siliyor (log/dosya temizleme)"),
        ["T1562"] = ("Savunmayı atlatma", "Güvenlik araçlarını/korumaları devre dışı bırakmaya çalışıyor"),
        ["T1497"] = ("Savunmayı atlatma", "Sanal makine/sandbox tespit edip davranışını gizliyor"),
        ["T1486"] = ("Etki", "Dosyaları şifreleyip fidye isteyebilir (ransomware)"),
        ["T1490"] = ("Etki", "Sistem kurtarmayı engelliyor (gölge kopyaları siliyor)"),
        ["T1489"] = ("Etki", "Servisleri durduruyor"),
        ["T1071"] = ("Komuta-kontrol", "Uzak bir sunucuyla ağ üzerinden haberleşiyor"),
        ["T1105"] = ("Komuta-kontrol", "İnternetten ek dosya/yük indiriyor"),
        ["T1095"] = ("Komuta-kontrol", "Standart olmayan bir protokolle dışarı bağlanıyor"),
        ["T1041"] = ("Veri sızdırma", "Veriyi komuta kanalı üzerinden dışarı çıkarıyor"),
        ["T1056"] = ("Kimlik bilgisi çalma", "Klavye girişlerini kaydedebiliyor (keylogger)"),
        ["T1003"] = ("Kimlik bilgisi çalma", "Sistemden parola/kimlik bilgisi çıkarmaya çalışıyor"),
        ["T1059"] = ("Çalıştırma", "Komut satırı/script ile komut çalıştırıyor"),
        ["T1204"] = ("Çalıştırma", "Kullanıcının dosyayı açmasıyla çalışıyor"),
        ["T1082"] = ("Keşif", "Sistem bilgilerini topluyor"),
        ["T1083"] = ("Keşif", "Dosya ve dizinleri tarıyor"),
        ["T1057"] = ("Keşif", "Çalışan süreçleri listeliyor"),
        ["T1518"] = ("Keşif", "Yüklü güvenlik yazılımlarını araştırıyor"),
        ["T1016"] = ("Keşif", "Ağ yapılandırmasını inceliyor"),
        ["T1021"] = ("Yatay hareket", "Ağdaki diğer makinelere yayılmaya çalışıyor"),
        ["T1036"] = ("Savunmayı atlatma", "Meşru bir dosya gibi görünmeye çalışıyor (masquerading)"),
    };

    static readonly Regex IdRx = new(@"T\d{4}", RegexOptions.Compiled);

    static string BaseId(string raw) { var m = IdRx.Match(raw); return m.Success ? m.Value : raw; }

    static string Description(string raw)
    {
        int sp = raw.IndexOf(' ');
        return sp >= 0 ? raw[(sp + 1)..].Trim() : raw;
    }

    /// <summary>Decode raw "{id} {description}" entries into tactic → distinct meanings, preserving the
    /// order tactics first appear. Unknown ids fall under "Diğer teknikler" with their raw description.</summary>
    public static List<(string Tactic, List<string> Meanings)> Decode(IEnumerable<string> raw)
    {
        var groups = new Dictionary<string, List<string>>();
        var order = new List<string>();
        foreach (var entry in raw)
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;
            string tactic, meaning;
            if (Map.TryGetValue(BaseId(entry), out var hit)) { tactic = hit.Tactic; meaning = hit.Meaning; }
            else { tactic = "Diğer teknikler"; meaning = Description(entry); }
            if (!groups.TryGetValue(tactic, out var list)) { list = []; groups[tactic] = list; order.Add(tactic); }
            if (!list.Contains(meaning)) list.Add(meaning);
        }
        return order.Select(t => (t, groups[t])).ToList();
    }

    /// <summary>The tactics that mean real damage — coloured as an alarm in the digest.</summary>
    public static bool IsAlarmTactic(string tactic) =>
        tactic is "Etki" or "Kalıcılığı sağlama" or "Kimlik bilgisi çalma";
}
