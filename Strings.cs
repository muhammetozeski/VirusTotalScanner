namespace VirusTotalScanner;

/// <summary>
/// User-facing UI strings, Turkish by default. <see cref="LocManager"/> reflection-writes these
/// fields to <c>lang.tr.xml</c> when it is missing, and — for any other chosen language —
/// overwrites the fields from <c>lang.&lt;code&gt;.xml</c> (e.g. the shipped <c>lang.en.xml</c>).
///
/// To localize a new string: add a public static string field here and a matching
/// &lt;s name="FieldName"&gt; entry in lang.en.xml. Fields are mutable on purpose (reflection sets
/// them); never mark them readonly/const. Interpolated text uses {0},{1}… with string.Format.
/// </summary>
internal static class Strings
{
    // ---- main window: tabs ----
    public static string TabScan = "🛡  Tarama";
    public static string TabQuota = "📊  Kotalar";
    public static string TabLogs = "📜  Loglar";
    public static string TabSettings = "⚙  Ayarlar";

    // ---- tray ----
    public static string TrayShow = "Göster";
    public static string TrayExit = "Çıkış";
    public static string TrayRunningText = "Arka planda çalışıyor. Açmak için simgeye çift tıklayın.";

    // ---- status bar / notifications ----
    public static string StatusBarFormat = "  Anahtar: {0}/{1} kullanılabilir   •   Ayar: {2}";
    public static string ThreatBalloonTitle = "Tehdit bulundu!";

    // ---- first-run wizard ----
    public static string FirstRunWelcome =
        "VirusTotal Scanner'a hoş geldiniz!\n\n" +
        "• Dosya/klasörleri sürükleyip bırakarak veya sağ tuş menüsünden tarayabilirsiniz.\n" +
        "• Başlamak için bir VirusTotal API anahtarı ekleyin.";
    public static string FirstRunAddKey = "Şimdi bir VirusTotal API anahtarı eklemek ister misiniz?";
    public static string FirstRunMenuPrompt = "Sağ tuş menüsüne 'VirusTotal ile tara' eklensin mi?\n(Tüm kullanıcılar için; yönetici izni/UAC istenecek.)";
    public static string FirstRunMenuTitle = "İzin";

    // ---- resume / repair ----
    public static string RepairMenuPrompt = "Sağ tuş menüsü kaydı eski exe yolunu gösteriyor (uygulama taşınmış). Şimdi onarılsın mı?";
    public static string ResumePromptFormat = "Yarım kalan bir tarama bulundu ({0} öğe):\n{1}\n\nKaldığı yerden devam edilsin mi?";
    public static string ResumePromptTitle = "Yarım kalan tarama";

    // ---- scan tab: action bar ----
    public static string BtnSelectFiles = "📄  Dosya seç…";
    public static string BtnSelectFolder = "📁  Klasör seç…";
    public static string BtnHashLookup = "🔎  Hash sorgula…";
    public static string BtnPause = "⏸  Duraklat";
    public static string BtnResume = "▶  Devam et";
    public static string BtnCancel = "⏹  İptal";
    public static string BtnExportCsv = "⬇  Dışa aktar (CSV)";
    public static string BtnExportReport = "📄  Rapor (HTML)";
    public static string BtnFolderRollup = "📊  Klasör özeti";
    public static string BtnRecheck = "🔁  Verdikt yeniden denetle";
    public static string BtnClearCache = "🗑  Önbelleği temizle";
    public static string DropHint = "  Dosya/klasörleri buraya da sürükleyip bırakabilirsiniz.";

    // ---- settings: language switch ----
    public static string SettingsLanguageLabel = "Dil:";
    public static string LanguageRestartNote = "Dil değişikliği uygulama yeniden başlatılınca tam olarak uygulanır.";

    // ---- scan queue grid + status ----
    public static string ColFile = "Dosya";
    public static string ColSize = "Boyut";
    public static string ColStatus = "Durum";
    public static string ColProgress = "İlerleme";
    public static string StatusReady = "Hazır.";

    // ---- detail pane ----
    public static string ShowAllEngines = "Tüm motorları göster";
    public static string OpenVtReport = "VirusTotal raporunu aç ↗";
    public static string ColEngine = "Antivirüs";
    public static string ColCategory = "Kategori";
    public static string ColResult = "Sonuç";
    public static string ColVersion = "Sürüm";
    public static string BtnCopy = "Kopyala";
}
