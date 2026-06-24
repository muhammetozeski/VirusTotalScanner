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

    // ---- common buttons / column words (reused across dialogs) ----
    public static string BtnClose = "Kapat";
    public static string BtnOk = "Tamam";
    public static string ColThreat = "Tehdit";
    public static string ColSuspicious = "Şüpheli";
    public static string ColClean = "Temiz";
    public static string ColSigned = "İmzalı";
    public static string ColUnknown = "Bilinmiyor";
    public static string ColVerdict = "Verdikt";
    public static string ColDetections = "Tespit";

    // ---- folder rollup dialog ----
    public static string DlgFolderRollupTitle = "📊 Klasör özeti";
    public static string ColFolder = "Klasör";
    public static string RollupSummaryFormat = "{0} klasör • {1} dosya • {2} tehdit • {3} şüpheli • {4} temiz • {5} imzalı-atlandı • {6} bilinmiyor/hata";
    public static string RollupTotal = "TOPLAM";

    // ---- folder neighbors dialog ----
    public static string DlgNeighborsTitle = "📂 Klasör komşuları";
    public static string NeighborsHeaderFormat = "{0}\n{1} taranmış komşu • {2} hiç taranmamış dosya";
    public static string NeighborsScanRestFormat = "🔎  Kalanları tara ({0})";
    public static string NeighborsNoNew = "Taranacak yeni dosya yok";

    // ---- family clusters dialog ----
    public static string DlgFamilyClustersTitle = "🧬 Aile kümeleri";
    public static string FamilyClustersNone = "Aynı aileyi paylaşan 2+ farklı hash yok (önbellekte tekrar eden bir aile bulunmadı).";
    public static string FamilyClustersHeaderFormat = "{0} aile kümesi — aynı zararlı ailesini paylaşan farklı dosyalar.";
    public static string ColFamily = "Aile";
    public static string ColMembers = "Üye";
    public static string ColLocations = "Konum";
    public static string ColFirstSeen = "İlk görülme";
    public static string ColPaths = "Yollar";

    // ---- scan item status text ----
    public static string StatusQueued = "Sırada";
    public static string StatusHashing = "Hash hesaplanıyor…";
    public static string StatusLookingUp = "VirusTotal sorgulanıyor…";
    public static string StatusUploading = "Yükleniyor…";
    public static string StatusPolling = "Analiz bekleniyor…";
    public static string StatusCompleted = "✅ Tamamlandı";
    public static string StatusFailedPrefix = "⚠ Hata: ";
    public static string StatusUnknown = "bilinmiyor";
    public static string StatusSkippedFormat = "⏭ Atlandı ({0})";
    public static string StatusSafeType = "güvenli tür";
    public static string StatusTrustedFormat = "🔵 {0} (VT atlandı)";
    public static string StatusSignedShort = "İmzalı";
    public static string StatusCancelled = "✋ İptal edildi";
    public static string VerdictSigned = "İMZALI";
    public static string CacheSuffix = " • önbellek";

    // ---- scan queue grid + status ----
    public static string ColFile = "Dosya";
    public static string ColSize = "Boyut";
    public static string ColStatus = "Durum";
    public static string ColProgress = "İlerleme";
    public static string StatusReady = "Hazır.";

    // ---- detail pane ----
    public static string ShowAllEngines = "Tüm motorları göster";
    public static string OpenVtReport = "VirusTotal raporunu aç ↗";
    public static string BtnComments = "💬  Yorumlar";
    public static string BtnBehaviour = "🔬  Davranış";
    public static string ColEngine = "Antivirüs";
    public static string ColCategory = "Kategori";
    public static string ColResult = "Sonuç";
    public static string ColVersion = "Sürüm";
    public static string BtnCopy = "Kopyala";
}
