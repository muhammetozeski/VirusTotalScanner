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
    public static string DlgCancel = "İptal";
    public static string BtnSave = "Kaydet";

    // ---- API key dialog ----
    public static string DlgApiKeyAddTitle = "API anahtarı ekle";
    public static string DlgApiKeyEditTitle = "API anahtarını düzenle";
    public static string ApiKeyLabelLabel = "Etiket (isteğe bağlı):";
    public static string ApiKeyKeyLabel = "VirusTotal API anahtarı:";
    public static string ApiKeyShow = "Göster";
    public static string ApiKeyValidate = "Doğrula";
    public static string ApiKeyEmptyWarn = "Anahtar boş olamaz.";
    public static string ApiKeyEnterFirst = "Önce anahtarı girin.";
    public static string ApiKeyValidating = "Doğrulanıyor…";
    public static string ApiKeyQuotaUnreadable = "Yanıt alındı ama kota okunamadı (anahtar yine de çalışabilir).";
    public static string ApiKeyValidFormat = "Geçerli ✓  Günlük {0}/{1} • Aylık {2}/{3}";
    public static string ApiKeyInvalid = "Geçersiz anahtar (401/403).";
    public static string ApiKeyErrorPrefix = "Hata: ";
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

    // ---- scan queue control: extra bar buttons ----
    public static string BtnVerifyHash = "✓  Hash doğrula";
    public static string BtnScanRunning = "🔬  Çalışanları tara";
    public static string BtnIntegrityCheck = "🛡  Bütünlük denetimi";
    public static string BtnFamilyClusters = "🧬  Aile kümeleri";
    public static string BtnQuarantineVault = "🗄  Karantina kasası";

    // ---- scan queue control: right-click menu ----
    public static string MenuOpenVt = "🔗  VirusTotal'de aç";
    public static string MenuCopy = "📋  Kopyala";
    public static string MenuCopyFilePath = "Dosya yolu";
    public static string MenuCopyFileName = "Dosya adı";
    public static string MenuCopyVerdictLine = "Verdikt satırı";
    public static string MenuRevealFile = "📁  Dosya konumunu aç";
    public static string MenuNeighbors = "📂  Klasör komşuları";
    public static string MenuFindCopies = "🔁  Diğer kopyaları bul (disk)";
    public static string MenuPinBaseline = "📌  Bütünlük izlemesine al";
    public static string MenuHuntPersistence = "🪝  Autostart kancalarını bul";
    public static string MenuRescan = "🔄  Yeniden tara";
    public static string MenuRescanNoTrust = "🛡  Güveni yok say, VT ile tara";
    public static string MenuQuarantine = "⚠  Karantinaya al (.VIRUS)";

    public static string ProgressSummaryFormat = "Toplam {0} • Tamamlanan {1} • Zararlı {2} • Şüpheli {3} • Temiz {4} • İmzalı↷atlandı {5} • Hata {6}";

    // ---- scan queue control: scan-entry / lookup / export / cache messages ----
    public static string FolderPickDescription = "Taranacak klasör (alt klasörler dahil)";
    public static string NeedApiKeyWarn = "Taramadan önce bir API anahtarı ekleyin, ya da Güven Kaynakları'ndan imza-atlamayı / anahtarsız (GUI) modu açın.";
    public static string ArchivePrompt = "Seçimde arşiv var (zip/nupkg/jar…).\n\nÜyelerini açıp her birini ayrı ayrı (kotasız) sorgulamak ister misiniz?\n\nEvet = üyeleri tara   •   Hayır = arşivin kendisini tara";
    public static string ArchiveFoundTitle = "Arşiv bulundu";
    public static string HashLookupPrompt = "Sorgulanacak MD5 / SHA-1 / SHA-256 hash:";
    public static string HashLookupTitle = "Hash sorgula";
    public static string HashInvalidWarn = "Geçerli bir MD5/SHA-1/SHA-256 hash girin.";
    public static string HashNotFound = "Bu hash VirusTotal'de bulunamadı.";
    public static string LookupFailedPrefix = "Sorgu başarısız: ";
    public static string NoResultsToExport = "Dışa aktarılacak sonuç yok.";
    public static string SavedPrefix = "Kaydedildi: ";
    public static string SaveErrorPrefix = "Kaydetme hatası: ";
    public static string ReportFilter = "HTML rapor|*.html|CSV|*.csv|JSON|*.json|Metin|*.txt";
    public static string ReportSavedPrefix = "Rapor kaydedildi: ";
    public static string ReportWriteErrorPrefix = "Rapor yazılamadı: ";
    public static string CacheClearConfirmFormat = "Yerel hash önbelleği ({0} kayıt) temizlensin mi?";
    public static string CacheClearedInfo = "Önbellek temizlendi.";
    public static string KeylessEnabledInfo = "Anahtarsız (GUI) mod açıldı. Sıradaki dosyalar kotasız sorgulanacak.";

    // ---- scan queue control: recheck / persistence / baseline / running / verify-hash ----
    public static string RunScanFirstInfo = "Önce bir tarama çalıştırın.";
    public static string RecheckNoneDueFormat = "Yeniden denetlenecek dosya yok ({0} günden eski önbellek kaydı yok).";
    public static string RecheckConfirmFormat = "{0} önbellek kaydı ({1} günden eski) yeniden denetlenecek.\nKotasız (GUI üzerinden) — biraz sürebilir. Devam edilsin mi?";
    public static string RecheckingFormat = "🔁 Yeniden denetleniyor… {0}/{1}";
    public static string RecheckNoChangeFormat = "{0} dosya denetlendi. Hiçbir verdikt değişmedi.";
    public static string RecheckChangedHeaderFormat = "{0} dosya denetlendi. {1} verdikt DEĞİŞTİ:\n";
    public static string RecheckWorse = "⬆ kötüleşti";
    public static string RecheckBetter = "⬇ iyileşti";
    public static string RecheckErrorPrefix = "Yeniden denetim hatası: ";
    public static string PersistenceNoneFormat = "'{0}' için autostart kancası bulunamadı (Run/Startup/Görevler temiz).";
    public static string PersistenceFoundFormat = "'{0}' için {1} autostart kancası bulundu:\n";
    public static string PersistenceManualNote = "Not: bunlar yalnızca listelenir; kaldırma manuel yapılmalı (regedit / Görev Zamanlayıcı).";
    public static string BaselineAddedFormat = "Bütünlük izlemesine eklendi:\n{0}\n\nToplam izlenen: {1}";
    public static string BaselineAddFailed = "Eklenemedi (dosya okunamadı).";
    public static string BaselineEmptyInfo = "İzlenen dosya yok.\nBir sonuca sağ tıklayıp 'Bütünlük izlemesine al' deyin.";
    public static string IntegrityCheckingFormat = "🛡 Bütünlük denetimi… {0}/{1}";
    public static string IntegrityErrorPrefix = "Bütünlük denetimi hatası: ";
    public static string IntegrityResultFormat = "{0} izlenen dosya denetlendi — {1} ALARM, {2} değişiklik.\n";
    public static string IntegrityAllUnchanged = "Hepsi değişmedi ✓";
    public static string NoRunnableProcessInfo = "Okunabilir çalışan süreç imajı bulunamadı.";
    public static string ScanRunningConfirmFormat = "Şu an çalışan {0} süreç imajı taranacak ({1} okunamadı/atlandı).\nÇoğu Microsoft imzalı olduğundan atlanır; yalnızca bilinmeyenler VT'ye gider.\n\nDevam edilsin mi?";
    public static string FolderNotFoundInfo = "Bu dosyanın klasörü bulunamadı.";
    public static string VerifyHashFileTitle = "Beklenen hash ile doğrulanacak dosya";
    public static string VerifyHashPrompt = "Beklenen hash (MD5/SHA-1/SHA-256):";
    public static string VerifyHashTitle = "Hash doğrula";
    public static string VerifyHashFormatWarn = "Beklenen hash 32 (MD5), 40 (SHA-1) veya 64 (SHA-256) hex karakter olmalı.";
    public static string VerifyHashMatchedFormat = "✓ EŞLEŞTİ ({0})\n\n{1}\n\n{2}";
    public static string VerifyHashMismatchFormat = "✗ EŞLEŞMEDİ ({0})\n\nBeklenen: {1}\nGerçek:   {2}\n\nDosya değiştirilmiş veya yanlış hash.";
    public static string VerifyHashErrorPrefix = "Doğrulama hatası: ";

    // ---- scan queue control: quarantine + find-copies messages ----
    public static string NeedVtResultInfo = "Önce dosyanın VT sonucu olmalı.";
    public static string QuarantineConfirmFormat = "'{0}' karantinaya alınsın mı? (uzantısı .VIRUS yapılır, çalıştırılamaz; sonradan geri yüklenebilir)";
    public static string QuarantineDoneInfo = "Dosya karantinaya alındı (çalıştırılamaz). Karantina kasasından geri yüklenebilir.";
    public static string QuarantineFailedPrefix = "Karantina başarısız: ";
    public static string FindCopiesConfirmFormat = "'{0}' ile birebir aynı (SHA-256) diğer kopyalar diskte aranacak (kotasız). Devam edilsin mi?";
    public static string FindingCopiesFormat = "🔁 Kopya aranıyor… {0}/{1}";
    public static string FindCopiesErrorPrefix = "Kopya arama hatası: ";
    public static string FileSizeUnknown = "Dosya boyutu bilinmiyor.";
    public static string NoCopiesFound = "Başka birebir kopya bulunamadı.";
    public static string CopiesFoundFormat = "{0} birebir kopya bulundu:\n";
    public static string MorePlusFormat = "… (+{0})";
    public static string QuarantineAllConfirm = "\nHepsi karantinaya alınsın mı? (.VIRUS)";
    public static string CopiesQuarantinedFormat = "{0}/{1} kopya karantinaya alındı.";
    public static string ErrorsHeader = "\n\nHatalar:\n";

    // ---- quarantine vault dialog ----
    public static string DlgVaultTitle = "🗄 Karantina kasası";
    public static string ColDate = "Tarih (UTC)";
    public static string ColOriginalPath = "Orijinal konum";
    public static string BtnRestore = "↩  Geri yükle";
    public static string VaultStillMaliciousFormat = "DİKKAT: '{0}' hâlâ zararlı görünüyor ({1}/{2}). Yine de geri yüklensin mi?";
    public static string VaultRestoreConfirmFormat = "'{0}' şu konuma geri yüklensin mi?\n{1}";
    public static string VaultRestoredFormat = "Geri yüklendi: {0}";
    public static string VaultRestoreFailedFormat = "Geri yüklenemedi: {0}";

    // ---- quota-exhausted dialog ----
    public static string DlgQuotaTitle = "API kotası doldu";
    public static string QuotaExhaustedMsgFormat = "Tüm API anahtarlarının kotası doldu.\nEn erken sıfırlanma: {0:HH:mm} (yerel saat).\n\nNe yapmak istersiniz?";
    public static string QuotaChoiceWait = "⏳  Bekle — sıfırlanınca otomatik devam et";
    public static string QuotaChoiceKeyless = "🌐  Anahtarsız (GUI) moda geç — kotasız, daha yavaş";
    public static string QuotaChoiceNewKey = "🔑  Yeni API anahtarı ekle";

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

    // ---- detail pane: comments + behaviour ----
    public static string CommentsNeedKeyless = "Topluluk yorumları için anahtarsız (GUI) mod gerekli.";
    public static string CommentsFetching = "💬  Getiriliyor…";
    public static string CommentsNone = "Topluluk yorumu bulunamadı.";
    public static string CommentsFailedPrefix = "Yorumlar alınamadı: ";
    public static string BehaviourNeedKeyless = "Sandbox davranışı için anahtarsız (GUI) mod gerekli.";
    public static string BehaviourFetching = "🔬  Getiriliyor…";
    public static string BehaviourNone = "Sandbox davranış verisi bulunamadı.";
    public static string BehaviourFailedPrefix = "Davranış alınamadı: ";
    public static string SecNetwork = "🌐 Ağ";
    public static string SecFilesWritten = "📁 Yazılan/bırakılan dosyalar";
    public static string SecRegistry = "🗝 Kayıt defteri";
    public static string SecProcesses = "⚙ Süreçler";
    public static string ConnectedThreatsFormat = "🔗 Bağlantılı tehditler: {0} dosya ortak IOC paylaşıyor";
    public static string ConnectedThreatsMaliciousSuffix = " (bazıları ZARARLI!)";
    public static string ConnectedShared = " — ortak: ";
    public static string MenuCopyEngineName = "📋  Motor adını kopyala";

    // ---- detail pane: body rendering ----
    public static string DetailEmptyHint = "Ayrıntıları görmek için soldan bir dosya seçin.";
    public static string BannerSigned = "İMZALI  —  VirusTotal taraması atlandı";
    public static string BannerVerdictFormat = "{0}  —  {1}/{2} motor tespit etti";
    public static string DetailLblFile = "Dosya: ";
    public static string DetailLblStatus = "Durum: ";
    public static string DetailLblPublisher = "Yayıncı: ";
    public static string DetailLblName = "Ad: ";
    public static string DetailLblType = "Tür: ";
    public static string DetailLblSize = "Boyut: ";
    public static string DetailLblReputation = "İtibar: ";
    public static string OverlayNoteFormat = "📎 İmza sonrası {0} eklenmiş — kurulumcu olabilir, ama doldurulmuş/trojanlı da olabilir";
    public static string SignedExplain = "\n\nGeçerli bir kod imzası bulundu; kota harcamamak için VirusTotal'e gönderilmedi.\nNot: imza güveni = yayıncının doğrulanması demektir, \"temiz\" garantisi değildir.\nYine de VT'ye göndermek için kuyrukta satıra sağ tıklayıp \"Güveni yok say, VT ile tara\".";
    public static string ProvenanceCache = "Kaynak: yerel önbellek (VT raporu)";
    public static string ProvenanceScan = "Kaynak: VirusTotal taraması";
    public static string StatsFormat = "Zararlı {0}   •   Şüpheli {1}   •   Temiz {2}   •   Tespitsiz {3}   •   Zaman aşımı {4}";
    public static string StatsCacheNote = "   •   (önbellek: motor listesi saklanmadı, ayrıntı için yeniden tarayın)";

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
