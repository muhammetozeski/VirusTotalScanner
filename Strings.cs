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

    // ---- settings: API keys card ----
    public static string CardApiKeys = "API Anahtarları";
    public static string ColLabel = "Etiket";
    public static string ColKey = "Anahtar";
    public static string BtnAdd = "Ekle…";
    public static string BtnEdit = "Düzenle…";
    public static string BtnDelete = "Sil";
    public static string KeysHint = "Birden çok anahtar ekleyebilirsiniz; biri dolunca diğerine geçilir.";
    public static string KeyStatusDisabled = "Devre dışı";
    public static string KeyStatusExhausted = "Dolu";
    public static string KeyStatusActive = "Aktif";

    // ---- settings: context-menu card ----
    public static string CardContextMenu = "Sağ Tuş Menüsü";
    public static string CtxExcludeSafe = "Güvenli türlerde (txt, resim, video…) menüde gösterme";
    public static string BtnCtxInstall = "Sağ tuşa ekle (yönetici)";
    public static string BtnRepair = "Onar";
    public static string CtxRepaired = "Onarıldı.";
    public static string BtnRemove = "Kaldır";
    public static string CtxRemoved = "Kaldırıldı.";

    // ---- settings: trust sources card ----
    public static string CardTrust = "Güven Kaynakları (kota tasarrufu)";
    public static string TrustInfo = "Geçerli kod imzası olan dosyalar kota harcamamak için VT'ye gönderilmez.\nNot: imza güveni = yayıncı doğrulandı demektir, \"temiz\" garantisi değildir.";
    public static string TrustSkipSignedLabel = "İmzalı dosyaları VT'ye gönderme (anahtarsız, sınırsız)";
    public static string TrustMsOnlyLabel = "Yalnızca Microsoft imzalı dosyaları atla (güvenli varsayılan)";
    public static string TrustAllowLabel = "Ek güvenilen yayıncılar (CN, ; ile ayır):";
    public static string TrustPickHashList = "Bilinen-temiz hash listesi seç…";
    public static string TrustHashFilter = "Metin/hash listesi|*.txt;*.csv;*.*";
    public static string TrustHashLoadedFormat = "{0} hash yüklendi.";
    public static string TrustKeylessLabel = "Anahtarsız sorgu: VirusTotal'i GUI üzerinden aç (yavaş, kotasız)";

    // ---- settings: verdict categories card ----
    public static string CardVerdictCats = "Verdict Kategorileri (tespit sayısı → ad + renk)";
    public static string ColMinDetections = "Min. tespit";
    public static string ColName = "Ad";
    public static string ColColor = "Renk";
    public static string BtnAddShort = "Ekle";
    public static string CatNewName = "Yeni";
    public static string BtnPickColor = "Renk seç…";
    public static string CatsSaved = "Kategoriler kaydedildi.";
    public static string BtnDefault = "Varsayılan";
    public static string BtnSaveMajorEngines = "Büyük motor listesini kaydet";
    public static string MajorEnginesSaved = "Büyük motor listesi kaydedildi.";
    public static string CatThresholdHint = "Eşikler benzersiz olmalı. Örn: 0→TEMİZ, 2→ŞÜPHELİ, 3→VİRÜS.";
    public static string MajorEnginesHint = "Büyük (yüksek itibarlı) motorlar — konsensüs için (; ile ayır):";

    // ---- settings: scan card ----
    public static string CardScan = "Tarama";
    public static string ScanConcurrencyLabel = "Eşzamanlı tarama:";
    public static string ScanMaxSizeLabel = "Boyut sınırı (MB, 0=sınırsız):";
    public static string ScanRecheckDaysLabel = "Verdikt yeniden denetim (gün):";
    public static string ScanUploadsLabel = "Paralel yükleme (aynı anda):";
    public static string ScanUseCacheLabel = "Yerel hash önbelleği kullan (kota tasarrufu)";
    public static string ScanCacheDaysLabel = "Önbellek geçerlilik (gün):";
    public static string ScanSkipSafeLabel = "Taramada güvenli türleri atla";
    public static string ScanSafeExtsLabel = "Güvenli uzantılar (; ile ayır):";
    public static string BtnSaveExts = "Uzantıları kaydet";

    // ---- settings: scheduled sweep card ----
    public static string SweepStatusInstalled = "Durum: kurulu";
    public static string SweepStatusNotInstalled = "Durum: kurulu değil";
    public static string CardSweep = "Zamanlanmış Tarama (Windows görevi)";
    public static string BtnPickFolder = "Klasör seç…";
    public static string SweepFolderDescription = "Periyodik taranacak klasör";
    public static string SweepIntervalLabel = "Sıklık:";
    public static string SweepDaily = "Günlük (03:00)";
    public static string Sweep6h = "Her 6 saat";
    public static string Sweep12h = "Her 12 saat";
    public static string SweepWeekly = "Haftalık (Pazar 03:00)";
    public static string BtnInstallUpdate = "Kur / Güncelle";
    public static string SweepInstalledFormat = "Zamanlanmış tarama kuruldu.\nRapor: {0}";
    public static string SweepInstallFailedPrefix = "Kurulamadı: ";
    public static string BtnRunNow = "Şimdi çalıştır";
    public static string SweepStartedInfo = "Tarama görevi başlatıldı (arka planda).";
    public static string SweepRunFailedPrefix = "Çalıştırılamadı: ";
    public static string SweepRemovedInfo = "Zamanlanmış tarama kaldırıldı.";
    public static string SweepRemoveFailedPrefix = "Kaldırılamadı: ";
    public static string SweepHint = "Seçilen klasör periyodik olarak (anahtarsız) taranır; sonuç bir HTML rapora yazılır.";

    // ---- settings: general card ----
    public static string CardGeneral = "Genel";
    public static string ThemeLabel = "Tema:";
    public static string ThemeFollow = "Sistemi izle";
    public static string ThemeDark = "Koyu";
    public static string ThemeLight = "Açık";
    public static string TrayMinimizeLabel = "Kapatınca sistem tepsisine küçült";
    public static string NotifyThreatLabel = "Tehdit bulununca bildirim göster";
    public static string ShowVotesLabel = "Topluluk oylarını göster";
    public static string WatchDownloadsLabel = "İndirilenleri izle — yeni dosyaları otomatik tara (İndirilenler + Masaüstü)";
    public static string WatchToggleFormat = "İndirilenleri izleme {0}. Uygulamayı yeniden başlatınca tam uygulanır.";
    public static string WatchOn = "açıldı";
    public static string WatchOff = "kapatıldı";
    public static string LoggingLabel = "Loglama açık";
    public static string StartupLabel = "Windows ile başlat (arka planda, tepside)";
    public static string ResumeAskLabel = "Açılışta yarım kalan taramayı sor";
    public static string AutoResumeLabel = "Açılışta yarım kalan taramayı SORMADAN devam et";
    public static string BtnLedgerExport = "📤 Ledger dışa aktar";
    public static string LedgerWrittenFormat = "{0} kayıt yazıldı.";
    public static string BtnLedgerImport = "📥 Ledger içe aktar";
    public static string LedgerImportedFormat = "{0} yeni kayıt eklendi, {1} çakışma.\nBütünlük: {2}";
    public static string LedgerIntegrityOk = "OK ✓";
    public static string LedgerIntegrityBad = "UYUŞMUYOR ⚠";

    // ---- settings: confirm gates card ----
    public static string CardConfirmGates = "Onay Soruları (bir daha sorma)";
    public static string ConfirmGatesHint = "'Bir daha sorma' dediğin onaylar burada görünür; istersen tekrar sormaya açabilirsin.";
    public static string BtnAskAgain = "Tekrar sor";
    public static string GateSuppressedFormat = "  —  KAPALI (yanıt: {0})";
    public static string GateYes = "Evet";
    public static string GateNo = "Hayır";
    public static string GateAsking = "  —  soruluyor";

    // ---- settings: context-menu install messages ----
    public static string MenuInstallConfirm = "VirusTotalScanner kendisini Windows sağ tuş menüsüne (tüm kullanıcılar) ekleyecek.\nYönetici izni (UAC) istenecek.\n\nDevam edilsin mi?";
    public static string MenuInstalledInfo = "Sağ tuş menüsüne eklendi.\nWindows 11'de 'Daha fazla seçenek göster' altında görünür.";
    public static string MenuOpFailedWarn = "İşlem tamamlanamadı (yönetici izni gerekebilir).";
    public static string MenuStatusPrefix = "Durum: ";

    // ---- settings: about card ----
    public static string CardAbout = "Hakkında";
    public static string AboutGetKeyLink = "VirusTotal API anahtarı al (virustotal.com)";
    public static string AboutConfigFilePrefix = "Ayar dosyası: ";

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

    // ---- trust evaluation reasons (shown as the skip reason) ----
    public static string TrustUnsigned = "imzasız";
    public static string TrustCertExpired = "sertifika süresi dolmuş";
    public static string TrustCertRevoked = "sertifika iptal edilmiş";
    public static string TrustUntrustedPublisher = "güvenilmeyen yayıncı";
    public static string TrustChainFailed = "güven zinciri kurulamadı";
    public static string TrustSigInvalid = "imza geçersiz";
    public static string TrustUntrustedFormat = "güvenilmiyor (0x{0:X8})";

    // ---- behavior/capability tags (detail pane) ----
    public static string BtagDetectDebug = "🐞 hata ayıklayıcı tespiti (anti-analiz)";
    public static string BtagAntiDebug = "🐞 anti-debug";
    public static string BtagDetectVm = "🖥 sanal makine tespiti";
    public static string BtagChecksVm = "🖥 sanal makine kontrolü";
    public static string BtagChecksNet = "🌐 ağ adaptörlerini kontrol ediyor";
    public static string BtagChecksCpu = "🔍 CPU/donanım kontrolü";
    public static string BtagChecksBios = "🔍 BIOS kontrolü";
    public static string BtagChecksDisk = "🔍 disk kontrolü";
    public static string BtagCpuClock = "⏱ CPU saatine doğrudan erişim";
    public static string BtagLongSleeps = "⏱ uzun bekleme (kum havuzu kaçınma)";
    public static string BtagSelfDelete = "🗑 kendini siliyor";
    public static string BtagPersistence = "📌 kalıcılık (autostart)";
    public static string BtagAutorun = "📌 autorun";
    public static string BtagRuntimeModules = "🧩 çalışma anında modül yükleme";
    public static string BtagCreateProcess = "⚙ süreç başlatıyor";
    public static string BtagSpawnProcess = "⚙ alt süreç oluşturuyor";
    public static string BtagRegistry = "🗝 kayıt defteri değişikliği";
    public static string BtagKeylogger = "⌨ tuş kaydı";
    public static string BtagContacts = "🌐 ağ iletişimi";
    public static string BtagNetwork = "🌐 ağ etkinliği";
    public static string BtagObfuscated = "📦 gizlenmiş/obfuscate";
    public static string BtagPacked = "📦 paketlenmiş";
    public static string BtagExploit = "💥 exploit";
    public static string BtagPowershell = "🔧 PowerShell kullanımı";
    public static string BtagCve = "💥 bilinen açık (CVE)";
    public static string BtagClassFormat = "🧬 Sınıf: {0}";
    public static string BtagBehavior = "🧬 Davranış";

    // ---- report signal text (detail pane / CLI) ----
    public static string StaleTextFormat = "🕗 {0}/{1} tespit aylarca eski imzalardan — yeniden denetlemek iyi olur";
    public static string CommunityRulesPrefixFormat = "🛡 Topluluk kuralları ({0}): ";
    public static string MoreParenFormat = "  (+{0})";
    public static string ConfidenceHeuristic = "🤖 Tüm tespitler sezgisel/ML (imza eşleşmesi yok → olası yanlış pozitif)";
    public static string ConfidenceSigFormat = "🎯 {0} imza eşleşmesi (gerçek tespit) • {1} sezgisel/ML";
    public static string FamilyLabelFormat = "🏷 En sık aile: {0}";
    public static string FamilyMotorFormat = " ({0} motor)";
    public static string VerdictUnknown = "BİLİNMİYOR";
    public static string AgeYearsFormat = "{0} yıl önce";
    public static string AgeDaysFormat = "{0} gün önce";
    public static string AgeHoursFormat = "{0} saat önce";
    public static string AgeMinutesFormat = "{0} dakika önce";
    public static string SubmissionsFormat = " • {0} gönderim";
    public static string VeryNew = "  ⚠ çok yeni";
    public static string FirstSeenFormat = "İlk görülme: {0} ({1}){2}{3}";
    public static string VotesTextFormat = "Topluluk: 👍 {0} zararsız  •  👎 {1} zararlı";
    public static string ConsensusNoneFlagged = "🛡 Konsensüs: hiçbir motor işaretlemedi";
    public static string ConsensusMajorCleanHint = "  (büyük motor yok → olası yanlış pozitif)";
    public static string ConsensusFormat = "Büyük motorlar: {0} işaretledi   •   Küçük motorlar: {1}{2}{3}";

    // ---- recommendation (Keep / Caution / Remove) ----
    public static string RecoHeadlineKeep = "Güvenli tutulabilir";
    public static string RecoHeadlineCautionDontRun = "Dikkatli ol — henüz çalıştırma";
    public static string RecoHeadlineCaution = "Dikkatli ol";
    public static string RecoHeadlineRemove = "Şimdi kaldır";
    public static string RecoTrustedFormat = "İmzalı{0} — yayıncı doğrulandı, VT atlandı.";
    public static string RecoDownloadedSuffix = " ve internetten indirildi";
    public static string RecoUnknownFormat = "VirusTotal'de bulunamadı (bilinmiyor){0}. Bilinmeyen dosyalar daha yüksek risklidir.";
    public static string RecoMalwareWord = "zararlı";
    public static string RecoMaliciousFormat = "{0}/{1} motor '{2}' olarak işaretledi{3}.";
    public static string RecoMajorClean = "yalnızca küçük/itibarsız motorlar işaretledi (olası yanlış pozitif)";
    public static string RecoHeuristicOnly = "tüm tespitler sezgisel/ML (imza eşleşmesi yok)";
    public static string RecoSomeFlaggedFormat = "{0} motor işaretledi";
    public static string RecoCautionRationaleFormat = "{0}{1}.";
    public static string RecoRareNewFormat = "0 tespit ama çok yeni/nadir bir dosya{0}.";
    public static string RecoCleanFormat = "0/{0} tespit.";

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
