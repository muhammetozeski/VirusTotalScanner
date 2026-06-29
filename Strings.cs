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

    // ---- CLI: --help usage text ----
    public static string HelpTextFormat =
        "{0} v{1}\n\n" +
        "Kullanım:\n" +
        "  VirusTotalScanner.exe [seçenekler] <dosya|klasör> [<dosya|klasör> ...]\n\n" +
        "Çift tıklayınca grafik arayüz açılır. Terminalden çalıştırınca komut satırı modunda çalışır.\n\n" +
        "Seçenekler:\n" +
        "  -s, --scan          Tarama işareti (sağ tuş menüsü kullanır)\n" +
        "  -r, --recurse       Klasörleri alt klasörlerle birlikte tara\n" +
        "      --no-trust      İmza güvenini yok say (imzalı dosyaları da VT'ye gönder)\n" +
        "  -k, --keyless       Anahtarsız sorgula (GUI/WebView2 üzerinden, kotasız, yavaş)\n" +
        "      --expand-archives  Arşivleri (zip/nupkg/jar…) aç, üyelerini ayrı ayrı tara\n" +
        "      --running       Çalışan tüm süreçlerin imajlarını tara (\"şu an virüslü müyüm?\")\n" +
        "  -n, --nogui, --cli  Grafik arayüz açmadan terminalde çalış\n" +
        "  -g, --gui           Terminalden bile olsa grafik arayüzü aç\n" +
        "  -j, --json          Sonuçları JSON olarak yaz (stdout)\n" +
        "      --report <yol>  Rapor dosyası yaz (.html/.csv/.json/.txt — uzantıdan biçim seçilir)\n" +
        "      --fail-on <N>   N+ tespit olan dosyada çıkış kodu 1 (CI kapısı)\n" +
        "      --diff <json>   Önceki --report json ile karşılaştır (sha256); delta yaz\n" +
        "      --fail-on-new / --fail-on-regression  yeni/kötüleşen verdiktte çıkış 1\n" +
        "  -q, --quiet         Yalın çıktı (yalnızca verdict satırları)\n" +
        "      --install       Sağ tuş menüsüne ekle\n" +
        "      --uninstall     Sağ tuş menüsünden kaldır\n" +
        "      --repair        Sağ tuş menüsü kaydını (exe yolu) onar\n" +
        "      --addkey <KEY>  API anahtarı ekle (şifreli saklanır)\n" +
        "      --listkeys      Tanımlı anahtarları ve kotaları listele\n" +
        "      --removekey <id|all>  Anahtar(ları) sil\n" +
        "      --lookup <hash>  Bir MD5/SHA-1/SHA-256 hash'ini sorgula\n" +
        "      --expect <hash>  Dosyayı beklenen hash ile doğrula (eşleşmezse çıkış kodu 4)\n" +
        "  -h, --help          Bu yardım\n" +
        "  -v, --version       Sürüm\n\n" +
        "Çıkış kodları: 0 temiz, 1 tehdit bulundu, 2 kullanım/IO hatası, 3 anahtar yok, 4 hash eşleşmedi.\n\n" +
        "Not: Bu bir GUI uygulamasıdır; betikte beklemek için 'Start-Process -Wait' kullanın.";

    // ---- CLI: menu / ledger / scan-flow messages ----
    public static string CliMenuInstalled = "Sağ tuş menüsü kuruldu.";
    public static string CliMenuRemoved = "Sağ tuş menüsü kaldırıldı.";
    public static string CliMenuRepaired = "Sağ tuş menüsü onarıldı.";
    public static string CliKeyAdded = "Anahtar eklendi.";
    public static string CliLedgerExportedFormat = "{0} kayıt ledger'a yazıldı: {1}";
    public static string CliLedgerImportedFormat = "{0} yeni kayıt eklendi, {1} çakışma. Bütünlük: {2}";
    public static string CliLedgerOk = "OK";
    public static string CliLedgerBad = "UYUŞMUYOR";
    public static string CliLedgerDiffFormat = "Sende olmayan {0}, çakışma {1}:";
    public static string CliTagNew = "[YENİ]";
    public static string CliTagConflict = "[ÇAKIŞMA]";
    public static string CliTagRegressed = "[KÖTÜLEŞTİ]";
    public static string CliRunningProcessesFormat = "Çalışan süreçler: {0} imaj taranacak ({1} okunamadı/atlandı).";
    public static string CliErrNoMeans = "HATA: API anahtarı yok, imza-atlama kapalı ve anahtarsız (GUI) mod açık değil.";
    public static string CliWarnNoKey = "(Uyarı: anahtar yok — yalnızca imzalı dosyalar değerlendirilebilir, imzasızlar atlanır.)";
    public static string CliKeylessNote = "(Anahtarsız GUI modu açık — sorgular WebView2 üzerinden, kotasız ama yavaş.)";
    public static string CliScanStartingFormat = "{0} — tarama başlıyor…\n";
    public static string CliReportWrittenFormat = "Rapor yazıldı: {0}";
    public static string CliDiffBaselineErrPrefix = "Diff: baseline okunamadı: ";
    public static string CliDeltaFormat = "\nDelta: {0} yeni, {1} kötüleşti, {2} değişmedi.";
    public static string CliDoneFormat = "\nBitti. {0} dosya tarandı, {1} tehdit bulundu.";

    // ---- CLI: recheck / behaviour / comments / baseline / verify-hash ----
    public static string CliNoRecheckRecords = "Önbellekte denetlenecek kayıt yok.";
    public static string CliRecheckingFormat = "{0} önbellek kaydı yeniden denetleniyor (kotasız)…";
    public static string CliDriftHeaderFormat = "Verdict drift — {0} değişiklik / {1} denetlendi";
    public static string CliDriftWrittenFormat = "{0} verdikt değişikliği yazıldı: {1}";
    public static string CliErrBehaviourKeyless = "HATA: davranış için anahtarsız GUI gerekli (--keyless).";
    public static string CliSecNetwork = "Ağ";
    public static string CliSecFiles = "Yazılan/bırakılan dosyalar";
    public static string CliSecRegistry = "Kayıt defteri";
    public static string CliSecProcesses = "Süreçler";
    public static string CliErrCommentsKeyless = "HATA: yorumlar için anahtarsız GUI gerekli (--keyless).";
    public static string CliNoComments = "Yorum bulunamadı.";
    public static string CliNoWatchedFiles = "İzlenen dosya yok.";
    public static string CliTagAlarm = "[ALARM]";
    public static string CliTagChanged = "[değişti]";
    public static string CliBaselineResultFormat = "{0} izlenen dosya denetlendi, {1} alarm.";
    public static string CliErrExpectOneFile = "HATA: --expect tek bir dosya yolu ister.";
    public static string CliErrHashFormat = "HATA: beklenen hash 32 (MD5), 40 (SHA-1) veya 64 (SHA-256) hex karakter olmalı.";
    public static string CliHashMatchedFormat = "[EŞLEŞTİ] {0}: {1}  ✓  {2}";
    public static string CliHashMismatchFormat = "[EŞLEŞMEDİ] {0}";
    public static string CliHashExpectedFormat = "   Beklenen {0}: {1}";
    public static string CliHashActualFormat = "   Gerçek   {0}: {1}";
    public static string CliErrPrefix = "HATA: ";

    // ---- CLI: lookup / keys / signed-print ----
    public static string CliErrNoKeyOrKeyless = "HATA: API anahtarı yok (veya --keyless kullanın).";
    public static string CliNotFound = "Bulunamadı (VT'de yok).";
    public static string CliNoKeys = "Anahtar yok.";
    public static string CliKeyDisabled = "devre dışı";
    public static string CliKeyExhausted = "dolu";
    public static string CliKeyActive = "aktif";
    public static string CliQuotaFormat = "gün {0}/{1}  ay {2}/{3}";
    public static string CliAllKeysDeleted = "Tüm anahtarlar silindi.";
    public static string CliKeyRemovedPrefix = "Anahtar silindi (varsa): ";
    public static string CliSignedFormat = "[İMZALI] {0}  — {1} (VT atlandı)";
    public static string CliItemErrorPrefix = "      Hata: ";

    // ---- context-menu installer ----
    public static string AdminDenied = "Yönetici izni verilmedi.";
    public static string MenuStateOk = "Kurulu ✓ (tüm kullanıcılar)";
    public static string MenuStateMissing = "Kurulu değil";
    public static string MenuStateStale = "Eski yol — onarım gerekli";
    public static string MenuStateUnknown = "Durum okunamadı";

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

    // ---- jargon glossary: engine category column ----
    public static string JcatMalicious = "Zararlı buldu";
    public static string JcatSuspicious = "Şüpheli buldu (kesin değil)";
    public static string JcatHarmless = "Zararsız (temiz) buldu";
    public static string JcatUndetected = "Hiçbir şey bulamadı (temiz)";
    public static string JcatTimeout = "Zaman aşımı — tarayamadı";
    public static string JcatConfirmedTimeout = "Kesin zaman aşımı — tarayamadı";
    public static string JcatTypeUnsupported = "Bu dosya türünü taramıyor";
    public static string JcatFailure = "Tarama başarısız oldu";
    public static string JcatNotSupported = "Desteklenmiyor";

    // ---- jargon glossary: detection-name morphemes ----
    public static string JmNotAVirus = "virüs değil (genelde araç/reklam)";
    public static string JmHeur = "sezgisel/tahmini imza (kesin değil)";
    public static string JmGeneric = "genel imza (kesin değil)";
    public static string JmTrojan = "truva atı";
    public static string JmBackdoor = "arka kapı";
    public static string JmWorm = "solucan (kendini yayar)";
    public static string JmRansom = "fidye yazılımı";
    public static string JmDownloader = "başka zararlı indirir";
    public static string JmDropper = "başka zararlı bırakır";
    public static string JmSpyware = "casus yazılım";
    public static string JmKeylog = "tuş kaydedici";
    public static string JmRootkit = "gizlenen zararlı (rootkit)";
    public static string JmAdware = "reklam yazılımı";
    public static string JmRiskware = "riskli ama meşru olabilir";
    public static string JmPua = "istenmeyen program (zararlı olmayabilir)";
    public static string JmUnwanted = "istenmeyen program";
    public static string JmExploit = "açık sömüren (exploit)";
    public static string JmMsil = ".NET programı";
    public static string JmWin32 = "Windows 32-bit";
    public static string JmWin64 = "Windows 64-bit";
    public static string JmScript = "betik (script)";

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
    public static string RecoCommunityHarmlessFormat = "topluluk çoğunlukla zararsız işaretledi ({0}/{1} oy)";
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

    // ============================================================
    // Localization completion: user-facing strings lifted from code
    // ============================================================

    // ---- ScanQueueControl ----
    public static string BtnIncidentTimeline = "🕓  Olay zaman çizelgesi";
    public static string BtnDownloadsTriage = "📥  İndirilenler triyajı";
    public static string BtnHelp = "❓  Yardım";
    public static string BtnAllCommands = "⌨  Ctrl+K · Tüm komutlar";
    public static string TipSelectFiles = "Taranacak dosya(lar) seç.";
    public static string TipSelectFolder = "Bir klasörü, alt klasörleriyle birlikte tara.";
    public static string TipHashLookup = "Elindeki bir MD5/SHA hash'ini VirusTotal'de ara (dosya gerekmez).";
    public static string TipVerifyHash = "Bir dosyanın beklenen hash ile birebir aynı olduğunu doğrula.";
    public static string TipScanRunning = "Şu an çalışan tüm süreçlerin imajlarını tara — 'şu an virüslü müyüm?'.";
    public static string TipIntegrityCheck = "İzlemeye aldığın dosyaların değişip değişmediğini (drift) denetle.";
    public static string TipExportCsv = "Sonuçları CSV tablosu olarak kaydet.";
    public static string TipExportReport = "Sonuçları HTML/CSV/JSON/metin rapora yaz.";
    public static string TipFolderRollup = "Taranan klasörleri tehdit/temiz sayılarıyla özetle.";
    public static string TipFamilyClusters = "Aynı zararlı ailesini paylaşan farklı dosyaları grupla.";
    public static string TipQuarantineVault = "Karantinaya alınanları gör; güvenliyse geri yükle.";
    public static string TipRecheck = "Eski önbellek kayıtlarını kotasız (GUI) yeniden sorgula.";
    public static string TipClearCache = "Yerel hash önbelleğini temizle (verdiktler tekrar VT'den alınır).";
    public static string TipIncidentTimeline = "Diske gelen çalıştırılabilirleri varış gününe göre kümele.";
    public static string TipAllCommands = "Tüm özelliklere tek yerden ulaş (kopya bul, autostart kancaları, aile kümeleri…).";
    public static string TipPause = "Devam eden taramayı duraklat / sürdür.";
    public static string TipCancel = "Devam eden taramayı iptal et.";
    public static string SearchPlaceholder = "🔎  Ara (ad/yol)…";
    public static string ChipAll = "Tümü";
    public static string ChipSkipped = "Atlandı";
    public static string ChipError = "Hata";
    public static string FilterCountFormat = "gösterilen {0} / toplam {1}";
    public static string ChipCountFormat = "{0} ({1})";
    public static string BtnUndo = "↩  Geri al";
    public static string UndoQuarantinedFormat = "✓  '{0}' karantinaya alındı (.VIRUS).";
    public static string UndoRestoredFormat = "↩ '{0}' geri yüklendi.";
    public static string RecallPathChangedFormat = "⚠ Bu yolda en son FARKLI bir dosya taramıştın ({0:yyyy-MM-dd} — {1} {2}); içerik o zamandan beri DEĞİŞTİ.";
    public static string RecallSeenBeforeFormat = "🕘 Bu dosyayı daha önce {0} kez taradın. Önceki: {1:yyyy-MM-dd HH:mm} — {2} {3}";
    public static string MenuCopySha256 = "SHA-256";
    public static string MenuCopyMd5 = "MD5";
    public static string MenuShare = "📤  Paylaş";
    public static string MenuShareCardImage = "🖼  Kart resmi (panoya)";
    public static string ShareCardCopiedInfo = "📋 Kart resmi panoya kopyalandı.";
    public static string CopyFailedPrefix = "Kopyalanamadı: ";
    public static string MenuShareSummaryText = "📝  Özet metin (panoya)";
    public static string MenuShareMarkdown = "⬇  Markdown özet (panoya)";
    public static string ShareMarkdownCopiedInfo = "📋 Markdown özet panoya kopyalandı.";
    public static string MenuShareSaveCard = "💾  Kart resmi kaydet…";
    public static string MenuWatchAdd = "👁  İzlemeye al (re-verdict)";
    public static string MenuWatchRemove = "👁  İzlemeden çıkar";
    public static string MenuRescanFailed = "🔁  Yalnızca hatalıları yeniden tara";
    public static string MenuMarkClean = "✓  Temiz olarak işaretle";
    public static string MenuSuppressFolder = "🔇  Bu klasörü sessizleştir";
    public static string MenuRescanCountFormat = "🔄  {0} dosyayı yeniden tara";
    public static string MenuQuarantineCountFormat = "⚠  {0} dosyayı karantinaya al (.VIRUS)";
    public static string OpenFilesDialogTitle = "Taranacak dosyalar";
    public static string ClipboardEmptyInfo = "Pano boş ya da metin içermiyor.";
    public static string ClipboardNotPathInfoFormat = "Panodaki metin bir dosya yolu, klasör ya da hash değil:\n{0}";
    public static string NoFailedRowsInfo = "Yeniden taranacak hatalı satır yok.";
    public static string PersistenceCleanupConfirmFormat = "{0} karantinaya alındı, ama {1} otomatik başlatma kancası hâlâ ona işaret ediyor (her açılışta çalıştırmaya çalışır). Şimdi temizleyelim mi?";
    public static string QuarantineKillConfirmFormat = "Bu dosya şu an çalışıyor: {0}.\nKarantinaya almak için önce kapatılsın mı?";
    public static string QuarantineLockedRebootFormat = "{0} hâlâ kilitli; bilgisayar yeniden başlatıldığında silinecek şekilde işaretlendi. Lütfen yeniden başlatın.";
    public static string AllowlistReasonUserMarkedClean = "Kullanıcı temiz olarak işaretledi";
    public static string MarkCleanNoHashInfo = "Bu dosyanın hash'i henüz yok; temiz olarak işaretlenemiyor.";
    public static string SkipReasonUserSaidClean = "Kullanıcı temiz dedi";
    public static string SuppressFolderConfirmFormat = "Bu klasör ve altındaki tüm dosyalar bundan sonra taramada atlanacak:\n{0}\n\nDevam edilsin mi?";
    public static string FolderMutedInfoFormat = "Klasör sessizleştirildi:\n{0}";
    public static string FolderAlreadyMutedInfo = "Bu klasör zaten listede.";
    public static string MarkedCleanCountInfoFormat = "{0} dosya temiz olarak işaretlendi (bundan sonra taramada atlanır).";
    public static string QuarantineBatchConfirmFormat = "{0} dosya karantinaya alınsın mı? (uzantıları .VIRUS yapılır, çalıştırılamaz; sonradan geri yüklenebilir)";
    public static string QuarantineBatchResultFormat = "{0}/{1} dosya karantinaya alındı.";
    public static string CsvDefaultFileName = "virustotal-sonuclar.csv";
    public static string CsvHeaderRow = "Dosya;Verdict;Zararli;Supheli;Toplam;MD5;SHA256;Rapor";
    public static string ProgressEtaFormat = "  •  Kalan ~{0}";
    public static string ProgressRateFormat = "{0}  •  {1:0.#} dosya/sn  •  Geçen {2}";
    public static string OverallBarTooltipFormat = "Zararlı {0} · Şüpheli {1} · Temiz {2} · İmzalı {3} · Atlandı {4} · Hata {5}  ({6}/{7})";
    public static string DurationHoursMinutesFormat = "{0} sa {1} dk";
    public static string DurationMinutesSecondsFormat = "{0} dk {1} sn";
    public static string DurationSecondsFormat = "{0} sn";
    public static string NoVisibleThreatsInfo = "Görünür tehdit yok.";
    public static string ThreatsSelectedFormat = "{0} tehdit seçildi — Ctrl+Q ile karantina";
    public static string JumpVerdictPositionFormat = "{0}/{1}  —  J/K sonraki/önceki, Shift+J/K hatalar";
    public static string VerdictImageCopiedInfo = "📋 Verdikt görseli panoya kopyalandı.";
    public static string EmptyStateTitle = "Taramaya başlamak için bir yol seç";
    public static string EmptyStateDropHint = "Dosya/klasörleri buraya sürükleyip de bırakabilirsin";
    public static string BtnInstallContextMenu = "🖱  Sağ tuş menüsünü kur";
    public static string CmdSelectFilesName = "Dosya seç…";
    public static string CmdSelectFilesDesc = "Taranacak dosya(lar) seç";
    public static string CmdSelectFolderDesc = "Bir klasörü alt klasörleriyle tara";
    public static string CmdHashLookupName = "Hash sorgula…";
    public static string CmdHashLookupDesc = "Bir MD5/SHA hash'ini VirusTotal'de ara";
    public static string CmdRescanFailedName = "Yalnızca hatalıları yeniden tara";
    public static string CmdRescanFailedDesc = "Başarısız (Hata) satırların hepsini yeniden tara";
    public static string CmdScanClipboardName = "Panodaki yolu/hash'i tara";
    public static string CmdScanClipboardDesc = "Panodaki dosya yolunu, klasörü ya da MD5/SHA hash'ini denetle";
    public static string CmdVerifyHashName = "Hash doğrula…";
    public static string CmdVerifyHashDesc = "Bir dosyayı beklenen hash ile karşılaştır";
    public static string CmdScanRunningName = "Çalışanları tara";
    public static string CmdScanRunningDesc = "Çalışan tüm süreç imajlarını tara";
    public static string CmdIntegrityCheckName = "Bütünlük denetimi";
    public static string CmdIntegrityCheckDesc = "İzlenen dosyalarda değişiklik/drift ara";
    public static string CmdFamilyClustersName = "Aile kümeleri";
    public static string CmdFamilyClustersDesc = "Aynı zararlı ailesini paylaşan dosyaları grupla";
    public static string CmdQuarantineVaultName = "Karantina kasası";
    public static string CmdQuarantineVaultDesc = "Karantinaya alınanları görüntüle / geri yükle";
    public static string CmdIncidentTimelineName = "Olay zaman çizelgesi";
    public static string CmdIncidentTimelineDesc = "Gelen çalıştırılabilirleri varış zamanına göre kümele";
    public static string CmdRecheckName = "Verdikt yeniden denetle";
    public static string CmdRecheckDesc = "Eski önbellek kayıtlarını kotasız yeniden sorgula";
    public static string CmdFolderRollupName = "Klasör özeti";
    public static string CmdFolderRollupDesc = "Taranan klasörleri tehdit sayısıyla özetle";
    public static string CmdExportReportName = "Rapor (HTML)";
    public static string CmdExportReportDesc = "Sonuçları HTML/CSV/JSON/metin rapora yaz";
    public static string CmdExportCsvName = "Dışa aktar (CSV)";
    public static string CmdExportCsvDesc = "Sonuçları CSV olarak kaydet";
    public static string CmdClearCacheName = "Önbelleği temizle";
    public static string CmdClearCacheDesc = "Yerel hash önbelleğini sil";
    public static string CmdFindCopiesName = "Diğer kopyaları bul (disk)";
    public static string CmdFindCopiesDesc = "Seçili dosyanın birebir kopyalarını diskte ara";
    public static string CmdHuntPersistenceName = "Autostart kancalarını bul";
    public static string CmdHuntPersistenceDesc = "Seçili dosya için kalıcılık kayıtlarını ara";
    public static string CmdNeighborsName = "Klasör komşuları";
    public static string CmdNeighborsDesc = "Seçili dosyanın klasöründeki diğer dosyalar";
    public static string CmdSaveProfileName = "Profil kaydet… (tarama ayarları)";
    public static string CmdSaveProfileDesc = "Şu anki tarama ayarlarını adlandırılmış profil olarak kaydet";
    public static string CmdApplyProfileNameFormat = "Profil uygula: {0}";
    public static string CmdApplyProfileDesc = "Bu profilin tarama ayarlarını uygula";
    public static string CmdDeleteProfileNameFormat = "Profil sil: {0}";
    public static string CmdDeleteProfileDesc = "Bu tarama profilini sil";
    public static string ProfileDeletedFormat = "Profil silindi: {0}";
    public static string SaveProfilePrompt = "Profil adı:";
    public static string SaveProfileTitle = "Tarama profili kaydet";
    public static string ProfileSavedFormat = "Profil kaydedildi: {0}";
    public static string ProfileAppliedFormat = "Profil uygulandı: {0} ({1} ayar)";
    public static string ProfileNotFoundFormat = "Profil bulunamadı: {0}";
    public static string DownloadsFolderNotFoundInfo = "İndirilenler klasörü bulunamadı.";

    // ---- SettingsControl ----
    public static string SettingsSearchPlaceholder = "🔎  Ayar ara (ad/etiket)…  —  Esc temizler";
    public static string CardAllowlist = "Beyaz liste (temiz olarak işaretledikleriniz)";
    public static string ColReason = "Gerekçe";
    public static string ColHash = "Hash";
    public static string ColAdded = "Eklendi";
    public static string BtnRemoveFromList = "Listeden çıkar";
    public static string BtnReviewMarkClean = "Gözden geçir (temiz say)";
    public static string BtnHealthCheck = "🩺  Sağlık denetimi";
    public static string AllowlistAllStillClean = "Beyaz listedeki tüm dosyalar hâlâ temiz.";
    public static string AllowlistNowFlaggedFormat = "{0} dosya artık işaretli! Kırmızı satırları gözden geçirin (çıkarın ya da temiz sayın).";
    public static string AllowlistImportedFromHistoryFormat = "{0} temiz dosya geçmişten beyaz listeye eklendi.";
    public static string BtnImportFromHistory = "Geçmişten içe aktar";
    public static string AllowlistHint = "'Temiz olarak işaretle' dediğiniz dosyalar burada; 'Sağlık denetimi' bunları kotasız yeniden sorgular ve sonradan tehdide dönüşenleri kırmızı işaretler.";
    public static string CardFolderSuppression = "Klasör bazlı sessizleştirme (geliştirme/build klasörleri)";
    public static string BtnAddFolder = "Klasör ekle…";
    public static string FolderSuppressionHint = "Bu klasörlerin altındaki dosyalar taramada atlanır — her derlemede hash'i değişen build çıktısı için (hash listesi bunu kapsayamaz).";
    public static string CardAutoAction = "Tarama sonrası oto-eylem kuralları";
    public static string ColBackgroundOnly = "Yalnızca arka plan";
    public static string ColMinDetect = "Min tespit";
    public static string ColFromInternet = "İnternetten";
    public static string ColMinLevel = "Min seviye 0-2";
    public static string ColFolderPrefix = "Klasör ön-eki";
    public static string ColAction = "Eylem";
    public static string AutoActionSaved = "Oto-eylem kuralları kaydedildi.";
    public static string AutoActionHint = "İlk eşleşen kural uygulanır. Eylemler: ToastOnly (sadece bildir), MarkClean (beyaz listeye al), SuppressFolder (klasörü atla), Quarantine (karantinaya al). Boş liste = yerleşik davranış.";
    public static string ScanCleanCacheDaysLabel = "Temiz önbellek geçerlilik (gün):";
    public static string ScanThreatCacheDaysLabel = "Tehdit önbellek geçerlilik (gün):";
    public static string NotifyThresholdLabel = "Bildirim eşiği (en az kaç tespit):";
    public static string NotifyScanSummaryLabel = "Tarama bitince özet bildirim göster";
    public static string WatchUsbLabel = "USB takıldığında taramayı öner";
    public static string AutoScanUsbLabel = "USB takılınca tıklamadan hemen otomatik tara (arka planda)";
    public static string WatchProcessLaunchesLabel = "Çalıştırılan her exe'yi başlarken denetle (gerçek-zamanlı, yönetici gerekir)";
    public static string ProcGuardEnabledInfo = "Bu koruma bir sonraki açılışta etkinleşir (WMI izleme yönetici hakları gerektirir).";
    public static string SignatureSoftenLabel = "İmzalı dosyada 1-2 sezgisel tespiti 'imzayla yumuşatıldı' işaretle (muhtemel yanlış pozitif)";
    public static string AutoQuarantineWatchersLabel = "Arka plan gözcüleri yüksek-tespitli tehditleri otomatik karantinaya alsın (geri alınabilir)";
    public static string AutoQuarantineThresholdLabel = "Otomatik karantina eşiği (tespit sayısı):";
    public static string MuteInFullscreenLabel = "Tam ekran uygulamada (oyun/sunum) bildirimleri sustur";
    public static string QuietHoursLabel = "Sessiz saatler (başlangıç–bitiş, eşitse kapalı):";
    public static string QuietHoursSeparator = "–";
    public static string QuarantineRetentionLabel = "Karantinayı şu günden eski kayıtlardan otomatik temizle (0=kapalı):";
    public static string PeriodicRecheckLabel = "Tepside her N saatte arka planda yeniden denetle (izleme/önbellek/bütünlük, 0=sadece açılışta):";
    public static string KeyRowDefaultLabel = "Key";
    public static string KeyDeleteConfirm = "Bu anahtar silinsin mi?";
    public static string BtnResetAllSettings = "↺  Tüm ayarları varsayılana döndür";
    public static string ResetAllSettingsConfirm = "Tüm ayarlar varsayılan değerlerine döndürülsün mü? (API anahtarları etkilenmez)";
    public static string SettingsResetInfo = "Ayarlar varsayılana döndürüldü. Görünmesi için Ayarlar sekmesini yeniden açın.";
    public static string BtnExportSettings = "Ayarları dışa aktar";
    public static string SettingsFileFilter = "Ayar dosyası|*.txt|Tümü|*.*";
    public static string SettingsExportedInfo = "Ayarlar dışa aktarıldı (API anahtarları hariç, paylaşıma uygun).";
    public static string SettingsExportFailedPrefix = "Dışa aktarılamadı: ";
    public static string BtnImportSettings = "Ayarları içe aktar";
    public static string SettingsImportedFormat = "{0} ayar içe aktarıldı. Görünmesi için Ayarlar sekmesini yeniden açın.";
    public static string SettingsImportFailedPrefix = "İçe aktarılamadı: ";

    // ---- ScanDetailControl ----
    public static string DetailMajorOnlyCheck = "Yalnızca büyük motorlar";
    public static string DetailSharedIocCampaignFormat = "{0} taranmış dosyayla ortak ağ göstergesi paylaşıyor (aynı kampanya olabilir)";
    public static string DetailSignalsHelpLink = "❓ Sinyaller ne demek?";
    public static string RecencyToday = "bugün";
    public static string DetailLocalFirstSeenFormat = "💻 Bu makinede ilk görülme: {0:yyyy-MM-dd} ({1})";
    public static string MenuCopyEngineResult = "📋  Sonucu kopyala";
    public static string MenuSearchEngineResult = "🔎  Sonucu internette ara";
    public static string DetailTrustedSubtitle = "VirusTotal taraması atlandı";
    public static string DetailSignatureSoftenedFormat = "🔓 Geçerli imza nedeniyle muhtemel yanlış pozitif: {0} — ‘Temiz olarak işaretle’ ile onayla";
    public static string DetailSignedFallback = "imzalı";
    public static string DetailCommunitySoftenedFormat = "👍 Topluluk çoğunlukla zararsız oyladı ({0}/{1} oy) — muhtemel yanlış pozitif";
    public static string DetailBehaviourDigestHeader = "🧪 Bu dosya çalışırsa PC'ne ne yapar:";
    public static string DetailActionQuarantine = "🛡  Karantinaya al";
    public static string DetailActionRescanFirst = "🔄  Önce yeniden tara";
    public static string DetailActionVtReport = "🔗  VT raporu";

    // ---- ScanOverviewControl ----
    public static string OverviewDropHint = "🛡  Taramak için dosya/klasörü buraya sürükle";
    public static string BtnScanDownloads = "⬇  İndirilenleri tara";
    public static string BtnRecheckShort = "🔁  Yeniden denetle";
    public static string OnboardCardTitle = "🚀 Başlangıç — kurulumu tamamla";
    public static string BtnHide = "Gizle";
    public static string OnboardStepApiKey = "API anahtarı / anahtarsız mod";
    public static string ActionGoSettings = "Ayarlar →";
    public static string OnboardStepInstallMenu = "Sağ-tık menüsünü kur";
    public static string OnboardStepWatchDownloads = "İndirilenleri izlemeyi aç";
    public static string ActionEnable = "Aç";
    public static string OnboardStepFirstScan = "İlk taramanı yap";
    public static string ActionScanDownloads = "İndirilenleri tara";
    public static string CoverageCardTitle = "🛡 Korumam ne kadar açık?";
    public static string CoverageWatchDownloads = "İndirilenler izleniyor";
    public static string CoverageUsbAutoScan = "USB otomatik tarama";
    public static string CoverageScheduledScan = "Zamanlı tarama";
    public static string CoverageContextMenu = "Sağ-tık menüsü";
    public static string TileCaptionFormat = "{0}  ›";
    public static string RecentScansTitle = "Son taramalar";
    public static string RecentEmptyHint = "Henüz tarama yok — yukarıdan bir dosya bırak.";
    public static string LastScanNever = "Son tarama: hiç";
    public static string RecencyYesterday = "dün";
    public static string LastScanPrefix = "Son tarama: ";
    public static string OverviewKeyAvailableFormat = "   •   Anahtar: {0}/{1} kullanılabilir";
    public static string OverviewKeylessOnSuffix = "  •  anahtarsız (GUI) mod açık";
    public static string OverviewWatchingSuffixFormat = "  •  👁 {0} dosya izleniyor";
    public static string HistoryReopenHeadFormat = "{0} — {1} {2}\n\nTam ayrıntı önbellekte yok";
    public static string HistoryReopenRescanSuffix = ".\nDosyayı yeniden taramak ister misin?";
    public static string ReopenFileGoneSuffix = " ve dosya artık şurada değil:\n";
    public static string ReopenNoPath = "(yol yok)";
    public static string BannerTitleAttention = "🔴  Dikkat gerek";
    public static string BannerLiveThreatFormat = "Bilinen zararlı bir dosya hâlâ diskte: {0}";
    public static string BtnOpenHistory = "Geçmişi aç →";
    public static string BannerTitlePending = "🟡  Beklemede";
    public static string BannerNoKeyRationale = "Kullanılabilir anahtar yok ve anahtarsız mod kapalı — tarama yapılamıyor.";
    public static string BannerBitQuarantinedFormat = "{0} dosya karantinada";
    public static string BannerBitOfflineQueueFormat = "{0} dosya çevrimdışı sırada";
    public static string BannerBitWatchingFormat = "{0} dosya izlemede";
    public static string BtnRecheckPlain = "Yeniden denetle";
    public static string BannerTitleProtected = "🟢  Korunuyorsun";
    public static string BannerProtectedRationale = "Diskte bilinen canlı tehdit yok.";
    public static string AttentionEscalationsFormat = "🔴 {0} dosya bir zamanlar temizdi, sonradan tehdide dönüştü (Geçmiş sekmesine bak).";
    public static string AttentionStaleMsg = "Bir süredir tarama yapılmadı — 'İndirilenleri tara' ya da 'Yeniden denetle' ile güncel tut.";
    public static string AttentionNoKeyMsg = "Kullanılabilir API anahtarı yok — Ayarlar'dan anahtar ekle ya da anahtarsız modu aç.";
    public static string AttentionQuarantinedFormat = "{0} dosya karantinada (geri yüklenebilir).";
    public static string AttentionOfflineQueueFormat = "📤 {0} dosya çevrimdışı sırada (internet gelince denenecek).";
    public static string AttentionPrefixFormat = "⚠  {0}";

    // ---- ScanHistoryControl ----
    public static string HistoryThreatsOnlyLabel = "Sadece tehditler";
    public static string HistoryStarredOnlyLabel = "★ Yıldızlılar";
    public static string BtnHistoryClear = "🗑  Geçmişi temizle";
    public static string HistoryClearConfirm = "Tüm tarama geçmişi silinsin mi? (önbellek etkilenmez)";
    public static string BtnHistoryReverdict = "⚠  Sonradan tehdit oldu mu?";
    public static string BtnHistoryExportReport = "📄  Rapor olarak ver…";
    public static string HistoryNoRecordsInRange = "Bu aralıkta kayıt yok.";
    public static string HistoryReportFilter = "HTML|*.html|CSV|*.csv|JSON|*.json";
    public static string HistoryReportFileName = "guvenlik-raporu.html";
    public static string HistoryReportWrittenFormat = "Rapor yazıldı: {0} kayıt ({1}).";
    public static string HistoryRangeLast7Days = "Son 7 gün";
    public static string HistoryRangeLast30Days = "Son 30 gün";
    public static string HistoryRangeLast90Days = "Son 90 gün";
    public static string BtnHistoryRecurring = "🔁  Tekrar eden tehditler";
    public static string BtnHistoryHotspots = "🎯  Tehdit odakları";
    public static string HistoryEscalationBannerFormat = "🔴 Sonradan tehdit oldu: {0} dosya bir zamanlar temizdi, şimdi işaretli (en son: {1} {2}).  İncelemek için tıkla.";
    public static string ColHistoryStar = "★";
    public static string ColHistoryDate = "Tarih";
    public static string ColHistorySource = "Kaynak";
    public static string ColHistoryNote = "Not";
    public static string ColPath = "Yol";
    public static string MenuHistoryRescan = "🔁  Tekrar tara";
    public static string MenuHistoryOpenDetails = "🔎  Ayrıntıyı aç";
    public static string BtnEscalationCopySha = "📋  SHA-256 kopyala";
    public static string MenuHistoryToggleStar = "⭐  Yıldız aç/kapat";
    public static string MenuHistoryEditNote = "📝  Not ekle/düzenle…";
    public static string HistoryNotePrompt = "Bu tarama için not:";
    public static string HistoryCountFormat = "{0} kayıt";
    public static string HistoryCountTotalSuffixFormat = " / {0} toplam";
    public static string HistoryFileGoneFormat = "Dosya artık şurada değil:\n";
    public static string HistoryNoPathInfo = "Bu kaydın dosya yolu yok.";

    // ---- QuotaDashboardControl ----
    public static string QuotaBtnRefreshFromServer = "↻  Sunucudan kotayı yenile";
    public static string QuotaPerKeyLimitsHint = "  4 sorgu/dk • 500/gün • 15.5K/ay (anahtar başına)";
    public static string QuotaNoKeysHint = "Henüz API anahtarı yok. Ayarlar sekmesinden ekleyin.";
    public static string QuotaMeterMinute = "Dakika";
    public static string QuotaMeterDaily = "Günlük";
    public static string QuotaMeterMonthly = "Aylık";
    public static string QuotaStatusDisabledPrefix = "● Devre dışı: ";
    public static string QuotaStatusAuthFallback = "auth";
    public static string QuotaStatusExhausted = "● Dolu — bekleniyor";
    public static string QuotaStatusActive = "● Aktif";
    public static string QuotaAllExhaustedBannerFormat = "Tüm anahtarlar dolu — {0} sonra otomatik devam edilecek…";
    public static string QuotaCountdownHoursFormat = "{0}sa {1}dk";
    public static string QuotaCountdownMinutesFormat = "{0}dk {1}sn";
    public static string QuotaCountdownSecondsFormat = "{0}sn";

    // ---- LogViewerControl ----
    public static string BtnLogClear = "Temizle";
    public static string BtnLogCopyAll = "Tümünü kopyala";
    public static string BtnLogOpenFolder = "Log klasörünü aç";

    // ---- MainForm ----
    public static string ToastUsbScanningTitle = "USB sürücü taranıyor";
    public static string ToastUsbScanningTextFormat = "{0}: takıldı, otomatik taranıyor…";
    public static string ToastUsbInsertedTitle = "USB sürücü takıldı";
    public static string ToastUsbInsertedTextFormat = "{0}: sürücüsünü taramak için bu bildirime tıkla.";
    public static string TabOverview = "🏠  Genel Bakış";
    public static string TabHistory = "🕘  Geçmiş";
    public static string TrayScanClipboard = "📋 Panodaki yolu tara";
    public static string ToastQuietThreatsTitle = "Sessiz modda tehdit bulundu";
    public static string ToastQuietThreatsTextFormat = "{0} tehdit bulundu — incelemek için tıkla.";
    public static string FileRestoredInfo = "Dosya geri yüklendi.";
    public static string ToastScanDoneThreatTitle = "Tarama bitti — tehdit bulundu";
    public static string ToastScanDoneCleanTitle = "Tarama bitti — temiz";
    public static string ToastScanDoneTextFormat = "{0} dosya tarandı, {1} tehdit.";
    public static string ToastThreatTextFormat = "{0}{1}: {2} ({3}/{4})";
    public static string ToastAutoQuarantineTitle = "Tehdit otomatik karantinaya alındı";
    public static string ToastAutoQuarantineTextFormat = "{0}{1} ({2}/{3}) — geri almak için tıkla.";
    public static string ToastQuarantineFallbackTextFormat = "{0}: {1} ({2}/{3})";
    public static string ToastDriftAlarmTitle = "Bütünlük uyarısı!";
    public static string ToastDriftAlarmTextFormat = "{0} izlenen dosya değişti ve güvenini kaybetti: {1}";
    public static string OverviewSweepNoticeFormat = "🌙 Zamanlı tarama {0} tehdit buldu — kuyruğa yüklemek için bildirime tıkla.";
    public static string ToastSweepThreatsTitle = "Zamanlı tarama tehdit buldu";
    public static string ToastSweepThreatsTextFormat = "{0} tehdit bulundu. Kuyruğa yüklemek için tıkla.";
    public static string ToastWatchEscalationTitle = "İzlenen dosya artık daha tehlikeli!";
    public static string ToastWatchEscalationOneFormat = "{0}: {1} → {2} motor tespit ediyor.";
    public static string ToastWatchEscalationManyFormat = "{0} izlenen dosyanın tespiti arttı (ör. {1}).";
    public static string AllowlistReasonAutoActionRule = "oto-eylem kuralı";

    // ---- CommandPaletteForm ----
    public static string CmdPaletteSearchPlaceholder = "⌘  Komut ara…  (örn. kopya, karantina, drift)";

    // ---- QuarantineVaultDialog ----
    public static string BtnVaultPurge = "🗑  Kalıcı sil";
    public static string BtnVaultPurgeAll = "🗑  Tümünü kalıcı sil";
    public static string BtnVaultCleanupOld = "🧹  Eski kayıtları temizle…";
    public static string VaultRecoveredSuffixFormat = "  •  {0} kurtarılan";
    public static string VaultSizeLabelFormat = "{0} dosya  •  geri kazanılabilir {1}{2}";
    public static string VaultPurgeOneConfirmFormat = "{0} kalıcı olarak silinsin mi?\nBu geri ALINAMAZ (dosya kasadan tamamen kaldırılır).";
    public static string VaultPurgeManyConfirmFormat = "Seçili {0} dosya kalıcı olarak silinsin mi?\nBu geri ALINAMAZ.";
    public static string VaultPurgedResultFormat = "{0}/{1} kalıcı silindi.";
    public static string VaultAlreadyEmpty = "Kasa zaten boş.";
    public static string VaultPurgeAllConfirmFormat = "Kasadaki TÜM {0} dosya kalıcı olarak silinsin mi?\nBu geri ALINAMAZ.";
    public static string VaultCleanupPrompt = "Kaç günden eski karantina kayıtları kalıcı silinsin?";
    public static string VaultCleanupTitle = "Eski kayıtları temizle";
    public static string VaultCleanupResultFormat = "{0} kayıt kalıcı silindi.";
    public static string VaultRestoreManyConfirmFormat = "Seçili {0} dosya orijinal konumlarına geri yüklensin mi?";
    public static string VaultRestoreManyResultFormat = "{0}/{1} geri yüklendi.";

    // ---- EscalationDossierDialog ----
    public static string DlgEscalationTitle = "🔴 Sonradan tehdit oldu — dosya geçmişi";
    public static string BtnEscalationLiveReverdict = "🔄  Canlı yeniden denetle (kota)";
    public static string BtnEscalationReveal = "📁  Konumu aç";
    public static string BtnEscalationOpenVt = "🌐  VT'de aç";
    public static string EscalationPresenceOnDisk = "✓ diskte";
    public static string EscalationPresenceGone = "— yok";
    public static string ColEscalationFlippedDate = "Tehdit oldu";
    public static string ColReverdictOldRatio = "Eskiden";
    public static string ColReverdictNewRatio = "Şimdi";
    public static string ColEscalationDaysClean = "Temiz kaldı (gün)";
    public static string EscalationNoRecords = "Kayıtlı sonradan-tehdit dönüşü yok.";
    public static string EscalationSummaryFormat = "{0} dosya sonradan tehdide döndü — {1} tanesi hâlâ diskte.";
    public static string EscalationCannotQuarantineGone = "Bu dosya artık diskte değil — karantinaya alınamaz.";
    public static string EscalationQuarantinedFormat = "Karantinaya alındı: {0}";
    public static string EscalationQuarantineFailedPrefix = "Karantinaya alınamadı: ";
    public static string EscalationFileNotOnDisk = "Dosya diskte bulunamadı.";
    public static string EscalationShaCopied = "SHA-256 kopyalandı.";
    public static string EscalationOpenFailedPrefix = "Açılamadı: ";

    // ---- HelpDialog ----
    public static string HelpDlgTitle = "❓ Yardım — sinyaller ne anlama geliyor?";
    public static string HelpTermShortcuts = "⌨ Klavye kısayolları";
    public static string HelpMeaningShortcuts = "Ctrl+K komut paleti · Ctrl+F ara · Ctrl+C SHA-256 kopyala · Ctrl+Shift+C verdikt görseli (pano) · Ctrl+R yeniden tara · Ctrl+Q karantina · Ctrl+Shift+J tüm tehditleri seç · J/K tehdide atla · Enter VT raporunu aç · Boşluk duraklat/sürdür · F5 verdikt yeniden denetle.";
    public static string HelpTermVerdict = "Verdikt (Temiz/Şüpheli/Zararlı)";
    public static string HelpMeaningVerdict = "Kaç motorun dosyayı işaretlediğine göre verilen sonuç. Eşikleri ve adları Ayarlar'dan değiştirebilirsin.";
    public static string HelpTermConsensus = "Konsensüs — büyük vs küçük motorlar";
    public static string HelpMeaningConsensus = "Tespiti yapanlar büyük/itibarlı motorlar mı, yoksa yalnızca küçük motorlar mı? Sadece küçük motorlar işaretlediyse büyük olasılıkla yanlış pozitiftir.";
    public static string HelpTermSignatureHeuristic = "İmza vs sezgisel/ML";
    public static string HelpMeaningSignatureHeuristic = "İmza eşleşmesi = bilinen bir zararlının parmak izi (kesin). Sezgisel/ML = tahmin (kesin değil). Tüm tespitler sezgiselse temkinli ol.";
    public static string HelpTermFirstSeen = "İlk görülme / nadirlik";
    public static string HelpMeaningFirstSeen = "Dosyanın dünyada ilk ne zaman görüldüğü. Dakikalar önce ilk kez görülen bir dosya, yıllardır bilinen bir dosyadan daha risklidir.";
    public static string HelpTermFamily = "Aile etiketi";
    public static string HelpMeaningFamily = "Motorların ortak adlandırdığı zararlı ailesi (ör. truva atı, fidye). Ne tür bir tehdit olduğunu özetler.";
    public static string HelpTermSignatureTrust = "İmza güveni (İmzalı)";
    public static string HelpMeaningSignatureTrust = "Geçerli bir kod imzası = yayıncının kim olduğu doğrulandı. Bu 'temiz' garantisi DEĞİLDİR; sadece kimliği doğrular. İmzalılar kota harcamamak için VT'ye gönderilmez.";
    public static string HelpTermDownloadSource = "İndirme kaynağı (Zone.Identifier)";
    public static string HelpMeaningDownloadSource = "Dosya internetten mi indirildi ve hangi siteden? İnternetten gelen dosyalar daha dikkatli incelenmeli.";
    public static string HelpTermBehaviour = "Davranış / yetenek özeti";
    public static string HelpMeaningBehaviour = "Dosyanın ne yaptığı: ağ iletişimi, kalıcılık, anti-analiz, tuş kaydı vb. (VT etiketlerinden, çalıştırmadan).";
    public static string HelpTermOverlay = "Overlay (imza sonrası ek bayt)";
    public static string HelpMeaningOverlay = "İmzalı bir dosyaya imzadan sonra eklenmiş veri. Kurulumcularda normaldir ama doldurulmuş/trojanlı bir dosyanın işareti de olabilir.";
    public static string HelpTermStale = "Eski imza (stale)";
    public static string HelpMeaningStale = "Tespit aylarca eski imzalardan geliyorsa, güncel motorlarla yeniden denetlemek mantıklı olabilir.";
    public static string HelpTermQuarantine = "Karantina (.VIRUS)";
    public static string HelpMeaningQuarantine = "Şüpheli dosyanın uzantısını .VIRUS yaparak çalıştırılamaz hale getirir. Geri dönüşü vardır — Karantina kasasından geri yükleyebilirsin.";
    public static string HelpTermKeyless = "Anahtarsız (GUI) mod";
    public static string HelpMeaningKeyless = "API anahtarı yerine gizli bir tarayıcı ile VT'nin web arayüzünü kullanır: kotasız ama daha yavaş.";

    // ---- DownloadsTriageDialog ----
    public static string DlgDownloadsTriageTitle = "📥 İndirilenler triyajı";
    public static string IncidentWindowItemFormat = "Son {0} gün";
    public static string BtnDownloadsRefresh = "🔄  Yenile";
    public static string BtnScanUnscanned = "🔎  Taranmamışları tara";
    public static string DownloadsNoUnscanned = "Taranmamış dosya yok.";
    public static string IncidentWindowLabel = "Pencere:";
    public static string ColDownloadSource = "Kaynak (indirme)";
    public static string ColSignature = "İmza";
    public static string DownloadsSameSourceBadgeFormat = "{0}  ⚑ aynı kaynak ×{1}";
    public static string IncidentScanning = "Taranıyor…";
    public static string IncidentScanningProgressFormat = "Taranıyor… {0}/{1}";
    public static string DownloadsSummaryFormat = "{0} dosya • {1} taranmamış • {2} tehdit (önbellekten)";
    public static string DownloadsErrorFormat = "Hata: {0}";

    // ---- HistoryReverdictDialog ----
    public static string DlgReverdictTitle = "⚠ Sonradan tehdit oldu mu?";
    public static string BtnReverdictRecheck = "🔄  Yeniden denetle";
    public static string BtnRescanSelected = "🔁  Seçileni yeniden tara";
    public static string ReverdictSelectRowOnDisk = "Diskte bulunan bir satır seç.";
    public static string ColReverdictFirstScan = "İlk tarama";
    public static string ReverdictNeedKeyless = "Anahtarsız (GUI) mod kapalı — bu denetim kotasız yeniden sorgu gerektirir.";
    public static string ReverdictChecking = "Geçmiş yeniden denetleniyor…";
    public static string ReverdictProgressFormat = "Yeniden denetleniyor… {0}/{1}";
    public static string ReverdictNoneFound = "Sonradan tehdide dönüşen, hâlâ diskte olan dosya bulunamadı.";
    public static string ReverdictFoundFormat = "{0} dosya bir zamanlar temizdi, şimdi işaretli ve hâlâ diskte.";

    // ---- ThreatHotspotDialog ----
    public static string DlgThreatHotspotTitle = "🎯 Tehdit odakları";
    public static string ThreatHotspotNone = "Tekrar tehdit üreten bir klasör bulunamadı.";
    public static string ThreatHotspotHeaderFormat = "{0} klasör tekrar tehdit üretti — tek dosyayı silmek yerine kaynağı kapatmayı düşün.";
    public static string ColDistinctThreats = "Farklı tehdit";
    public static string ColSpan = "Aralık";
    public static string ColSamples = "Örnekler";
    public static string BtnRescanFolder = "🔁  Klasörü yeniden tara";
    public static string BtnOpenFolder = "📁  Klasörü aç";

    // ---- IncidentTimelineDialog ----
    public static string DlgIncidentTimelineTitle = "🕓 Olay Zaman Çizelgesi";
    public static string BtnIncidentScan = "🔍  Tara";
    public static string ColDay = "Gün";
    public static string ColTime = "Saat";
    public static string IncidentSummaryFormat = "{0} gün • {1} çalıştırılabilir • {2} tehdit (önbellekten)";

    // ---- PersistenceHooksDialog ----
    public static string PersistHooksTitleFormat = "🔗 Autostart kancaları — {0}";
    public static string PersistHooksColCommand = "Komut";
    public static string BtnPersistRemoveHook = "🗑  Seçili kancayı kaldır";
    public static string PersistHooksHeaderFormat = "{0} kalıcılık kancası bulundu. Kaldırma geri alınabilir: kayıt değeri quarantine\\autostart-restore.log'a yazılır, Başlangıç .lnk'i kasaya taşınır.";
    public static string PersistHookRemoveConfirmFormat = "Bu autostart kancası kaldırılsın mı?\n[{0}] {1}";
    public static string PersistHookRemovedInfo = "Kanca kaldırıldı (geri alınabilir).";
    public static string PersistUnknownError = "bilinmeyen hata";
    public static string PersistHookRemoveFailedHklmNote = "\n(HKLM kancaları yönetici hakları gerektirir.)";

    // ---- RecurrenceDialog ----
    public static string DlgRecurrenceTitle = "🔁 Tekrar eden tehditler";
    public static string RecurrenceNone = "Aynı tehdit birden fazla taramada tekrarlanmadı.";
    public static string RecurrenceHeaderFormat = "{0} tehdit ayrı taramalarda tekrar belirdi — kaynağı hâlâ canlı olabilir.";
    public static string ColRecurrenceTimes = "Kez";
    public static string BtnOpenLastLocation = "📁  Son konumu aç";

    // ---- CliRunner ----
    public static string CliSweepResultWriteErrorPrefix = "Tarama sonucu yazılamadı: ";
    public static string CliSecMitre = "MITRE ATT&CK";
    public static string CliWatchListEmpty = "İzleme listesi boş.";
    public static string CliWatchRecheckingFormat = "{0} izlenen dosya yeniden denetleniyor (anahtarsız)…";
    public static string CliWatchNoEscalation = "Tespit artışı yok.";
    public static string CliWatchEscalationFormat = "[ARTIŞ] {0}: {1} → {2}/{3} motor";
    public static string CliTimelineScanningFormat = "Son {0} günde gelen çalıştırılabilirler taranıyor (verdikt önbellekten)…";
    public static string CliTimelineSummaryFormat = "{0} gün • {1} çalıştırılabilir • {2} tehdit (önbellekten)\n";
    public static string CliTimelineDayFormat = "{0}  —  {1} dosya, {2} tehdit, {3} internetten";
    public static string CliVerdictError = "HATA";

    // ---- ReportWriter ----
    public static string ReportCsvHeader = "Dosya,Verdikt,Zararlı,Şüpheli,Toplam,Aile,MD5,SHA256,RaporURL";
    public static string ReportTextTitleFormat = "{0} v{1} — tarama raporu";
    public static string ReportTextSummaryFormat = "Dosya: {0}   Tehdit: {1}   İmzalı-atlandı: {2}   Hata: {3}";
    public static string ReportTextErrorPrefix = "    hata: ";
    public static string ReportHtmlDocTitleFormat = "{0} raporu";
    public static string ReportHtmlPrintLink = "🖨 Yazdır / PDF";
    public static string ReportHtmlHeadingFormat = "{0} — tarama raporu";
    public static string ReportHtmlSummaryFormat = "Dosya: {0} &nbsp; Tehdit: <b class=\"threat\">{1}</b> &nbsp; İmzalı-atlandı: {2} &nbsp; Hata: {3}";
    public static string ReportHtmlTableHead = "<table><thead><tr><th>Verdikt</th><th>Tespit</th><th>Dosya</th><th>Konsensüs / ayrıntı</th></tr></thead><tbody>";
    public static string ReportHtmlTrustedSignature = "güvenilen imza";
    public static string ReportHistoryCsvHeader = "Tarih,Dosya,Verdikt,Tespit,Toplam,Kaynak,MD5,SHA256,RaporURL";
    public static string ReportHistoryTitleFormat = "{0} — güvenlik raporu";
    public static string ReportHistorySummaryFormat = "Aralık: <b>{0}</b> &nbsp;•&nbsp; Tarandı: {1} &nbsp;•&nbsp; Tehdit: <b class=\"threat\">{2}</b> &nbsp;•&nbsp; Temiz: <b class=\"clean\">{3}</b>";
    public static string ReportHistorySourceBreakdownHeading = "<h2>Kaynak kırılımı</h2><div class=\"sum\">";
    public static string ReportHistoryWeeklyTrendHead = "<h2>Haftalık eğilim</h2><table><thead><tr><th>Hafta başı</th><th>Tarandı</th><th>Tehdit</th></tr></thead><tbody>";
    public static string ReportHistoryThreatsHeadingFormat = "Tehditler ({0})";
    public static string ReportHistoryThreatsTableHead = "<table><thead><tr><th>Tarih</th><th>Dosya</th><th>Tespit</th><th>Kaynak</th><th>SHA-256</th></tr></thead><tbody>";

    // ---- ShareCard ----
    public static string ShareCardDetectedFormat = "{0}/{1} motor tespit etti";
    public static string ShareCardSignedSkipped = "İmzalı — VT taraması atlandı";
    public static string ShareCardSha256Label = "SHA-256  ";
    public static string ShareCardFamilyLabel = "Aile: ";
    public static string ShareCardLocalFirstSeenFormat = "Bu makinede ilk görülme: {0:yyyy-MM-dd}";
    public static string ShareCardMd5Label = "MD5    ";
    public static string ShareCardSha256TextLabel = "SHA256 ";
    public static string ShareCardMdTypeLabel = "- **Tür:** ";
    public static string ShareCardMdFamilyLabel = "- **Aile:** ";
    public static string ShareCardMdReportLink = "- [VirusTotal raporu](";
    public static string ShareCardThreatTagPrefix = "🏷 ";

    // ---- MitreGlossary ----
    public static string MitreTacticPersistence = "Kalıcılığı sağlama";
    public static string MitreMeaningT1547 = "Windows açılışta kendini otomatik başlatacak şekilde yerleşiyor";
    public static string MitreMeaningT1053 = "Zamanlanmış görev oluşturarak kalıcı oluyor";
    public static string MitreMeaningT1543 = "Bir sistem servisi kurarak kalıcı oluyor";
    public static string MitreMeaningT1546 = "Bir olay tetikleyicisine kendini bağlıyor (açılışta çalışır)";
    public static string MitreTacticDefenseEvasion = "Savunmayı atlatma";
    public static string MitreMeaningT1055 = "Kendini başka bir sürecin içine enjekte ediyor (gizlenme)";
    public static string MitreMeaningT1027 = "Kodunu gizliyor/şifreliyor, analizden kaçıyor";
    public static string MitreMeaningT1112 = "Kayıt defterini değiştiriyor";
    public static string MitreMeaningT1070 = "İzlerini siliyor (log/dosya temizleme)";
    public static string MitreMeaningT1562 = "Güvenlik araçlarını/korumaları devre dışı bırakmaya çalışıyor";
    public static string MitreMeaningT1497 = "Sanal makine/sandbox tespit edip davranışını gizliyor";
    public static string MitreTacticImpact = "Etki";
    public static string MitreMeaningT1486 = "Dosyaları şifreleyip fidye isteyebilir (ransomware)";
    public static string MitreMeaningT1490 = "Sistem kurtarmayı engelliyor (gölge kopyaları siliyor)";
    public static string MitreMeaningT1489 = "Servisleri durduruyor";
    public static string MitreTacticCommandControl = "Komuta-kontrol";
    public static string MitreMeaningT1071 = "Uzak bir sunucuyla ağ üzerinden haberleşiyor";
    public static string MitreMeaningT1105 = "İnternetten ek dosya/yük indiriyor";
    public static string MitreMeaningT1095 = "Standart olmayan bir protokolle dışarı bağlanıyor";
    public static string MitreTacticExfiltration = "Veri sızdırma";
    public static string MitreMeaningT1041 = "Veriyi komuta kanalı üzerinden dışarı çıkarıyor";
    public static string MitreTacticCredentialTheft = "Kimlik bilgisi çalma";
    public static string MitreMeaningT1056 = "Klavye girişlerini kaydedebiliyor (keylogger)";
    public static string MitreMeaningT1003 = "Sistemden parola/kimlik bilgisi çıkarmaya çalışıyor";
    public static string MitreTacticExecution = "Çalıştırma";
    public static string MitreMeaningT1059 = "Komut satırı/script ile komut çalıştırıyor";
    public static string MitreMeaningT1204 = "Kullanıcının dosyayı açmasıyla çalışıyor";
    public static string MitreTacticDiscovery = "Keşif";
    public static string MitreMeaningT1082 = "Sistem bilgilerini topluyor";
    public static string MitreMeaningT1083 = "Dosya ve dizinleri tarıyor";
    public static string MitreMeaningT1057 = "Çalışan süreçleri listeliyor";
    public static string MitreMeaningT1518 = "Yüklü güvenlik yazılımlarını araştırıyor";
    public static string MitreMeaningT1016 = "Ağ yapılandırmasını inceliyor";
    public static string MitreTacticLateralMovement = "Yatay hareket";
    public static string MitreMeaningT1021 = "Ağdaki diğer makinelere yayılmaya çalışıyor";
    public static string MitreMeaningT1036 = "Meşru bir dosya gibi görünmeye çalışıyor (masquerading)";
    public static string MitreTacticOther = "Diğer teknikler";

    // ---- BehaviourDigest ----
    public static string DigestNetworkFormat = "{0} ağ adresine/sunucuya bağlanıyor";
    public static string DigestFilesWrittenFormat = "{0} dosya yazıyor/bırakıyor";
    public static string DigestPersistence = "Otomatik başlatma/kalıcılık anahtarı yazıyor — yeniden başlatmada hayatta kalır";
    public static string DigestRegistryFormat = "{0} kayıt defteri anahtarı değiştiriyor";
    public static string DigestProcessesFormat = "{0} başka süreç başlatıyor";
    public static string DigestMitreFormat = "{0}: {1}";
    public static string DigestNoImpact = "Kayda değer bir sistem etkisi gözlenmedi";

    // ---- VerdictCategories ----
    public static string VerdictCatCleanName = "TEMİZ";
    public static string VerdictCatSuspiciousName = "ŞÜPHELİ";
    public static string VerdictCatVirusName = "VİRÜS";

    // ---- ConfirmGate ----
    public static string GateQuarantineTitle = "Karantina";
    public static string GateQuarantineQuestion = "Bu dosya karantinaya alınsın mı? (çalıştırılamasın diye uzantısı .VIRUS yapılır)";
    public static string GateContextMenuInstallTitle = "Sağ tuş menüsü kurulumu";
    public static string GateContextMenuInstallQuestion = "Sağ tuş menüsüne 'VirusTotal ile tara' eklensin mi? (yönetici gerekebilir)";
    public static string GateClearCacheQuestion = "Yerel tarama önbelleği (cache.json) temizlensin mi?";
    public static string GateDeleteKeyTitle = "Anahtar sil";
    public static string GateDeleteKeyQuestion = "Bu API anahtarı silinsin mi?";
    public static string ConfirmDontAskAgain = "Bir daha sorma";

    // ---- PersistenceHunter ----
    public static string PersistLocStartupUser = "Başlangıç (kullanıcı)";
    public static string PersistLocStartupCommon = "Başlangıç (ortak)";
    public static string PersistTaskNameFallback = "(görev)";
    public static string PersistLocScheduledTask = "Zamanlanmış görev";
    public static string PersistTaskDeleteExitFormat = "schtasks çıkış {0}";

    // ---- ScanScheduler ----
    public static string SkipReasonTooLargeFormat = "çok büyük (>{0} MB)";
    public static string SkipReasonKnownGoodList = "Bilinen temiz (yerel liste)";
    public static string SkipReasonDevFolder = "Geliştirme klasörü (kullanıcı onayı)";
    public static string ItemErrorNoReport = "VT'de bulunamadı veya sorgu sonuç vermedi (yükleme için API anahtarı gerekir).";
    public static string UploadProgressDetailFormat = "Yükleniyor… {0:F0}%  {1}/{2}  ({3}/s)";
    public static string PollProgressDetailFormat = "Analiz bekleniyor… (durum: {0}, {1}. yoklama)";

    // ---- GuiScrapeService ----
    public static string CaptchaWindowTitle = "VirusTotal — reCAPTCHA";
    public static string CaptchaBarPrompt = "  VirusTotal reCAPTCHA istedi. Lütfen aşağıda çözün, sonra sağdaki düğmeye basın.";
    public static string CaptchaBtnSolved = "Çözdüm, devam et";
    public static string CaptchaBtnSwitchToApi = "API anahtarına geç";

    // ---- DownloadsTriageService ----
    public static string DownloadsTriageSignedFormat = "✓ {0}";

    // ---- AllowlistStore ----
    public static string AllowlistHealthStale = "⚠ ARTIK İŞARETLİ";
    public static string AllowlistHealthUnchecked = "denetlenmedi";
    public static string AllowlistHealthClean = "temiz";
    public static string AllowlistReasonImportedFromHistory = "Geçmişten içe aktarıldı (temiz)";

    // ---- BaselineStore ----
    public static string BaselineDriftMissing = "dosya artık yok";
    public static string BaselineDriftUnchanged = "değişmedi";
    public static string BaselineDriftLostTrustFormat = "DEĞİŞTİ ve imza sürekliliği kayboldu: '{0}' → '{1}'";
    public static string BaselineSignerInvalid = "imzasız/geçersiz";
    public static string BaselineDriftSamePublisher = "değişti (aynı yayıncı imzaladı — normal güncelleme)";
    public static string BaselineDriftWasUnsigned = "değişti (zaten imzasızdı)";

    // ---- QuarantineVault ----
    public static string VaultNoSpaceFormat = "Kasada yer yok — en az {0} MB boşaltın.";
    public static string VaultVerdictRecovered = "kurtarıldı";
    public static string VaultFileNotFound = "Kasa dosyası bulunamadı.";
    public static string VaultTamperedNoRestore = "Kasa dosyası karantinaya alındığından beri değişmiş — geri yükleme güvenli değil. Bunun yerine 'Kalıcı sil' kullanın.";
    public static string VaultOriginalPathOccupied = "Orijinal konumda zaten bir dosya var.";

    // ---- Program ----
    public static string FatalUnexpectedErrorFormat = "Beklenmeyen hata:\n{0}";
    public static string UiThreadExceptionFormat = "Beklenmeyen bir hata oluştu (loglandı):\n{0}";
    public static string CliFatalFormat = "FATAL: {0}";

    // ---- DownloadsWatcher ----
    public static string WatcherLureLabel = "çift uzantı tuzağı";
    public static string WatcherArchiveMemberFormat = "› {0}";

    // ---- ZoneIdentifier ----
    public static string ZoneLocalMachine = "Yerel makine";
    public static string ZoneLocalNetwork = "Yerel ağ (intranet)";
    public static string ZoneTrustedSite = "Güvenilen site";
    public static string ZoneInternet = "İnternet";
    public static string ZoneRestrictedSite = "Kısıtlı site";
    public static string ZoneDownloadedWarn = "  ⚠ internetten indirildi";
    public static string ZoneSummaryBothFormat = "📥 Kaynak bölgesi: {0}{1}\n   Kaynak (CDN/host): {2}\n   Yönlendiren sayfa: {3}";
    public static string ZoneSummaryFormat = "📥 Kaynak bölgesi: {0}{1}{2}";
    public static string ZoneSourceSuffixFormat = " — {0}";

    // ---- PE identity / signer continuity / process-start / key rotation / quota units ----
    public static string PeImpersonationFormat = "⚠ '{0}' olduğunu iddia ediyor ama imza {1} — TAKLİT olabilir";
    public static string PeSigDifferentPrefix = "farklı: ";
    public static string PeSigMissingInvalid = "yok/geçersiz";
    public static string PeNameMismatchFormat = "📛 gömülü ad '{0}' ≠ disk adı '{1}'";
    public static string SignerContinuityFormat = "⚠ '{0}' normalde '{1}' tarafından imzalı; bu dosya {2} — olası sahte/trojanlı sürüm";
    public static string SignerDifferentPublisherPrefix = "farklı yayıncı: ";
    public static string OriginNoteCaughtAtLaunch = "çalıştırılırken yakalandı";
    public static string ErrNoKeysDefined = "Hiç API anahtarı tanımlı değil. Ayarlar'dan bir VirusTotal anahtarı ekleyin.";
    public static string QuotaUnitMinute = "dk";
    public static string QuotaUnitDay = "gün";
    public static string QuotaUnitMonth = "ay";
}
