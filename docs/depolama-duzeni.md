# Portable Depolama Düzeni

`VirusTotalScanner`, çalıştığı klasör yazılabiliyorsa tüm durumunu kendi kök dizininde üç standart klasörde tutar (`ConfigPathResolver.cs`). Yalnızca kök klasör salt okunursa `%AppData%\VirusTotalScanner` konumuna düşer.

## Klasör Yapısı

```text
VirusTotalScanner\
  VirusTotalScanner.exe
  UserData\                 # Kalıcı kullanıcı verileri (asla otomatik temizlenmez)
    Settings\               # VirusTotalScanner.config, ConfirmGates.json, BannerMutes.json, ScanProfiles.json, AutoActions.json
    Language\               # lang.tr.xml, lang.en.xml (gömülü kaynaktan ilk açılışta çıkarılır)
    Verdicts\               # VerdictLedger.json (eski cache.json), ScanHistory.json, BehaviourDigest.json, IocIndex.json, PendingOutbox.json, ReverdictWatch.json, Escalations.json, SweepResult.json, SweepReport.html
    Trust\                  # Allowlist.json, FolderAllowlist.json, Baseline.json, ProductSigners.json
    Quarantine\             # Karantina dosyaları ve manifesti
    Backups\                # Acil düz-metin anahtar yedeği, bozuk vault yedeği, VerdictLedger yedek fallback'i
  UserCache\                # Yeniden üretilebilir kullanıcı önbelleği (yer açmak için silinebilir)
    Fingerprints.json       # Yerel dosya path+boyut+mtime -> MD5/SHA-256 önbelleği
  AppCache\                 # Oturuma özgü, güvenle silinebilir geçici veriler
    Logs\                   # Uygulama günlükleri
    BrowserCache\           # 150 slota kadar sıfır-çerezli WebView2 profilleri
    Tor\                    # torrc ve Data\ (Tor çalışma dizini)
    Session\                # ScanSession.json (yarım kalan tarama oturumu)
    Diagnostics\            # route-probe-*.txt, scan-plan-*.txt
```

## Karar Gerekçeleri

- **`cache.json` -> `UserData\Verdicts\VerdictLedger.json`:** Bu dosya yeniden indirilmesi bedava olan bir önbellek değil, harcanmış VirusTotal API kotasının kalıcı karar defteridir. Adında `Cache` veya `Data` geçmediği için temizlik araçlarıyla karıştırılmaz ve `UserData` altında korunur.
- **`Fingerprints.json` -> `UserCache\`:** Diskteki dosyalardan yeniden hesaplanabilir (~85 MB) bir hızlandırma önbelleğidir; kullanıcı yer açmak için `UserCache` klasörünü sildiğinde kalıcı veri kaybı olmaz.
- **Gömülü `lang.en.xml`:** `VirusTotalScanner.csproj` içinde `EmbeddedResource` (`LogicalName="VirusTotalScanner.lang.en.xml"`, `WithCulture="false"`) olarak paketlenir; `LocManager.Init()` bunu `UserData\Language\lang.en.xml` konumuna çıkarır. Böylece dağıtım kökünde yalnızca `VirusTotalScanner.exe` bulunur.
- **Kayıpsız Migrasyon (`StorageMigration.cs`):** `Program.InitCore()` içinde `SettingsManager.LoadSettings()` öncesinde çalışır. Eski düz kökteki dosyaları yeni hedefte karşılığı yoksa taşır; mevcut yeni dosyaların üstüne asla yazmaz.
- **Temizlik Kaydı:** Disk temizleme listesine (`program-onbellekleri.txt`) yalnızca `AppCache` ve `UserCache` yazılır; `UserData` asla eklenmez.
