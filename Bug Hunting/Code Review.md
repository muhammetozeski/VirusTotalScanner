# Kod Gözden Geçirme — Faz 2 (2026-09-01)

124 kaynak dosyanın tamamı okundu (JargonGlossary/MitreGlossary sözlük verileri hızlı geçildi).
Kontrol listesi: hata yutma, UI çizim disiplini, kod tekrarı, merkezi yönetim, sadeleştirme,
statik/const, null, isimlendirme+summary, resilience, switch/if.

## Düzeltilen bulgular

| Bulgu | Dosya(lar) | Commit |
|---|---|---|
| `+` / `??` öncelik hatası: unhandled-exception log fallback'i hiç çalışmıyordu | Core\Program.cs | 512abbe |
| Kilitsiz paylaşılan store'lar (ProductSignerRegistry paralel tarama yolunda AKTİF yarış; BaselineStore periyodik-verify×UI; QuarantineVault arka plan karantina×dialog; IocStore) | Stores\BaselineStore, IocStore, QuarantineVault; Security\ProductSignerRegistry | b620856 |
| WatchService lookup'larına ct geçmiyordu | Stores\ReverdictWatchStore.cs | c2273bf |
| Restore Task'i lambda'ya atılıyordu (CS4014) + dialog'un kendi FormatBytes kopyası | Ui\Dialogs\QuarantineVaultDialog.cs | 0b7f830+50eff38 |
| CLI verdict renkleri hardcoded "ZARARLI/ŞÜPHELİ/TEMİZ" adlarına bağlıydı (yeniden adlandırma/İngilizce UI renkleri kaybediyordu) | Cli\CliRunner.cs | a3cb30f |
| Hardcoded Türkçe metinler (SweepScheduler×2, PE kimlik satırı, IOC "ara ↗", ledger diff) | 5 dosya + Strings + lang.en.xml | def44d4 |
| VT URL literalleri (3×GuiScrape+ReportWriter+Helper), 7×el yapımı explorer /select, Logger'daki DeleteOldestFiles kopyası, iki kontroldeki özdeş history-Reopen akışı | 10 dosya, yeni Ui\HistoryReopen.cs | 39021e1 |
| GuiScrapeService'te 3× kopyalanmış navigate-yakala iskeleti → tek FetchJsonAsync (Lookup'ın "önceki çağrı suffix'i sıfırlamıştır" varsayımı da kalktı) | Services\GuiScrapeService.cs | 1ab2d74 |
| AtomicFile'ın atomik olmayan Copy fallback'i sessizdi (vault decrypt hatasının baş şüphelisi) | Core\AtomicFile.cs | 65ddee8 |
| AdminHelper bayat özet (HKCU değil HKLM) | Core\AdminHelper.cs | 768a89f |
| `Update(entry)` parametreyi hiç kullanmıyordu → `Persist()` | Stores\ReverdictWatchStore.cs | 712cd91 |
| DiffService gereksiz koşul | Services\DiffService.cs | da7bb57 |
| Downloads triage dosya hatalarını sessizce atlıyordu | Services\DownloadsTriageService.cs | 3443971 |

## Bilinçli bırakılanlar (bug değil)
- Logger içi `catch { }`'ler: loglama hatası loglanamaz; DiskWriter thread'ini yaşatmak için bilinçli.
- EntityGridView OnHandleCreated/SetSelectedRowCore IndexOutOfRange yutmaları: belgeli WinForms yarışı.
- TaskbarProgress/ConsoleBootstrap best-effort catch'leri: belgeli, yan işlev.
- OverlayDetector catch→0: "sinyal, verdikt değil" sözleşmesi.
- KnownGoodDb.Contains hızlı-yol Count okuması: geçici yanlış-negatif, zararsız.
- PauseTokenSource `??=` teorik yarışı: Pause yalnızca UI thread'den çağrılıyor.
- HashService'teki üç buffer döngüsü: farklı hash kombinasyonları; birleştirme okunabilirliği düşürür (prensip 2).

## Faz 3–5'e devredilenler
- **Faz 3:** ProcessStartGuard admin yokken sessizce kapalı kalıyor (config'de açık!) — hub + Coverage kartında görünür olacak. Arka plan işlerinin tamamı (catch-up, re-check, sweep) UI'da görünmez.
- **Faz 5:** ScanHistoryControl RefreshEscBanner hardcoded renkleri; CoverageRow 240px etiket kırpması; QuotaDashboard sabit pixel kart yerleşimi; SettingsControl sabit kart yükseklikleri; overview banner'ının eylem butonu snapshot'ta görünmüyor.
- Strings.cs'te kullanılmayan anahtar taraması yapılmadı (düşük öncelik).
