# Dokümantasyon Fihristi

Bu klasör `VirusTotalScanner` projesinin kalıcı teknik bilgisini, doğrulanan yöntemlerini ve mimari kararlarını barındırır. Görevle ilgili dalı aşağıdan seçip oku.

## Temel Belgeler

- [Dokümantasyon-Nasıl-Yapılır.md](Dokümantasyon-Nasıl-Yapılır.md) — Bu projede kalıcı bilginin nasıl yazılacağı, ne zaman güncelleneceği ve fihrist bakımı kuralları.
- [depolama-duzeni.md](depolama-duzeni.md) — Portable üç klasörlü veri yerleşimi (`UserData`, `UserCache`, `AppCache`), `VerdictLedger.json` ve otomatik eski düzen migrasyonu.
- [guncelleme.md](guncelleme.md) — Tek dosya self-contained ve framework-dependent derleme, Authenticode imzalama, yerel dağıtım ve GitHub release adımları.

## Teknik Dersler ve Mimari Notlar

- [keyless-vt-brainstorm-orchestration.md](keyless-vt-brainstorm-orchestration.md) — Anahtarsız tarayıcı sorgusu ve çoklu rota/direnç yaklaşımı.
- [quarantine-move-safety.md](quarantine-move-safety.md) — Karantina taşıma güvenliği ve manifest koruması.
- [winforms-overlay-zorder.md](winforms-overlay-zorder.md) — WinForms katman sıralaması (Z-order) notları.
- [winforms-responsive-dpi-layout.md](winforms-responsive-dpi-layout.md) — WinForms yüksek DPI ve duyarlı düzen ilkeleri.
- [wmi-process-start-guard.md](wmi-process-start-guard.md) — WMI süreç başlatma izleyici davranışı ve sınırları.
- [autonomous-loop-discipline.md](autonomous-loop-discipline.md) — Otonom döngü ve görev takip disiplini.
- [coding-principles.txt](coding-principles.txt) — Proje kodlama standartları.
