# VirusTotal Scanner

Windows (WinForms, .NET 10) uygulaması: dosya, çoklu seçim veya klasör (alt klasörler dahil)
sağ tıklayıp VirusTotal'de tarar. Tek exe + tek ayar dosyası.

## Çalışma modları (tek exe)
- **Çift tık / argümansız** → tam grafik arayüz.
- **Dosya/klasör argümanı (sağ tuş veya exe'ye sürükle-bırak)** → arayüzde tarama; çalışan
  bir örnek varsa yollar ona iletilir (tek kuyruk).
- **Terminalden** → komut satırı modu (arayüz açılmaz, çıktı konsola, exit code döner).

## Kurulum / kullanım
1. `publish\small\VirusTotalScanner.exe` (küçük, .NET 10 Desktop Runtime gerekir) **veya**
   `publish\portable\VirusTotalScanner.exe` (büyük, hiçbir şey gerekmez) çalıştırın.
2. İlk açılışta sihirbaz: bir VirusTotal API anahtarı ekleyin, isterseniz sağ tuş menüsüne ekleyin.
3. Ayarlar → "Sağ tuşa ekle" ile dosya/klasör sağ tuş menüsüne yerleşir (yönetici gerekmez).

## Komut satırı
```
VirusTotalScanner.exe <dosya|klasör> [...]   # tara
  -r, --recurse        klasörleri alt klasörlerle tara
      --no-trust       imza güvenini yok say (imzalıları da VT'ye gönder)
  -j, --json           JSON çıktı (stdout)
  -q, --quiet          yalın çıktı
      --install/--uninstall/--repair   sağ tuş menüsü (HKLM, yönetici/UAC)
      --addkey <KEY> / --listkeys / --removekey <id|all>
      --lookup <hash>  MD5/SHA-1/SHA-256 sorgula
  -h, --help / -v, --version
```
Çıkış kodları: `0` temiz, `1` tehdit, `2` kullanım/IO, `3` anahtar yok.
Betikte beklemek için: `Start-Process -Wait VirusTotalScanner.exe ...`

## Anahtarsız / kotasız kontrol
VirusTotal API'si her hash sorgusu için anahtar ister (kotaya sayılır); eski anahtarsız
Cymru MHR servisi kapanmış, `vt` CLI de aynı anahtarı/kotayı kullanır. İki gerçek anahtarsız yol var:

**1) Yerel imza ön-filtresi.** Geçerli imzalı (gömülü VEYA katalog imzalı — örn. tüm Windows
dosyaları) dosyalar `WinVerifyTrust` ile doğrulanıp **VT'ye hiç gönderilmez** — anahtar yok, kota
yok, pratikte sınırsız. "İmzalı (taranmadı)" diye işaretlenir; imza = yayıncı doğrulandı demektir,
"temiz" garantisi DEĞİLDİR (yeşil rozet verilmez). Varsayılan: yalnızca Microsoft imzalılar atlanır;
Ayarlar → Güven Kaynakları'ndan ek yayıncı, "tüm geçerli imzalar" veya bilinen-temiz hash listesi
eklenebilir. Sağ tık → "Güveni yok say, VT ile tara" ile zorla.

**2) Anahtarsız GUI sorgusu (WebView2).** Ayarlar → Güven Kaynakları → "Anahtarsız sorgu" (veya CLI
`--keyless`). Gizli bir tarayıcı (WebView2) VirusTotal'in herkese açık sayfasını açar ve sayfanın
kendi veri çağrısının yanıtını yakalar — anahtar yok, kota yok, ama **yavaştır** ve yalnızca sorgu
yapar (bilinmeyen dosyayı yükleyemez). Çalışması için Windows'ta WebView2 Runtime gerekir (Win11'de
hazır gelir).

## Özellikler
- MD5 ile var-mı kontrolü; yoksa ayrıntılı yükleme çubuğuyla yükleyip analiz bekler.
- Çok anahtar + dönüşümlü kullanım; biri dolunca diğerine geçer; hepsi dolunca geri sayımla
  bekler (kapanmaz), reset olunca otomatik devam eder.
- Anahtar başına dakika (4) / günlük (500) / aylık (15.5K) kota takibi, canlı pano.
- Anahtarlar DPAPI ile şifrelenip ayar dosyasında saklanır (ayrı dosya yok).
- Polly ile dayanıklı HTTP (yeniden deneme/backoff; 429'da anahtar değiştirme).
- Hangi antivirüsün pozitif verdiğini tablo + tespit oranı çubuğu + verdict rozeti.
- Yerel hash önbelleği (kota tasarrufu), sürükle-bırak, sistem tepsisi + tehdit bildirimi,
  karantina, CSV dışa aktarma, koyu/açık tema, canlı log görüntüleyici, sağ tuş onar/kaldır.

## Geliştirme
```
dotnet build                 # derle
dotnet run                   # arayüzü çalıştır
.\publish.ps1                # iki tek-exe profili (publish\small, publish\portable)
```
Loglar/önbellek `%AppData%\VirusTotalScanner\` altında; ayar dosyası exe'nin yanında
(yazılamıyorsa %AppData%'da).
