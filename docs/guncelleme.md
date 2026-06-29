# Güncelleme / derleme & yayınlama runbook'u

Yayınlanan programı (`C:\E\kp\aaBenimProgramlarim\VirusTotalScanner`) güncellemek için
izlenen adımlar. Çıktı: **tek dosya, kendi kendine yeten (self-contained / framework
bağımsız), ReadyToRun** bir exe.

## Hedef davranış

- Derleme öncesi ve sonrası `bin` ve `obj` klasörleri temizlenir (temiz çıktı + repo'da iz bırakmaz).
- **Hiçbir şey kalıcı silinmez.** Silinecek her şey (eski exe, `bin`, `obj`) **Geri Dönüşüm
  Kutusu'na** yollanır.
- Yeni exe kopyalanmadan **önce**, hedefteki eski `VirusTotalScanner.exe` Geri Dönüşüm
  Kutusu'na gönderilir.
- Yayın klasöründe **yalnızca `VirusTotalScanner.exe` ve `lang.en.xml` değişir.**
  Oradaki çalışma-zamanı verisine (`VirusTotalScanner.config`, `cache.json`, `history.json`,
  `allowlist.json`, `lang.tr.xml`, `Logs\`, `Quarantine\`, `webview2\` …) **dokunulmaz.**
- Hedefteki exe çalışıyorsa dosya kilitli olur; **kopyalamadan önce uygulamayı kapat.**

## Dil dosyası nerede?

- Repo'da: `lang\lang.en.xml` (kaynak).
- `.csproj` bunu `Link` ile çıktı **kök** klasörüne `lang.en.xml` olarak kopyalar; çünkü
  `LocManager` dil dosyalarını exe'nin bulunduğu klasörde arar.
- Türkçe (varsayılan) için ayrı dosya gerekmez — `Strings.cs` içindeki derlenmiş varsayılanlar
  kullanılır. `lang.tr.xml` yalnızca ilk çalıştırmada, elle düzenlenebilsin diye yazılır.

## Adımlar

Önce çalışan `VirusTotalScanner`'ı kapat (yoksa exe kilitli olur).
Sonra PowerShell (`pwsh`) ile, proje kökünden:

```powershell
$proj   = "C:\E\KodlamaProjeleri\CSharp\VirusTotalScanner"
$target = "C:\E\kp\aaBenimProgramlarim\VirusTotalScanner"
$pub    = "$proj\bin\Release\net10.0-windows\win-x64\publish"

# Geri Dönüşüm Kutusu'na yollayan yardımcı (kalıcı silmez)
Add-Type -AssemblyName Microsoft.VisualBasic
function Recycle($p){ if(Test-Path $p){ if((Get-Item $p).PSIsContainer){
  [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($p,'OnlyErrorDialogs','SendToRecycleBin') } else {
  [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($p,'OnlyErrorDialogs','SendToRecycleBin') } } }

Set-Location $proj

# 1) Temizle (Geri Dönüşüm'e)
Recycle "$proj\bin"; Recycle "$proj\obj"

# 2) Tek exe, self-contained, ReadyToRun (trim YOK — reflection'lı lokalizasyonu kırar)
dotnet publish VirusTotalScanner.csproj -c Release -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true -p:PublishReadyToRun=true

# 3) Eski exe'yi önce Geri Dönüşüm'e yolla, sonra yeni exe + lang.en.xml'i kopyala
#    (hedefte başka hiçbir şeye dokunma)
Recycle "$target\VirusTotalScanner.exe"
Copy-Item "$pub\VirusTotalScanner.exe" $target -Force
Copy-Item "$pub\lang.en.xml"           $target -Force

# 4) Tekrar temizle (Geri Dönüşüm'e)
Recycle "$proj\bin"; Recycle "$proj\obj"
```

## Notlar

- **Trim açılmaz.** `LocManager` ve `LocManager`/`Strings` reflection kullandığı için
  `PublishTrimmed` çıktıyı sessizce bozar.
- Tek-dosya yayında `Content` (lang.en.xml) exe'nin yanına kopyalanır, exe'nin içine
  gömülmez — bu istenen davranıştır (çalışma anında exe klasöründen okunur).
- `RID` = `win-x64`. Çıktı: `bin\Release\net10.0-windows\win-x64\publish\VirusTotalScanner.exe`.
- Sürüm `.csproj` içindeki `<Version>` ile yönetilir.
