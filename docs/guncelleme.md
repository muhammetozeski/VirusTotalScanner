# Güncelleme / derleme & yayınlama runbook'u

Yayınlanan programı (`C:\E\kp\aaBenimProgramlarim\VirusTotalScanner`) güncellemek için
izlenen adımlar. Çıktı: **tek dosya, kendi kendine yeten (self-contained / framework
bağımsız), ReadyToRun** bir exe.

## Hedef davranış

- Çıktı proje klasöründeki `publish` klasörüne alınır (`.gitignore` içinde). Yalnızca portable
  (self-contained) exe alınır.
- Exe, publish biter bitmez ve **hiçbir yere kopyalanmadan önce** Authenticode ile imzalanır.
  `Dogrula.ps1` çıktısında `Valid` görülmeden ilerlenmez.
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

## Sürüm

- Sürüm `.csproj` içindeki `<Version>` ile yönetilir ve GitHub release etiketiyle (`vX.Y.Z`) aynıdır.
- Numara son GitHub release'ine göre Semantic Versioning ile belirlenir:
  - **Major** (ör. 2.0.0): çok büyük mimari veya kırıcı değişiklik.
  - **Minor** (ör. 1.1.0): yeni özellik.
  - **Patch** (ör. 1.0.1): yalnızca hata düzeltmesi.
- Son release'i görmek için: `gh release list -R muhammetozeski/VirusTotalScanner`

## Adımlar

Önce çalışan `VirusTotalScanner`'ı kapat (yoksa exe kilitli olur; kilitli exe imzalanamaz ve
üzerine yazılamaz).
Sonra PowerShell (`pwsh`) ile, proje kökünden:

```powershell
$proj   = "C:\E\KodlamaProjeleri\CSharp\VirusTotalScanner"
$target = "C:\E\kp\aaBenimProgramlarim\VirusTotalScanner"
$pub    = "$proj\publish"
$imza   = "C:\E\kp\aaBenimProgramlarim\Imza"

# Geri Dönüşüm Kutusu'na yollayan yardımcı (kalıcı silmez)
Add-Type -AssemblyName Microsoft.VisualBasic
function Recycle($p){ if(Test-Path $p){ if((Get-Item $p).PSIsContainer){
  [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory($p,'OnlyErrorDialogs','SendToRecycleBin') } else {
  [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($p,'OnlyErrorDialogs','SendToRecycleBin') } } }

Set-Location $proj

# 1) Temizle (Geri Dönüşüm'e) — önceki publish çıktısı dahil
Recycle "$proj\bin"; Recycle "$proj\obj"; Recycle $pub

# 2) Tek exe, self-contained, ReadyToRun (trim YOK — reflection'lı lokalizasyonu kırar)
dotnet publish VirusTotalScanner.csproj -c Release -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true -p:PublishReadyToRun=true -o $pub

# 3) Hiçbir yere kopyalamadan önce imzala, sonra doğrula — Valid görmeden devam etme
& "$imza\Imzala.ps1" $pub
& "$imza\Dogrula.ps1" $pub

# 4) Eski exe'yi önce Geri Dönüşüm'e yolla, sonra yeni exe + lang.en.xml'i kopyala
#    (hedefte başka hiçbir şeye dokunma)
Recycle "$target\VirusTotalScanner.exe"
Copy-Item "$pub\VirusTotalScanner.exe" $target -Force
Copy-Item "$pub\lang.en.xml"           $target -Force

# 5) Tekrar temizle (Geri Dönüşüm'e); publish klasörü release için kalır
Recycle "$proj\bin"; Recycle "$proj\obj"
```

Kısayol `C:\E\Kısayollar\!Benim Programlarım\VirusTotalScanner.lnk` yoksa oluşturulur. Son olarak
program klasörü Explorer'da `VirusTotalScanner.exe` seçili halde açılır.

## GitHub

1. Push'tan önce gönderilecek commit'lerde imza/atıf satırı olmadığı kontrol edilir
   (`Co-Authored-By`, "Generated with Claude Code" vb.):

   ```powershell
   git log origin/master..HEAD -i --grep "Co-Authored-By" --grep "Generated with" --format="%h %s"
   ```

   Çıktı boş olmalı. Sonra `git push origin master`.
2. `C:\E\kp\aaBenimProgramlarim\Imza\Dagitim` klasörü `SignatureTrust.zip` olarak zip'lenir.
   `Imzalama.pfx` ve `PFX-PAROLA.txt` hiçbir yere kopyalanmaz.
3. Release, `.csproj` sürümüyle aynı etiketle (`vX.Y.Z`) oluşturulur. Asset'ler:
   `publish\VirusTotalScanner.exe` ve `SignatureTrust.zip`. Release notları İngilizcedir ve şu
   satırı içerir:

   > The executables are digitally signed. To let Windows verify the signature, run `Install-Certificate.cmd`
   > from `SignatureTrust.zip` once. The programs run without it; only the signature stays unverified.

4. README'nin kurulum bölümünde aynı bilgi tek cümleyle yer alır. İmza SmartScreen uyarısını kaldırmaz.

## Notlar

- **Trim açılmaz.** `LocManager` ve `LocManager`/`Strings` reflection kullandığı için
  `PublishTrimmed` çıktıyı sessizce bozar.
- Tek-dosya yayında `Content` (lang.en.xml) exe'nin yanına kopyalanır, exe'nin içine
  gömülmez — bu istenen davranıştır (çalışma anında exe klasöründen okunur).
- `RID` = `win-x64`. Çıktı: `publish\VirusTotalScanner.exe`.
