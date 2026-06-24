using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>
/// Terminal mode: runs without any GUI, prints to the attached console, returns an exit code.
/// Exit codes: 0 clean, 1 threat found, 2 usage/IO, 3 no/invalid API key.
/// </summary>
internal static class CliRunner
{
    public static async Task<int> RunAsync(CliOptions opts)
    {
        ConsoleBootstrap.WritePromptNewlineFix();
        if (opts.Keyless) Settings.KeylessGuiLookup.Value = true; // this run only (not persisted)

        if (opts.ShowHelp) { PrintHelp(); return 0; }
        if (opts.ShowVersion) { Console.WriteLine($"{AppConstants.AppTitle} v{AppConstants.Version}"); return 0; }

        if (opts.InstallMenu) return MenuCmd(ContextMenuInstaller.Install(Settings.ContextMenuExcludeSafe, out var e1), e1, "Sağ tuş menüsü kuruldu.");
        if (opts.UninstallMenu) return MenuCmd(ContextMenuInstaller.Uninstall(out var e2), e2, "Sağ tuş menüsü kaldırıldı.");
        if (opts.RepairMenu) return MenuCmd(ContextMenuInstaller.Repair(out var e3), e3, "Sağ tuş menüsü onarıldı.");

        if (opts.AddKeyValue != null) { AppServices.Vault.Add("CLI", opts.AddKeyValue); Console.WriteLine("Anahtar eklendi."); return 0; }
        if (opts.RemoveKeyValue != null) return RemoveKey(opts.RemoveKeyValue);
        if (opts.ListKeys) { ListKeysCmd(); return 0; }
        if (opts.LookupHash != null) return await LookupAsync(opts.LookupHash, opts.Json);
        if (opts.ExpectedHash != null) return await VerifyHashCmd(opts);

        // --running scans the on-disk image of every running process instead of given paths.
        List<string> scanPaths = opts.Paths;
        if (opts.Running)
        {
            var (rp, unreadable) = RunningProcesses.ImagePaths();
            scanPaths = rp;
            if (!opts.Json && !opts.Quiet) Console.WriteLine($"Çalışan süreçler: {rp.Count} imaj taranacak ({unreadable} okunamadı/atlandı).");
        }
        if (scanPaths.Count == 0) { PrintHelp(); return 2; }

        bool keyless = Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable;

        if (!AppServices.Rotator.HasUsableKeys && !Settings.TrustSkipSigned && !keyless)
        {
            Console.Error.WriteLine("HATA: API anahtarı yok, imza-atlama kapalı ve anahtarsız (GUI) mod açık değil.");
            return 3;
        }
        if (!AppServices.Rotator.HasUsableKeys && !keyless)
            Console.Error.WriteLine("(Uyarı: anahtar yok — yalnızca imzalı dosyalar değerlendirilebilir, imzasızlar atlanır.)");
        if (keyless && !opts.Json && !opts.Quiet)
            Console.WriteLine("(Anahtarsız GUI modu açık — sorgular WebView2 üzerinden, kotasız ama yavaş.)");

        var scheduler = AppServices.Scheduler;
        scheduler.UiPost = a => a(); // run inline (no UI thread)

        if (!opts.Json && !opts.Quiet)
            Console.WriteLine($"{AppConstants.AppTitle} — tarama başlıyor…\n");

        scheduler.ItemFinished += item =>
        {
            if (!opts.Json) PrintItem(item, opts.Quiet);
        };

        var scanOpts = ScanOptions.FromSettings(opts.Recurse);
        scanOpts.BypassTrust = opts.NoTrust;
        scanOpts.ExpandArchives = opts.ExpandArchives;
        await scheduler.RunAsync(scanPaths, scanOpts);

        if (opts.Json) PrintJson(scheduler.Items);

        if (opts.ReportPath != null)
        {
            try
            {
                ReportWriter.Write(opts.ReportPath, scheduler.Items.ToList());
                if (!opts.Quiet && !opts.Json) Console.WriteLine($"Rapor yazıldı: {opts.ReportPath}");
            }
            catch (Exception ex) { Console.Error.WriteLine("Rapor yazılamadı: " + ex.Message); }
        }

        AppServices.Shutdown();

        // Gate: --fail-on N flips the exit code on any file with >= N detections; otherwise the
        // verdict categories decide what counts as a threat.
        bool threat = opts.FailOn >= 0
            ? scheduler.Items.Any(i => (i.Report?.DetectionCount ?? 0) >= opts.FailOn)
            : scheduler.Items.Any(i => i.Report?.IsMalicious == true);
        if (!opts.Json && !opts.Quiet)
        {
            int mal = scheduler.Items.Count(i => i.Report?.IsMalicious == true);
            int total = scheduler.Items.Count;
            Console.WriteLine($"\nBitti. {total} dosya tarandı, {mal} tehdit bulundu.");
        }
        return threat ? 1 : 0;
    }

    static async Task<int> VerifyHashCmd(CliOptions opts)
    {
        if (opts.Paths.Count != 1 || !File.Exists(opts.Paths[0]))
        {
            Console.Error.WriteLine("HATA: --expect tek bir dosya yolu ister.");
            return 2;
        }
        try
        {
            var r = await HashService.VerifyExpectedAsync(opts.Paths[0], opts.ExpectedHash!);
            if (r.Algorithm == "?")
            {
                Console.Error.WriteLine("HATA: beklenen hash 32 (MD5), 40 (SHA-1) veya 64 (SHA-256) hex karakter olmalı.");
                return 2;
            }
            if (r.Matched)
            {
                Console.WriteLine($"[EŞLEŞTİ] {r.Algorithm}: {r.Actual}  ✓  {opts.Paths[0]}");
                return 0;
            }
            Console.WriteLine($"[EŞLEŞMEDİ] {opts.Paths[0]}");
            Console.WriteLine($"   Beklenen {r.Algorithm}: {r.Expected}");
            Console.WriteLine($"   Gerçek   {r.Algorithm}: {r.Actual}");
            return 4;
        }
        catch (Exception ex) { Console.Error.WriteLine("HATA: " + ex.Message); return 3; }
    }

    static async Task<int> LookupAsync(string hash, bool json)
    {
        bool keyless = Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable;
        if (!keyless && !AppServices.Rotator.HasUsableKeys) { Console.Error.WriteLine("HATA: API anahtarı yok (veya --keyless kullanın)."); return 3; }
        try
        {
            VtFileReport? report;
            if (keyless)
            {
                report = await GuiScrapeService.LookupAsync(hash);
            }
            else
            {
                string key = await AppServices.Rotator.AcquireAsync();
                report = await AppServices.Api.GetFileReportAsync(hash, key);
            }
            if (report == null) { Console.WriteLine("Bulunamadı (VT'de yok)."); return 0; }
            if (json) { PrintJson([new ScanItem(hash) { Report = report, Md5 = report.Md5, Sha256 = report.Sha256 }]); return report.IsMalicious ? 1 : 0; }
            Console.WriteLine($"[{report.Verdict}] ({report.DetectionCount}/{report.TotalEngines})  {report.MeaningfulName ?? hash}");
            if (report.ConsensusText != null) Console.WriteLine("   " + report.ConsensusText);
            if (report.FamilyLabel != null) Console.WriteLine("   " + report.FamilyLabel);
            if (report.CapabilitySummary != null) Console.WriteLine("   " + report.CapabilitySummary);
            foreach (var d in report.Detections.Take(15)) Console.WriteLine($"   - {d.EngineName}: {d.Result}");
            Console.WriteLine("   " + report.ReportUrl);
            return report.IsMalicious ? 1 : 0;
        }
        catch (Exception ex) { Console.Error.WriteLine("HATA: " + ex.Message); return 3; }
    }

    static void ListKeysCmd()
    {
        var keys = AppServices.Vault.Keys;
        if (keys.Count == 0) { Console.WriteLine("Anahtar yok."); return; }
        var now = DateTime.UtcNow;
        foreach (var k in keys)
            Console.WriteLine($"{k.Id}  {k.Masked}  [{(string.IsNullOrWhiteSpace(k.Label) ? "-" : k.Label)}]  " +
                $"{(k.Disabled ? "devre dışı" : k.IsExhausted(now) ? "dolu" : "aktif")}  " +
                $"gün {k.Daily.Used}/{k.Daily.Allowed}  ay {k.Monthly.Used}/{k.Monthly.Allowed}");
    }

    static int RemoveKey(string idOrAll)
    {
        if (idOrAll.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var k in AppServices.Vault.Keys.ToList()) AppServices.Vault.Remove(k.Id);
            Console.WriteLine("Tüm anahtarlar silindi.");
            return 0;
        }
        AppServices.Vault.Remove(idOrAll);
        Console.WriteLine("Anahtar silindi (varsa): " + idOrAll);
        return 0;
    }

    static int MenuCmd(bool ok, string? err, string okMsg)
    {
        if (ok) { Console.WriteLine(okMsg); return 0; }
        Console.Error.WriteLine("HATA: " + err);
        return 2;
    }

    static void PrintItem(ScanItem item, bool quiet)
    {
        if (item.Status == ScanStatus.TrustedSkipped)
        {
            try { Console.ForegroundColor = ConsoleColor.Cyan; } catch { }
            Console.WriteLine($"[İMZALI] {item.FileName}  — {item.SkipReason} (VT atlandı)");
            try { Console.ResetColor(); } catch { }
            return;
        }

        var r = item.Report;
        string verdict = r?.Verdict ?? (item.Status == ScanStatus.Failed ? "HATA" : "?");
        var color = verdict switch
        {
            "ZARARLI" => ConsoleColor.Red,
            "ŞÜPHELİ" => ConsoleColor.Yellow,
            "TEMİZ" => ConsoleColor.Green,
            _ => ConsoleColor.Gray,
        };
        try { Console.ForegroundColor = color; } catch { }
        string ratio = r != null ? $" ({r.DetectionCount}/{r.TotalEngines})" : "";
        Console.WriteLine($"[{verdict}]{ratio}  {item.FileName}");
        try { Console.ResetColor(); } catch { }

        if (!quiet && r != null && r.DetectionCount > 0)
            foreach (var d in r.Detections.Take(10))
                Console.WriteLine($"      - {d.EngineName}: {d.Result}");
        if (!quiet && r != null)
            Console.WriteLine($"      {r.ReportUrl}");
        if (item.Status == ScanStatus.Failed && item.Error != null)
            Console.WriteLine("      Hata: " + item.Error);
    }

    static void PrintJson(IEnumerable<ScanItem> items)
    {
        var arr = items.Select(i => new
        {
            file = i.FilePath,
            status = i.Status.ToString(),
            verdict = i.Report?.Verdict,
            malicious = i.Report?.Malicious ?? 0,
            suspicious = i.Report?.Suspicious ?? 0,
            total = i.Report?.TotalEngines ?? 0,
            md5 = i.Md5,
            sha256 = i.Sha256,
            report = i.Report?.ReportUrl,
            detections = i.Report?.Detections.Select(d => new { engine = d.EngineName, result = d.Result }).ToArray(),
            error = i.Error,
        });
        Console.WriteLine(JsonSerializer.Serialize(arr, new JsonSerializerOptions { WriteIndented = true }));
    }

    static void PrintHelp()
    {
        Console.WriteLine($"""
        {AppConstants.AppTitle} v{AppConstants.Version}

        Kullanım:
          VirusTotalScanner.exe [seçenekler] <dosya|klasör> [<dosya|klasör> ...]

        Çift tıklayınca grafik arayüz açılır. Terminalden çalıştırınca komut satırı modunda çalışır.

        Seçenekler:
          -s, --scan          Tarama işareti (sağ tuş menüsü kullanır)
          -r, --recurse       Klasörleri alt klasörlerle birlikte tara
              --no-trust      İmza güvenini yok say (imzalı dosyaları da VT'ye gönder)
          -k, --keyless       Anahtarsız sorgula (GUI/WebView2 üzerinden, kotasız, yavaş)
              --expand-archives  Arşivleri (zip/nupkg/jar…) aç, üyelerini ayrı ayrı tara
              --running       Çalışan tüm süreçlerin imajlarını tara ("şu an virüslü müyüm?")
          -n, --nogui, --cli  Grafik arayüz açmadan terminalde çalış
          -g, --gui           Terminalden bile olsa grafik arayüzü aç
          -j, --json          Sonuçları JSON olarak yaz (stdout)
              --report <yol>  Rapor dosyası yaz (.html/.json/.txt — uzantıdan biçim seçilir)
              --fail-on <N>   N+ tespit olan dosyada çıkış kodu 1 (CI kapısı)
          -q, --quiet         Yalın çıktı (yalnızca verdict satırları)
              --install       Sağ tuş menüsüne ekle
              --uninstall     Sağ tuş menüsünden kaldır
              --repair        Sağ tuş menüsü kaydını (exe yolu) onar
              --addkey <KEY>  API anahtarı ekle (şifreli saklanır)
              --listkeys      Tanımlı anahtarları ve kotaları listele
              --removekey <id|all>  Anahtar(ları) sil
              --lookup <hash>  Bir MD5/SHA-1/SHA-256 hash'ini sorgula
              --expect <hash>  Dosyayı beklenen hash ile doğrula (eşleşmezse çıkış kodu 4)
          -h, --help          Bu yardım
          -v, --version       Sürüm

        Çıkış kodları: 0 temiz, 1 tehdit bulundu, 2 kullanım/IO hatası, 3 anahtar yok, 4 hash eşleşmedi.

        Not: Bu bir GUI uygulamasıdır; betikte beklemek için 'Start-Process -Wait' kullanın.
        """);
    }
}
