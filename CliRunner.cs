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

        if (opts.InstallMenu) return MenuCmd(ContextMenuInstaller.Install(Settings.ContextMenuExcludeSafe, out var e1), e1, Strings.CliMenuInstalled);
        if (opts.UninstallMenu) return MenuCmd(ContextMenuInstaller.Uninstall(out var e2), e2, Strings.CliMenuRemoved);
        if (opts.RepairMenu) return MenuCmd(ContextMenuInstaller.Repair(out var e3), e3, Strings.CliMenuRepaired);

        if (opts.AddKeyValue != null) { AppServices.Vault.Add("CLI", opts.AddKeyValue); Console.WriteLine(Strings.CliKeyAdded); return 0; }
        if (opts.RemoveKeyValue != null) return RemoveKey(opts.RemoveKeyValue);
        if (opts.ListKeys) { ListKeysCmd(); return 0; }
        if (opts.LookupHash != null) return await LookupAsync(opts.LookupHash, opts.Json);
        if (opts.CommentsHash != null) return await CommentsCmd(opts.CommentsHash);
        if (opts.BehaviourHash != null) return await BehaviourCmd(opts.BehaviourHash);
        if (opts.ExpectedHash != null) return await VerifyHashCmd(opts);
        if (opts.VerifyBaseline) return await VerifyBaselineCmd();
        if (opts.DriftReport != null) return await DriftReportCmd(opts.DriftReport);
        if (opts.ExportLedger != null) { int n = LedgerService.Export(AppServices.Cache, opts.ExportLedger); Console.WriteLine(string.Format(Strings.CliLedgerExportedFormat, n, opts.ExportLedger)); return 0; }
        if (opts.ImportLedger != null) { var (add, conf, ok) = LedgerService.Import(AppServices.Cache, opts.ImportLedger); Console.WriteLine(string.Format(Strings.CliLedgerImportedFormat, add, conf, ok ? Strings.CliLedgerOk : Strings.CliLedgerBad)); return 0; }
        if (opts.LedgerDiff != null) { var (nw, cf) = LedgerService.Diff(AppServices.Cache, opts.LedgerDiff); Console.WriteLine(string.Format(Strings.CliLedgerDiffFormat, nw.Count, cf.Count)); foreach (var x in nw.Take(20)) Console.WriteLine("  " + Strings.CliTagNew + " " + x); foreach (var x in cf.Take(20)) Console.WriteLine("  " + Strings.CliTagConflict + " " + x); return 0; }
        if (opts.TimelineDays != null) return await TimelineCmd(opts.TimelineDays.Value);
        if (opts.WatchCheck) return await WatchCheckCmd();

        // --running scans the on-disk image of every running process instead of given paths.
        List<string> scanPaths = opts.Paths;
        if (opts.Running)
        {
            var (rp, unreadable) = RunningProcesses.ImagePaths();
            scanPaths = rp;
            if (!opts.Json && !opts.Quiet) Console.WriteLine(string.Format(Strings.CliRunningProcessesFormat, rp.Count, unreadable));
        }
        if (scanPaths.Count == 0) { PrintHelp(); return 2; }

        bool keyless = Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable;

        if (!AppServices.Rotator.HasUsableKeys && !Settings.TrustSkipSigned && !keyless)
        {
            Console.Error.WriteLine(Strings.CliErrNoMeans);
            return 3;
        }
        if (!AppServices.Rotator.HasUsableKeys && !keyless)
            Console.Error.WriteLine(Strings.CliWarnNoKey);
        if (keyless && !opts.Json && !opts.Quiet)
            Console.WriteLine(Strings.CliKeylessNote);

        var scheduler = AppServices.Scheduler;
        scheduler.UiPost = a => a(); // run inline (no UI thread)

        if (!opts.Json && !opts.Quiet)
            Console.WriteLine(string.Format(Strings.CliScanStartingFormat, AppConstants.AppTitle));

        scheduler.ItemFinished += item =>
        {
            if (!opts.Json) PrintItem(item, opts.Quiet);
            ScanHistoryStore.Record(item, "CLI");
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
                if (!opts.Quiet && !opts.Json) Console.WriteLine(string.Format(Strings.CliReportWrittenFormat, opts.ReportPath));
            }
            catch (Exception ex) { Console.Error.WriteLine(Strings.ReportWriteErrorPrefix + ex.Message); }
        }

        if (opts.SweepResultPath != null)
        {
            try { SweepResultStore.Write(opts.SweepResultPath, scheduler.Items); }
            catch (Exception ex) { Console.Error.WriteLine(Strings.CliSweepResultWriteErrorPrefix + ex.Message); }
        }

        // Verdict-delta gate: compare against a prior --report json baseline (keyed by sha256).
        bool diffFail = false;
        if (opts.DiffBaseline != null)
        {
            var delta = DiffService.Compare(scheduler.Items.ToList(), opts.DiffBaseline);
            if (delta == null) Console.Error.WriteLine(Strings.CliDiffBaselineErrPrefix + opts.DiffBaseline);
            else
            {
                if (!opts.Json)
                {
                    Console.WriteLine(string.Format(Strings.CliDeltaFormat, delta.New, delta.Regressed, delta.Unchanged));
                    foreach (var f in delta.NewFiles.Take(20)) Console.WriteLine("  " + Strings.CliTagNew + " " + f);
                    foreach (var f in delta.RegressedFiles.Take(20)) Console.WriteLine("  " + Strings.CliTagRegressed + " " + f);
                }
                if ((opts.FailOnNew && delta.New > 0) || (opts.FailOnRegression && delta.Regressed > 0)) diffFail = true;
            }
        }

        AppServices.Shutdown();

        // Gate: --fail-on N flips the exit code on any file with >= N detections; otherwise the
        // verdict categories decide what counts as a threat. --diff gates add new/regression fails.
        bool threat = opts.FailOn >= 0
            ? scheduler.Items.Any(i => (i.Report?.DetectionCount ?? 0) >= opts.FailOn)
            : scheduler.Items.Any(i => i.Report?.IsMalicious == true);
        threat = threat || diffFail;
        if (!opts.Json && !opts.Quiet)
        {
            int mal = scheduler.Items.Count(i => i.Report?.IsMalicious == true);
            int total = scheduler.Items.Count;
            Console.WriteLine(string.Format(Strings.CliDoneFormat, total, mal));
        }
        return threat ? 1 : 0;
    }

    static async Task<int> DriftReportCmd(string path)
    {
        var due = RecheckService.DueForRecheck(AppServices.Cache, 0); // re-check every cached entry
        if (due.Count == 0) { Console.WriteLine(Strings.CliNoRecheckRecords); return 0; }
        Console.WriteLine(string.Format(Strings.CliRecheckingFormat, due.Count));
        var changes = await RecheckService.RunAsync(AppServices.Cache, due, null, default);

        string ext = Path.GetExtension(path).ToLowerInvariant();
        var sb = new System.Text.StringBuilder();
        if (ext == ".csv")
        {
            sb.AppendLine("SHA256,OldVerdict,OldDetections,NewVerdict,NewDetections,GotWorse,ReportUrl");
            foreach (var c in changes)
                sb.AppendLine($"{c.Sha256},{c.OldVerdict},{c.OldDetections},{c.NewVerdict},{c.NewDetections},{c.GotWorse},{c.Url}");
        }
        else
        {
            sb.AppendLine(string.Format(Strings.CliDriftHeaderFormat, changes.Count, due.Count));
            foreach (var c in changes)
                sb.AppendLine($"{(c.GotWorse ? Strings.RecheckWorse : Strings.RecheckBetter)}: {c.OldVerdict}({c.OldDetections}) → {c.NewVerdict}({c.NewDetections})  {c.Url}");
        }
        try { File.WriteAllText(path, sb.ToString(), new System.Text.UTF8Encoding(false)); }
        catch (Exception ex) { Console.Error.WriteLine(Strings.ReportWriteErrorPrefix + ex.Message); return 2; }

        Console.WriteLine(string.Format(Strings.CliDriftWrittenFormat, changes.Count, path));
        return changes.Any(c => c.GotWorse) ? 1 : 0;
    }

    static async Task<int> BehaviourCmd(string hash)
    {
        if (!(Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable))
        { Console.Error.WriteLine(Strings.CliErrBehaviourKeyless); return 3; }
        var b = await GuiScrapeService.FetchBehaviourAsync(hash);
        if (!b.Any) { Console.WriteLine(Strings.BehaviourNone); return 0; }
        static void Section(string title, List<string> items)
        {
            if (items.Count == 0) return;
            Console.WriteLine(title + ":");
            foreach (var x in items.Take(15)) Console.WriteLine("   " + x);
        }
        Section(Strings.CliSecNetwork, b.Network);
        Section(Strings.CliSecFiles, b.FilesWritten);
        Section(Strings.CliSecRegistry, b.Registry);
        Section(Strings.CliSecProcesses, b.Processes);
        Section(Strings.CliSecMitre, b.Mitre);
        return 0;
    }

    static async Task<int> CommentsCmd(string hash)
    {
        if (!(Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable))
        { Console.Error.WriteLine(Strings.CliErrCommentsKeyless); return 3; }
        var comments = await GuiScrapeService.FetchCommentsAsync(hash);
        if (comments.Count == 0) { Console.WriteLine(Strings.CliNoComments); return 0; }
        foreach (var c in comments.Take(20))
        {
            Console.WriteLine($"[{c.Date:yyyy-MM-dd}] {c.Text?.Replace("\n", " ").Trim()}");
            if (c.Tags.Count > 0) Console.WriteLine("   #" + string.Join(" #", c.Tags));
        }
        return 0;
    }

    static async Task<int> VerifyBaselineCmd()
    {
        if (BaselineStore.Count == 0) { Console.WriteLine(Strings.CliNoWatchedFiles); return 0; }
        var res = await BaselineStore.VerifyAsync(null, default);
        foreach (var r in res.Where(r => r.Kind != DriftKind.Unchanged))
            Console.WriteLine($"{(r.IsAlarm ? Strings.CliTagAlarm : Strings.CliTagChanged)} {r.Path} — {r.Detail}");
        int alarms = res.Count(r => r.IsAlarm);
        Console.WriteLine(string.Format(Strings.CliBaselineResultFormat, res.Count, alarms));
        return alarms > 0 ? 1 : 0;
    }

    static async Task<int> VerifyHashCmd(CliOptions opts)
    {
        if (opts.Paths.Count != 1 || !File.Exists(opts.Paths[0]))
        {
            Console.Error.WriteLine(Strings.CliErrExpectOneFile);
            return 2;
        }
        try
        {
            var r = await HashService.VerifyExpectedAsync(opts.Paths[0], opts.ExpectedHash!);
            if (r.Algorithm == "?")
            {
                Console.Error.WriteLine(Strings.CliErrHashFormat);
                return 2;
            }
            if (r.Matched)
            {
                Console.WriteLine(string.Format(Strings.CliHashMatchedFormat, r.Algorithm, r.Actual, opts.Paths[0]));
                return 0;
            }
            Console.WriteLine(string.Format(Strings.CliHashMismatchFormat, opts.Paths[0]));
            Console.WriteLine(string.Format(Strings.CliHashExpectedFormat, r.Algorithm, r.Expected));
            Console.WriteLine(string.Format(Strings.CliHashActualFormat, r.Algorithm, r.Actual));
            return 4;
        }
        catch (Exception ex) { Console.Error.WriteLine(Strings.CliErrPrefix + ex.Message); return 3; }
    }

    static async Task<int> WatchCheckCmd()
    {
        int n = ReverdictWatchStore.Count;
        if (n == 0) { Console.WriteLine(Strings.CliWatchListEmpty); return 0; }
        Console.WriteLine(string.Format(Strings.CliWatchRecheckingFormat, n));
        var escalations = await WatchService.CheckAllAsync();
        if (escalations.Count == 0) { Console.WriteLine(Strings.CliWatchNoEscalation); return 0; }
        foreach (var (e, oldD, newD) in escalations)
            Console.WriteLine(string.Format(Strings.CliWatchEscalationFormat, e.Name, oldD, newD, e.LastTotal));
        return 1;
    }

    static async Task<int> TimelineCmd(int days)
    {
        Console.WriteLine(string.Format(Strings.CliTimelineScanningFormat, days));
        var result = await IncidentTimelineService.BuildAsync(AppServices.Cache, days,
            (d, t) => { if (d % 250 == 0 || d == t) { try { Console.Error.Write($"\r  {d}/{t}   "); } catch { } } }, default);
        try { Console.Error.WriteLine(); } catch { }

        int totalFiles = result.Sum(d => d.Count);
        int totalThreats = result.Sum(d => d.Threats);
        Console.WriteLine(string.Format(Strings.CliTimelineSummaryFormat, result.Count, totalFiles, totalThreats));
        foreach (var d in result.Take(90))
        {
            Console.WriteLine(string.Format(Strings.CliTimelineDayFormat, d.DayText, d.Count, d.Threats, d.FromNet));
            foreach (var f in d.Files.Where(f => f.Detections > 0).Take(10))
                Console.WriteLine($"   [{f.Verdict} {f.Detections}] {f.ArrivalLocal:HH:mm}  {f.Name}{(f.Host != null ? "  <- " + f.Host : "")}");
        }
        return totalThreats > 0 ? 1 : 0;
    }

    static async Task<int> LookupAsync(string hash, bool json)
    {
        bool keyless = Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable;
        if (!keyless && !AppServices.Rotator.HasUsableKeys) { Console.Error.WriteLine(Strings.CliErrNoKeyOrKeyless); return 3; }
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
            if (report == null) { Console.WriteLine(Strings.CliNotFound); return 0; }
            if (json) { PrintJson([new ScanItem(hash) { Report = report, Md5 = report.Md5, Sha256 = report.Sha256 }]); return report.IsMalicious ? 1 : 0; }
            Console.WriteLine($"[{report.Verdict}] ({report.DetectionCount}/{report.TotalEngines})  {report.MeaningfulName ?? hash}");
            var reco = RecommendationService.Build(new ScanItem(hash) { Report = report });
            Console.WriteLine($"   👉 {reco.Headline} — {reco.Rationale}");
            if (report.ConsensusText != null) Console.WriteLine("   " + report.ConsensusText);
            if (report.ConfidenceText != null) Console.WriteLine("   " + report.ConfidenceText);
            if (report.StaleText != null) Console.WriteLine("   " + report.StaleText);
            if (report.CommunityRulesText != null) Console.WriteLine("   " + report.CommunityRulesText);
            if (report.FamilyLabel != null) Console.WriteLine("   " + report.FamilyLabel);
            if (report.CapabilitySummary != null) Console.WriteLine("   " + report.CapabilitySummary);
            foreach (var d in report.Detections.Take(15)) Console.WriteLine($"   - {d.EngineName}: {d.Result}");
            Console.WriteLine("   " + report.ReportUrl);
            return report.IsMalicious ? 1 : 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(Strings.CliErrPrefix + ex.Message); return 3; }
    }

    static void ListKeysCmd()
    {
        var keys = AppServices.Vault.Keys;
        if (keys.Count == 0) { Console.WriteLine(Strings.CliNoKeys); return; }
        var now = DateTime.UtcNow;
        foreach (var k in keys)
            Console.WriteLine($"{k.Id}  {k.Masked}  [{(string.IsNullOrWhiteSpace(k.Label) ? "-" : k.Label)}]  " +
                $"{(k.Disabled ? Strings.CliKeyDisabled : k.IsExhausted(now) ? Strings.CliKeyExhausted : Strings.CliKeyActive)}  " +
                string.Format(Strings.CliQuotaFormat, k.Daily.Used, k.Daily.Allowed, k.Monthly.Used, k.Monthly.Allowed));
    }

    static int RemoveKey(string idOrAll)
    {
        if (idOrAll.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var k in AppServices.Vault.Keys.ToList()) AppServices.Vault.Remove(k.Id);
            Console.WriteLine(Strings.CliAllKeysDeleted);
            return 0;
        }
        AppServices.Vault.Remove(idOrAll);
        Console.WriteLine(Strings.CliKeyRemovedPrefix + idOrAll);
        return 0;
    }

    static int MenuCmd(bool ok, string? err, string okMsg)
    {
        if (ok) { Console.WriteLine(okMsg); return 0; }
        Console.Error.WriteLine(Strings.CliErrPrefix + err);
        return 2;
    }

    static void PrintItem(ScanItem item, bool quiet)
    {
        if (item.Status == ScanStatus.TrustedSkipped)
        {
            try { Console.ForegroundColor = ConsoleColor.Cyan; } catch { }
            Console.WriteLine(string.Format(Strings.CliSignedFormat, item.FileName, item.SkipReason));
            try { Console.ResetColor(); } catch { }
            return;
        }

        var r = item.Report;
        string verdict = r?.Verdict ?? (item.Status == ScanStatus.Failed ? Strings.CliVerdictError : "?");
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
            Console.WriteLine(Strings.CliItemErrorPrefix + item.Error);
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
        Console.WriteLine(string.Format(Strings.HelpTextFormat, AppConstants.AppTitle, AppConstants.Version));
    }
}
