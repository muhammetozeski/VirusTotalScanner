namespace VirusTotalScanner;

/// <summary>
/// One place that says, in plain Turkish, what every control on every tab actually does — and gets
/// it onto the controls. A button caption has room for two or three words; the difference between
/// "eşzamanlı tarama" and "paralel yükleme", or what a cache day count of 0 means, does not fit
/// there and used to be knowable only by reading the source.
///
/// Controls are matched by <see cref="System.Windows.Forms.Control.AccessibleName"/> first (set on
/// text boxes, grids, combos and numerics, which carry no caption) and by their caption otherwise,
/// so a card only has to be built — not individually wired — to get its help.
/// </summary>
internal static class TooltipCatalog
{
    /// <summary>Walks the whole control tree of <paramref name="root"/> and attaches every tooltip
    /// this catalog knows. Safe to call more than once (later calls just overwrite).</summary>
    public static void Apply(ToolTip tips, Control root)
    {
        var map = Build();
        int hit = 0;
        var missed = new List<string>();
        void Walk(Control c, string? inherited)
        {
            string? mine = null;
            try
            {
                // Three keys are tried, because a caption is not always what a control ends up carrying:
                // ThemeManager stamps AccessibleName with the icon-stripped caption for screen readers,
                // so "↻  Sunucudan kotayı yenile" becomes "Sunucudan kotayı yenile" behind our back.
                foreach (var key in new[] { c.AccessibleName, c.Text, StripLeadingIcon(c.Text) })
                {
                    if (string.IsNullOrEmpty(key) || !map.TryGetValue(key, out var text)) continue;
                    tips.SetToolTip(c, text);
                    mine = text;
                    hit++;
                    break;
                }

                if (mine == null && inherited != null && string.IsNullOrEmpty(tips.GetToolTip(c)))
                {
                    // A composite control's inner parts (a NumericUpDown's edit box, a panel's ✕) have no
                    // caption of their own; hovering them should still explain the thing they belong to.
                    tips.SetToolTip(c, inherited);
                    mine = inherited;
                }

                if (mine == null && c is Button or CheckBox or RadioButton or ComboBox or NumericUpDown or TextBox
                    && string.IsNullOrEmpty(tips.GetToolTip(c)))
                    missed.Add(string.IsNullOrEmpty(c.AccessibleName) ? c.Text ?? "" : c.AccessibleName);
            }
            catch (Exception ex) { Log("Tooltip attach failed: " + ex.Message, LogLevel.Warning); }
            foreach (Control child in c.Controls) Walk(child, mine ?? inherited);
        }
        Walk(root, null);
        Log($"Tooltips attached on {root.GetType().Name}: {hit} matched"
            + (missed.Count == 0 ? ", nothing left uncovered." : $", still uncovered: {string.Join(" | ", missed.Distinct())}"), LogLevel.Debug);
    }

    /// <summary>Marks a caption-less control (text box, grid, combo, numeric) so the walker can find
    /// its help text. Returns the control so it can be used inline.</summary>
    public static T Name<T>(T c, string accessibleName) where T : Control
    {
        c.AccessibleName = accessibleName;
        return c;
    }

    /// <summary>"🛡  Karantinaya al" -> "Karantinaya al". Mirrors what ThemeManager stamps into
    /// AccessibleName, so a key written with its icon still matches a stamped control.</summary>
    static string StripLeadingIcon(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "";
        int i = 0;
        while (i < text.Length && !char.IsLetterOrDigit(text[i])) i++;
        string name = text[i..].Trim();
        return name.Length > 0 ? name : text.Trim();
    }

    // Keys for controls that have no caption of their own.
    public const string KeysGrid = "tt.keysGrid";
    public const string MenuStatus = "tt.menuStatus";
    public const string AllowGrid = "tt.allowGrid";
    public const string FolderGrid = "tt.folderGrid";
    public const string WatchGrid = "tt.watchGrid";
    public const string CatGrid = "tt.catGrid";
    public const string MajorEnginesBox = "tt.majorEnginesBox";
    public const string AutoActionGrid = "tt.autoActionGrid";
    public const string SafeExtsBox = "tt.safeExtsBox";
    public const string UploadPolicyCombo = "tt.uploadPolicyCombo";
    public const string LookupPolicyCombo = "tt.lookupPolicyCombo";
    public const string TrustAllowBox = "tt.trustAllowBox";
    public const string KnownGoodBox = "tt.knownGoodBox";
    public const string SweepFolderBox = "tt.sweepFolderBox";
    public const string SweepIntervalCombo = "tt.sweepIntervalCombo";
    public const string SweepStatus = "tt.sweepStatus";
    public const string LanguageCombo = "tt.languageCombo";
    public const string ThemeCombo = "tt.themeCombo";
    public const string AutoQuarantineNum = "tt.autoQuarantineNum";
    public const string QuietStartNum = "tt.quietStartNum";
    public const string QuietEndNum = "tt.quietEndNum";
    public const string RetentionNum = "tt.retentionNum";
    public const string PeriodicNum = "tt.periodicNum";
    public const string SettingsSearch = "tt.settingsSearch";
    public const string TorPathBox = "tt.torPathBox";
    public const string TorThresholdNum = "tt.torThresholdNum";
    public const string TorStatusLabel = "tt.torStatusLabel";
    public const string CacheBackupFolderBox = "tt.cacheBackupFolderBox";
    public const string CacheBackupHoursNum = "tt.cacheBackupHoursNum";
    public const string CacheBackupKeepNum = "tt.cacheBackupKeepNum";
    public const string CacheBackupList = "tt.cacheBackupList";
    public const string KeyBackupPathBox = "tt.keyBackupPathBox";
    public const string QuotaFlow = "tt.quotaFlow";
    public const string QuotaBanner = "tt.quotaBanner";
    public const string HistoryGrid = "tt.historyGrid";
    public const string HistorySearch = "tt.historySearch";
    public const string LogBox = "tt.logBox";

    static Dictionary<string, string> Build() => new(StringComparer.Ordinal)
    {
        // ---- scan tab: action bar ----
        [Strings.BtnSelectFiles] = Strings.TipSelectFiles,
        [Strings.BtnSelectFolder] = Strings.TipSelectFolder,
        [Strings.BtnPause] = Strings.TipPause,
        [Strings.BtnResume] = Strings.TipPause,
        [Strings.BtnCancel] = Strings.TipCancel,
        [Strings.BtnJumpToCurrent] = Strings.TipJumpToCurrent,
        [Strings.BtnHashLookup] = Strings.TipHashLookup,
        [Strings.BtnVerifyHash] = Strings.TipVerifyHash,
        [Strings.BtnScanRunning] = Strings.TipScanRunning,
        [Strings.BtnScanDownloads] = Strings.TtScanDownloads,
        [Strings.BtnRecheckShort] = Strings.TipRecheck,
        [Strings.BtnIntegrityCheck] = Strings.TipIntegrityCheck,
        [Strings.BtnExportCsv] = Strings.TipExportCsv,
        [Strings.BtnExportReport] = Strings.TipExportReport,
        [Strings.BtnFolderRollup] = Strings.TipFolderRollup,
        [Strings.BtnQuarantineVault] = Strings.TipQuarantineVault,
        [Strings.BtnDownloadsTriage] = Strings.TipDownloadsTriage,
        [Strings.BtnIncidentTimeline] = Strings.TipIncidentTimeline,
        [Strings.BtnFamilyClusters] = Strings.TipFamilyClusters,
        [Strings.BtnRecheck] = Strings.TipRecheck,
        [Strings.BtnBackupCache] = Strings.TipBackupCache,
        [Strings.BtnAllCommands] = Strings.TipAllCommands,
        [Strings.BtnHelp] = Strings.TipHelp,
        [Strings.BtnUndo] = Strings.TipUndoQuarantine,
        [Strings.BtnHide] = Strings.TtHide,
        [Strings.BtnInstallContextMenu] = Strings.TtCtxInstall,

        // ---- Tor row ----
        [Strings.TorToggleLabel] = Strings.TipTorToggle,
        [Strings.TorNewCircuitBtn] = Strings.TipTorNewCircuit,
        [TorStatusLabel] = Strings.TipTorStatus,
        [Strings.TorAutoEnableLabel] = Strings.TtTorAutoEnable,
        [Strings.TorNewCircuitOnErrorLabel] = Strings.TtTorNewCircuitOnError,
        [Strings.CaptchaAutoClickLabel] = Strings.TtCaptchaAutoClick,
        [Strings.TorRouteApiLabel] = Strings.TtTorRouteApi,
        [Strings.ScanUseFingerprintLabel] = Strings.TtUseFingerprintCache,
        [Strings.BtnTorFindExe] = Strings.TtTorFindExe,
        [Strings.BtnTorTest] = Strings.TtTorTest,
        [TorPathBox] = Strings.TtTorPathBox,
        [TorThresholdNum] = Strings.TtTorThreshold,

        // ---- settings: API keys ----
        [KeysGrid] = Strings.TtKeysGrid,
        [Strings.BtnAdd] = Strings.TtKeyAdd,
        [Strings.BtnEdit] = Strings.TtKeyEdit,
        [Strings.BtnReEnableKeys] = Strings.TtReEnableKeys,
        [Strings.BtnDelete] = Strings.TtDeleteRow,
        [KeyBackupPathBox] = Strings.TtKeyBackupPath,
        [Strings.BtnPickKeyBackupFile] = Strings.TtPickKeyBackupFile,
        [Strings.BtnWriteKeyBackupNow] = Strings.TtWriteKeyBackupNow,

        // ---- settings: context menu ----
        [Strings.CtxExcludeSafe] = Strings.TtCtxExcludeSafe,
        [Strings.BtnCtxInstall] = Strings.TtCtxInstall,
        [Strings.BtnRepair] = Strings.TtCtxRepair,
        [Strings.BtnRemove] = Strings.TtRemoveGeneric,
        [MenuStatus] = Strings.TtMenuStatus,

        // ---- settings: trust ----
        [Strings.TrustSkipSignedLabel] = Strings.TtTrustSkipSigned,
        [Strings.TrustMsOnlyLabel] = Strings.TtTrustMsOnly,
        [Strings.TrustKeylessLabel] = Strings.TtTrustKeyless,
        [Strings.TrustAllowLabel] = Strings.TtTrustAllow,
        [TrustAllowBox] = Strings.TtTrustAllow,
        [KnownGoodBox] = Strings.TtKnownGood,
        [Strings.TrustPickHashList] = Strings.TtKnownGood,

        // ---- settings: allowlist ----
        [AllowGrid] = Strings.TtAllowGrid,
        [Strings.BtnRemoveFromList] = Strings.TtRemoveFromList,
        [Strings.BtnReviewMarkClean] = Strings.TtReviewMarkClean,
        [Strings.BtnHealthCheck] = Strings.TtHealthCheck,
        [Strings.BtnImportFromHistory] = Strings.TtImportFromHistory,

        // ---- settings: folder suppression / watch folders ----
        [FolderGrid] = Strings.TtFolderGrid,
        [WatchGrid] = Strings.TtWatchGrid,
        [Strings.BtnAddFolder] = Strings.TtAddFolder,

        // ---- settings: verdict categories ----
        [CatGrid] = Strings.TtCatGrid,
        [Strings.BtnAddShort] = Strings.TtAddRow,
        [Strings.BtnPickColor] = Strings.TtPickColor,
        [Strings.BtnSave] = Strings.TtSaveRows,
        [Strings.BtnDefault] = Strings.TtDefaults,
        [MajorEnginesBox] = Strings.TtMajorEngines,
        [Strings.BtnSaveMajorEngines] = Strings.TtMajorEngines,

        // ---- settings: auto actions ----
        [AutoActionGrid] = Strings.TtAutoActionGrid,

        // ---- settings: scan card ----
        [Strings.ScanConcurrencyLabel] = Strings.TtConcurrency,
        [Strings.ScanUploadsLabel] = Strings.TtUploads,
        [Strings.ScanMaxSizeLabel] = Strings.TtMaxSize,
        [Strings.ScanRecheckDaysLabel] = Strings.TtRecheckDays,
        [Strings.ScanUseCacheLabel] = Strings.TtUseCache,
        [Strings.ScanCleanCacheDaysLabel] = Strings.TtCleanCacheDays,
        [Strings.ScanThreatCacheDaysLabel] = Strings.TtThreatCacheDays,
        [Strings.ScanSkipSafeLabel] = Strings.TtSkipSafe,
        [Strings.ScanUploadPolicyLabel] = Strings.TtUploadPolicy,
        [UploadPolicyCombo] = Strings.TtUploadPolicy,
        [Strings.ScanLookupPolicyLabel] = Strings.TtLookupPolicy,
        [LookupPolicyCombo] = Strings.TtLookupPolicy,
        [Strings.ScanSafeExtsLabel] = Strings.TtSafeExts,
        [SafeExtsBox] = Strings.TtSafeExts,
        [Strings.BtnSaveExts] = Strings.TtSafeExts,

        // ---- settings: cache backup ----
        [CacheBackupFolderBox] = Strings.TtCacheBackupFolder,
        [Strings.BtnPickFolder] = Strings.TtPickFolder,
        [CacheBackupHoursNum] = Strings.TtCacheBackupHours,
        [CacheBackupKeepNum] = Strings.TtCacheBackupKeep,
        [Strings.BtnBackupNow] = Strings.TtBackupNow,
        [Strings.BtnRestoreBackup] = Strings.TtRestoreBackup,
        [Strings.BtnOpenBackupFolder] = Strings.TtOpenBackupFolder,
        [CacheBackupList] = Strings.TtCacheBackupList,

        // ---- settings: sweep ----
        [SweepFolderBox] = Strings.TtSweepFolder,
        [SweepIntervalCombo] = Strings.TtSweepInterval,
        [Strings.SweepIntervalLabel] = Strings.TtSweepInterval,
        [Strings.BtnInstallUpdate] = Strings.TtSweepInstall,
        [Strings.BtnRunNow] = Strings.TtSweepRunNow,
        [SweepStatus] = Strings.TtSweepStatus,

        // ---- settings: general ----
        [Strings.SettingsLanguageLabel] = Strings.TtLanguage,
        [LanguageCombo] = Strings.TtLanguage,
        [Strings.ThemeLabel] = Strings.TtTheme,
        [ThemeCombo] = Strings.TtTheme,
        [Strings.StartupLabel] = Strings.TtStartup,
        [Strings.ResumeAskLabel] = Strings.TtResumeAsk,
        [Strings.AutoResumeLabel] = Strings.TtAutoResume,
        [Strings.TrayMinimizeLabel] = Strings.TtTrayMinimize,
        [Strings.NotifyThreatLabel] = Strings.TtNotifyThreat,
        [Strings.NotifyThresholdLabel] = Strings.TtNotifyThreshold,
        [Strings.NotifyScanSummaryLabel] = Strings.TtNotifySummary,
        [Strings.ShowVotesLabel] = Strings.TtShowVotes,
        [Strings.WatchDownloadsLabel] = Strings.TtWatchDownloads,
        [Strings.WatchUsbLabel] = Strings.TtWatchUsb,
        [Strings.AutoScanUsbLabel] = Strings.TtAutoScanUsb,
        [Strings.WatchProcessLaunchesLabel] = Strings.TtProcGuard,
        [Strings.SignatureSoftenLabel] = Strings.TtSignatureSoften,
        [Strings.AutoQuarantineWatchersLabel] = Strings.TtAutoQuarantine,
        [Strings.AutoQuarantineThresholdLabel] = Strings.TtAutoQuarantineThreshold,
        [AutoQuarantineNum] = Strings.TtAutoQuarantineThreshold,
        [Strings.MuteInFullscreenLabel] = Strings.TtMuteFullscreen,
        [Strings.QuietHoursLabel] = Strings.TtQuietHours,
        [QuietStartNum] = Strings.TtQuietHours,
        [QuietEndNum] = Strings.TtQuietHours,
        [Strings.QuarantineRetentionLabel] = Strings.TtRetention,
        [RetentionNum] = Strings.TtRetention,
        [Strings.PeriodicRecheckLabel] = Strings.TtPeriodic,
        [PeriodicNum] = Strings.TtPeriodic,
        [Strings.BtnLedgerExport] = Strings.TtLedgerExport,
        [Strings.BtnLedgerImport] = Strings.TtLedgerImport,
        [Strings.LoggingLabel] = Strings.TtLogging,
        [SettingsSearch] = Strings.TtSettingsSearch,

        // ---- settings: confirm gates / about ----
        [Strings.BtnAskAgain] = Strings.TtAskAgain,
        [Strings.AboutGetKeyLink] = Strings.TtGetKeyLink,
        [Strings.BtnResetAllSettings] = Strings.TtResetAll,
        [Strings.BtnExportSettings] = Strings.TtExportSettings,
        [Strings.BtnImportSettings] = Strings.TtImportSettings,

        // ---- quota tab ----
        [Strings.QuotaBtnRefreshFromServer] = Strings.TtQuotaRefresh,
        [QuotaFlow] = Strings.TtQuotaCards,
        [QuotaBanner] = Strings.TtQuotaBanner,

        // ---- history tab ----
        [HistoryGrid] = Strings.TtHistoryGrid,
        [HistorySearch] = Strings.TtHistorySearch,
        [Strings.BtnHistoryClear] = Strings.TtHistoryClear,
        [Strings.BtnHistoryReverdict] = Strings.TtHistoryReverdict,
        [Strings.BtnHistoryExportReport] = Strings.TtHistoryExport,
        [Strings.BtnHistoryRecurring] = Strings.TtHistoryRecurring,
        [Strings.BtnHistoryHotspots] = Strings.TtHistoryHotspots,

        // ---- logs tab ----
        [LogBox] = Strings.TtLogBox,
        [Strings.BtnLogClear] = Strings.TtLogClear,
        [Strings.BtnLogCopyAll] = Strings.TtLogCopyAll,
        [Strings.BtnLogOpenFolder] = Strings.TtLogOpenFolder,

        // ---- detail pane ----
        [Strings.DetailActionQuarantine] = Strings.TtDetailQuarantine,
        [Strings.DetailActionRescanFirst] = Strings.TtDetailRescan,
        [Strings.DetailActionVtReport] = Strings.TtDetailVtReport,
        [Strings.MenuMarkClean] = Strings.TtDetailMarkClean,
        [Strings.MenuCopy] = Strings.TtDetailCopy,
        [Strings.ShowAllEngines] = Strings.TtDetailShowAllEngines,
        [Strings.DetailMajorOnlyCheck] = Strings.TtDetailMajorOnly,
        [Strings.BtnComments] = Strings.TtDetailComments,
        [Strings.BtnBehaviour] = Strings.TtDetailBehaviour,

        // ---- drawer headers (their caption carries a live action count) ----
        ["tt.drawer.scan"] = Strings.TtDrawerScan,
        ["tt.drawer.reports"] = Strings.TtDrawerReports,
        ["tt.drawer.tools"] = Strings.TtDrawerTools,

        // ---- overview cards ----
        [Strings.ActionGoSettings] = Strings.TtActionGoSettings,
        [Strings.ActionEnable] = Strings.TtActionEnable,
        [Strings.ActionScanDownloads] = Strings.TtScanDownloads,
        [Strings.BannerMuteTip] = Strings.BannerMuteTip,
        [Strings.BtnCopy] = Strings.TtDetailCopyValue,
        [CloseButton] = Strings.TtCloseStrip,
        [StatusBannerButton] = Strings.TtOverviewStatusButton,
    };

    /// <summary>Small ✕ buttons that dismiss a strip, and the overview banner's action button, whose
    /// captions are set at runtime.</summary>
    public const string CloseButton = "tt.closeStrip";
    public const string StatusBannerButton = "tt.statusBannerButton";
}
