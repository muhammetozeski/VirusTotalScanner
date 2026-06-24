using System.Drawing;

namespace VirusTotalScanner;

/// <summary>"Ayarlar" tab: API keys CRUD, context-menu install/repair/uninstall, scan and
/// general preferences. Every change is persisted immediately.</summary>
internal sealed class SettingsControl : UserControl
{
    sealed class KeyRow
    {
        // Properties (not fields) — DataGridView data binding only binds to properties.
        public string Id { get; set; } = "";
        public string Label { get; set; } = "";
        public string Anahtar { get; set; } = "";
        public string Durum { get; set; } = "";
    }

    readonly FlowLayoutPanel _flow = new();
    readonly DataGridView _keysGrid = new();
    readonly Label _menuStatus = new();

    public SettingsControl()
    {
        Dock = DockStyle.Fill;
        _flow.Dock = DockStyle.Fill;
        _flow.FlowDirection = FlowDirection.TopDown;
        _flow.WrapContents = false;
        _flow.AutoScroll = true;
        _flow.Padding = new Padding(10);
        Controls.Add(_flow);

        _flow.Controls.Add(BuildKeysCard());
        _flow.Controls.Add(BuildContextMenuCard());
        _flow.Controls.Add(BuildTrustCard());
        _flow.Controls.Add(BuildVerdictCard());
        _flow.Controls.Add(BuildScanCard());
        _flow.Controls.Add(BuildSweepCard());
        _flow.Controls.Add(BuildGeneralCard());
        _flow.Controls.Add(BuildConfirmGatesCard());
        _flow.Controls.Add(BuildAboutCard());

        Resize += (_, _) => ResizeCards();
        _flow.Resize += (_, _) => ResizeCards();
        AppServices.Vault.Changed += () => SafeUi(RefreshKeys);

        RefreshKeys();
        RefreshMenuStatus();
    }

    void ResizeCards()
    {
        int w = _flow.ClientSize.Width - 28;
        if (w < 200) return;
        foreach (Control c in _flow.Controls) c.Width = w;
    }

    Panel BuildKeysCard()
    {
        var card = Card(Strings.CardApiKeys, 270, out var body);

        _keysGrid.Dock = DockStyle.Top;
        _keysGrid.Height = 150;
        _keysGrid.AutoGenerateColumns = false;
        _keysGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColLabel, DataPropertyName = nameof(KeyRow.Label), Width = 160 });
        _keysGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColKey, DataPropertyName = nameof(KeyRow.Anahtar), Width = 160 });
        _keysGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColStatus, DataPropertyName = nameof(KeyRow.Durum), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        ThemeManager.StyleGrid(_keysGrid);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(0, 6, 0, 0) };
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnAdd, (_, _) => AddKey(), accent: true));
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnEdit, (_, _) => EditKey()));
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnDelete, (_, _) => RemoveKey()));
        var hint = ThemeManager.MakeLabel(Strings.KeysHint, subtle: true);

        body.Controls.Add(hint);
        body.Controls.Add(buttons);
        body.Controls.Add(_keysGrid);
        return card;
    }

    Panel BuildContextMenuCard()
    {
        var card = Card(Strings.CardContextMenu, 180, out var body);
        _menuStatus.AutoSize = true;
        _menuStatus.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);

        var excludeSafe = new CheckBox { Text = Strings.CtxExcludeSafe, AutoSize = true, Checked = Settings.ContextMenuExcludeSafe };
        excludeSafe.CheckedChanged += (_, _) => { Settings.ContextMenuExcludeSafe.Value = excludeSafe.Checked; SettingsManager.SaveSettings(); };

        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top };
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnCtxInstall, (_, _) => InstallMenu(), accent: true));
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnRepair, (_, _) => RunMenuOp(() => ContextMenuInstaller.Repair(out var e), Strings.CtxRepaired)));
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnRemove, (_, _) => RunMenuOp(() => ContextMenuInstaller.Uninstall(out var e), Strings.CtxRemoved)));

        body.Controls.Add(excludeSafe);
        body.Controls.Add(buttons);
        body.Controls.Add(_menuStatus);
        return card;
    }

    Panel BuildTrustCard()
    {
        var card = Card(Strings.CardTrust, 330, out var body);

        var info = ThemeManager.MakeLabel(Strings.TrustInfo, subtle: true);

        var skipSigned = new CheckBox { Text = Strings.TrustSkipSignedLabel, AutoSize = true, Checked = Settings.TrustSkipSigned };
        skipSigned.CheckedChanged += (_, _) => { Settings.TrustSkipSigned.Value = skipSigned.Checked; SettingsManager.SaveSettings(); };

        var msOnly = new CheckBox { Text = Strings.TrustMsOnlyLabel, AutoSize = true, Checked = Settings.TrustMicrosoftOnly };
        msOnly.CheckedChanged += (_, _) => { Settings.TrustMicrosoftOnly.Value = msOnly.Checked; SettingsManager.SaveSettings(); };

        var allowLbl = ThemeManager.MakeLabel(Strings.TrustAllowLabel);
        var allow = new TextBox { Dock = DockStyle.Top, Text = Settings.TrustPublisherAllowList };
        allow.Leave += (_, _) => { Settings.TrustPublisherAllowList.Value = allow.Text.Trim(); SettingsManager.SaveSettings(); };

        var dbRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Top };
        var dbBox = new TextBox { Width = 360, Text = Settings.KnownGoodHashDbPath, ReadOnly = true };
        var pick = ThemeManager.MakeButton(Strings.TrustPickHashList, (_, _) =>
        {
            using var dlg = new OpenFileDialog { Filter = Strings.TrustHashFilter };
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                Settings.KnownGoodHashDbPath.Value = dlg.FileName;
                SettingsManager.SaveSettings();
                dbBox.Text = dlg.FileName;
                KnownGoodDb.Reload();
                NativeMessageBox.Info(string.Format(Strings.TrustHashLoadedFormat, KnownGoodDb.Count));
            }
        });
        dbRow.Controls.Add(dbBox);
        dbRow.Controls.Add(pick);

        var keyless = new CheckBox { Text = Strings.TrustKeylessLabel, AutoSize = true, Checked = Settings.KeylessGuiLookup };
        keyless.CheckedChanged += (_, _) => { Settings.KeylessGuiLookup.Value = keyless.Checked; SettingsManager.SaveSettings(); };

        body.Controls.Add(info);
        body.Controls.Add(skipSigned);
        body.Controls.Add(keyless);
        body.Controls.Add(msOnly);
        body.Controls.Add(allowLbl);
        body.Controls.Add(allow);
        body.Controls.Add(dbRow);
        return card;
    }

    System.ComponentModel.BindingList<VerdictCategory>? _catRows;
    DataGridView? _catGrid;

    Panel BuildVerdictCard()
    {
        var card = Card(Strings.CardVerdictCats, 340, out var body);

        _catGrid = new DataGridView { Dock = DockStyle.Top, Height = 130, AutoGenerateColumns = false };
        _catGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColMinDetections, DataPropertyName = nameof(VerdictCategory.MinDetections), Width = 90 });
        _catGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColName, DataPropertyName = nameof(VerdictCategory.Name), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _catGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColColor, Width = 110, ReadOnly = true });
        _catGrid.ReadOnly = false;
        _catGrid.AllowUserToAddRows = false;
        _catGrid.CellFormatting += (_, e) =>
        {
            if (e.ColumnIndex == 2 && _catGrid.Rows[e.RowIndex].DataBoundItem is VerdictCategory c)
            {
                e.Value = c.ColorHex;
                e.CellStyle!.BackColor = c.Color;
                e.CellStyle.ForeColor = c.Color.GetBrightness() < 0.5 ? System.Drawing.Color.White : System.Drawing.Color.Black;
            }
        };
        ThemeManager.StyleGrid(_catGrid);
        _catGrid.ReadOnly = false; // re-enable after StyleGrid (which sets ReadOnly=true)

        RefreshCats();

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnAddShort, (_, _) =>
        {
            int next = (_catRows!.Count == 0 ? 0 : _catRows.Max(c => c.MinDetections) + 1);
            _catRows.Add(new VerdictCategory { MinDetections = next, Name = Strings.CatNewName, ColorHex = "#888888" });
        }, accent: true));
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnPickColor, (_, _) =>
        {
            if (_catGrid.CurrentRow?.DataBoundItem is not VerdictCategory c) return;
            using var dlg = new ColorDialog { Color = c.Color, FullOpen = true };
            if (dlg.ShowDialog() == DialogResult.OK) { c.ColorHex = "#" + dlg.Color.R.ToString("X2") + dlg.Color.G.ToString("X2") + dlg.Color.B.ToString("X2"); _catGrid.Invalidate(); }
        }));
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnDelete, (_, _) => { if (_catGrid.CurrentRow?.DataBoundItem is VerdictCategory c) _catRows!.Remove(c); }));
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnSave, (_, _) => { VerdictCategories.Save(_catRows!); RefreshCats(); Theme.ApplyFromSettings(); NativeMessageBox.Info(Strings.CatsSaved); }));
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnDefault, (_, _) => { VerdictCategories.Save(VerdictCategories.Defaults()); RefreshCats(); Theme.ApplyFromSettings(); }));

        var majorBox = new TextBox { Dock = DockStyle.Top, Text = Settings.MajorEnginesList };
        var majorSave = ThemeManager.MakeButton(Strings.BtnSaveMajorEngines, (_, _) =>
        {
            Settings.MajorEnginesList.Value = majorBox.Text.Trim();
            SettingsManager.SaveSettings();
            MajorEngines.Load();
            NativeMessageBox.Info(Strings.MajorEnginesSaved);
        });

        body.Controls.Add(buttons);
        body.Controls.Add(_catGrid);
        body.Controls.Add(ThemeManager.MakeLabel(Strings.CatThresholdHint, subtle: true));
        body.Controls.Add(majorSave);
        body.Controls.Add(majorBox);
        body.Controls.Add(ThemeManager.MakeLabel(Strings.MajorEnginesHint, subtle: true));
        return card;
    }

    void RefreshCats()
    {
        _catRows = new System.ComponentModel.BindingList<VerdictCategory>(
            VerdictCategories.All.Select(c => new VerdictCategory { MinDetections = c.MinDetections, Name = c.Name, ColorHex = c.ColorHex }).ToList());
        if (_catGrid != null) _catGrid.DataSource = _catRows;
    }

    Panel BuildScanCard()
    {
        var card = Card(Strings.CardScan, 355, out var body);

        var concurrency = LabeledNumeric(Strings.ScanConcurrencyLabel, Settings.MaxConcurrentScans, 1, 16,
            v => { Settings.MaxConcurrentScans.Value = v; SettingsManager.SaveSettings(); });
        var maxSize = LabeledNumeric(Strings.ScanMaxSizeLabel, Settings.MaxFileSizeMB, 0, 100000,
            v => { Settings.MaxFileSizeMB.Value = v; SettingsManager.SaveSettings(); });
        var recheckDays = LabeledNumeric(Strings.ScanRecheckDaysLabel, Settings.RecheckPeriodDays, 1, 365,
            v => { Settings.RecheckPeriodDays.Value = v; SettingsManager.SaveSettings(); });
        var uploads = LabeledNumeric(Strings.ScanUploadsLabel, Settings.MaxConcurrentUploads, 1, 16,
            v => { Settings.MaxConcurrentUploads.Value = v; SettingsManager.SaveSettings(); });
        var cache = new CheckBox { Text = Strings.ScanUseCacheLabel, AutoSize = true, Checked = Settings.UseLocalHashCache };
        cache.CheckedChanged += (_, _) => { Settings.UseLocalHashCache.Value = cache.Checked; SettingsManager.SaveSettings(); };
        var cacheDays = LabeledNumeric(Strings.ScanCacheDaysLabel, Settings.HashCacheDays, 0, 365,
            v => { Settings.HashCacheDays.Value = v; SettingsManager.SaveSettings(); });
        var skipSafe = new CheckBox { Text = Strings.ScanSkipSafeLabel, AutoSize = true, Checked = Settings.SkipSafeExtensionsOnScan };
        skipSafe.CheckedChanged += (_, _) => { Settings.SkipSafeExtensionsOnScan.Value = skipSafe.Checked; SettingsManager.SaveSettings(); };

        var lbl = ThemeManager.MakeLabel(Strings.ScanSafeExtsLabel);
        var exts = new TextBox { Dock = DockStyle.Top, Text = Settings.SafeExtensions, Height = 24 };
        var save = ThemeManager.MakeButton(Strings.BtnSaveExts, (_, _) => { Settings.SafeExtensions.Value = exts.Text.Trim(); SettingsManager.SaveSettings(); });

        body.Controls.Add(exts);
        body.Controls.Add(lbl);
        body.Controls.Add(save);
        body.Controls.Add(skipSafe);
        body.Controls.Add(cacheDays);
        body.Controls.Add(cache);
        body.Controls.Add(recheckDays);
        body.Controls.Add(maxSize);
        body.Controls.Add(uploads);
        body.Controls.Add(concurrency);
        return card;
    }

    static string SweepStatusText() =>
        SweepScheduler.IsInstalled()
            ? Strings.SweepStatusInstalled + (string.IsNullOrEmpty(Settings.SweepFolder.Value) ? "" : " — " + Settings.SweepFolder.Value)
            : Strings.SweepStatusNotInstalled;

    Panel BuildSweepCard()
    {
        var card = Card(Strings.CardSweep, 250, out var body);

        var status = ThemeManager.MakeLabel(SweepStatusText(), subtle: true);
        var folderBox = new TextBox { Dock = DockStyle.Top, Text = Settings.SweepFolder };
        var pick = ThemeManager.MakeButton(Strings.BtnPickFolder, (_, _) =>
        {
            using var dlg = new FolderBrowserDialog { Description = Strings.SweepFolderDescription };
            if (dlg.ShowDialog() == DialogResult.OK) folderBox.Text = dlg.SelectedPath;
        });

        var intervalRow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top };
        intervalRow.Controls.Add(ThemeManager.MakeLabel(Strings.SweepIntervalLabel));
        var interval = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 200 };
        interval.Items.AddRange([Strings.SweepDaily, Strings.Sweep6h, Strings.Sweep12h, Strings.SweepWeekly]);
        interval.SelectedIndex = 0;
        intervalRow.Controls.Add(interval);

        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top };
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnInstallUpdate, (_, _) =>
        {
            string[] sched = interval.SelectedIndex switch
            {
                1 => ["/SC", "HOURLY", "/MO", "6"],
                2 => ["/SC", "HOURLY", "/MO", "12"],
                3 => ["/SC", "WEEKLY", "/D", "SUN", "/ST", "03:00"],
                _ => ["/SC", "DAILY", "/ST", "03:00"],
            };
            if (SweepScheduler.Install(folderBox.Text.Trim(), sched, out var err))
                NativeMessageBox.Info(string.Format(Strings.SweepInstalledFormat, SweepScheduler.ReportPath));
            else NativeMessageBox.Error(Strings.SweepInstallFailedPrefix + err);
            status.Text = SweepStatusText();
        }, accent: true));
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnRunNow, (_, _) =>
        {
            if (SweepScheduler.RunNow(out var err)) NativeMessageBox.Info(Strings.SweepStartedInfo);
            else NativeMessageBox.Error(Strings.SweepRunFailedPrefix + err);
        }));
        buttons.Controls.Add(ThemeManager.MakeButton(Strings.BtnRemove, (_, _) =>
        {
            if (SweepScheduler.Uninstall(out var err)) NativeMessageBox.Info(Strings.SweepRemovedInfo);
            else NativeMessageBox.Error(Strings.SweepRemoveFailedPrefix + err);
            status.Text = SweepStatusText();
        }));

        body.Controls.Add(ThemeManager.MakeLabel(Strings.SweepHint, subtle: true));
        body.Controls.Add(intervalRow);
        body.Controls.Add(folderBox);
        body.Controls.Add(pick);
        body.Controls.Add(buttons);
        body.Controls.Add(status);
        return card;
    }

    Panel BuildGeneralCard()
    {
        var card = Card(Strings.CardGeneral, 450, out var body);

        var langRow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top };
        langRow.Controls.Add(ThemeManager.MakeLabel(Strings.SettingsLanguageLabel));
        var langCombo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
        foreach (var (_, name) in LocManager.Available) langCombo.Items.Add(name);
        int curLang = Array.FindIndex(LocManager.Available, a => a.Code.Equals(Settings.Language.Value, StringComparison.OrdinalIgnoreCase));
        langCombo.SelectedIndex = curLang < 0 ? 0 : curLang;
        langCombo.SelectedIndexChanged += (_, _) =>
        {
            string code = LocManager.Available[langCombo.SelectedIndex].Code;
            if (!string.Equals(code, Settings.Language.Value, StringComparison.OrdinalIgnoreCase))
            {
                Settings.Language.Value = code;
                SettingsManager.SaveSettings();
                NativeMessageBox.Info(Strings.LanguageRestartNote);
            }
        };
        langRow.Controls.Add(langCombo);

        var themeRow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top };
        themeRow.Controls.Add(ThemeManager.MakeLabel(Strings.ThemeLabel));
        var combo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
        combo.Items.AddRange([Strings.ThemeFollow, Strings.ThemeDark, Strings.ThemeLight]);
        combo.SelectedIndex = Settings.FollowWindowsTheme ? 0 : (string.Equals(Settings.Theme.Value, "Light", StringComparison.OrdinalIgnoreCase) ? 2 : 1);
        combo.SelectedIndexChanged += (_, _) =>
        {
            if (combo.SelectedIndex == 0) Theme.SetTheme("Dark", follow: true);
            else Theme.SetTheme(combo.SelectedIndex == 2 ? "Light" : "Dark", follow: false);
        };
        themeRow.Controls.Add(combo);

        var tray = new CheckBox { Text = Strings.TrayMinimizeLabel, AutoSize = true, Checked = Settings.MinimizeToTray };
        tray.CheckedChanged += (_, _) => { Settings.MinimizeToTray.Value = tray.Checked; SettingsManager.SaveSettings(); };
        var notify = new CheckBox { Text = Strings.NotifyThreatLabel, AutoSize = true, Checked = Settings.NotifyOnThreat };
        notify.CheckedChanged += (_, _) => { Settings.NotifyOnThreat.Value = notify.Checked; SettingsManager.SaveSettings(); };
        var votes = new CheckBox { Text = Strings.ShowVotesLabel, AutoSize = true, Checked = Settings.ShowCommunityVotes };
        votes.CheckedChanged += (_, _) => { Settings.ShowCommunityVotes.Value = votes.Checked; SettingsManager.SaveSettings(); };
        var watch = new CheckBox { Text = Strings.WatchDownloadsLabel, AutoSize = true, Checked = Settings.WatchDownloads };
        watch.CheckedChanged += (_, _) =>
        {
            Settings.WatchDownloads.Value = watch.Checked;
            SettingsManager.SaveSettings();
            NativeMessageBox.Info(string.Format(Strings.WatchToggleFormat, watch.Checked ? Strings.WatchOn : Strings.WatchOff));
        };
        var logging = new CheckBox { Text = Strings.LoggingLabel, AutoSize = true, Checked = LoggerHost.IsEnabled };
        logging.CheckedChanged += (_, _) => LoggerHost.SetEnabled(logging.Checked);

        var startup = new CheckBox { Text = Strings.StartupLabel, AutoSize = true, Checked = StartupManager.IsEnabled() };
        startup.CheckedChanged += (_, _) => StartupManager.SetEnabled(startup.Checked);

        var resume = new CheckBox { Text = Strings.ResumeAskLabel, AutoSize = true, Checked = Settings.ResumeInterruptedScans };
        resume.CheckedChanged += (_, _) => { Settings.ResumeInterruptedScans.Value = resume.Checked; SettingsManager.SaveSettings(); };

        var autoResume = new CheckBox { Text = Strings.AutoResumeLabel, AutoSize = true, Checked = Settings.AutoResumeScans };
        autoResume.CheckedChanged += (_, _) => { Settings.AutoResumeScans.Value = autoResume.Checked; SettingsManager.SaveSettings(); };

        body.Controls.Add(langRow);
        body.Controls.Add(themeRow);
        body.Controls.Add(startup);
        body.Controls.Add(resume);
        body.Controls.Add(autoResume);
        var ledgerRow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top };
        ledgerRow.Controls.Add(ThemeManager.MakeButton(Strings.BtnLedgerExport, (_, _) =>
        {
            using var dlg = new SaveFileDialog { Filter = "Ledger|*.json", FileName = "team-ledger.json" };
            if (dlg.ShowDialog() == DialogResult.OK) NativeMessageBox.Info(string.Format(Strings.LedgerWrittenFormat, LedgerService.Export(AppServices.Cache, dlg.FileName)));
        }));
        ledgerRow.Controls.Add(ThemeManager.MakeButton(Strings.BtnLedgerImport, (_, _) =>
        {
            using var dlg = new OpenFileDialog { Filter = "Ledger|*.json" };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            var (add, conf, ok) = LedgerService.Import(AppServices.Cache, dlg.FileName);
            NativeMessageBox.Info(string.Format(Strings.LedgerImportedFormat, add, conf, ok ? Strings.LedgerIntegrityOk : Strings.LedgerIntegrityBad));
        }));

        body.Controls.Add(tray);
        body.Controls.Add(notify);
        body.Controls.Add(votes);
        body.Controls.Add(watch);
        body.Controls.Add(ledgerRow);
        body.Controls.Add(logging);
        return card;
    }

    Panel BuildConfirmGatesCard()
    {
        var gates = ConfirmGateManager.All.ToList();
        var card = Card(Strings.CardConfirmGates, 70 + gates.Count * 30, out var body);
        body.Controls.Add(ThemeManager.MakeLabel(Strings.ConfirmGatesHint, subtle: true));
        foreach (var gate in gates)
        {
            var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Top };
            var lbl = ThemeManager.MakeLabel("");
            var btn = ThemeManager.MakeButton(Strings.BtnAskAgain, null);
            void Refresh()
            {
                lbl.Text = gate.Title + (gate.Suppressed ? string.Format(Strings.GateSuppressedFormat, gate.RememberedAnswer ? Strings.GateYes : Strings.GateNo) : Strings.GateAsking);
                btn.Enabled = gate.Suppressed;
            }
            btn.Click += (_, _) => { gate.ResetSuppression(); Refresh(); };
            Refresh();
            row.Controls.Add(lbl);
            row.Controls.Add(btn);
            body.Controls.Add(row);
        }
        return card;
    }

    Panel BuildAboutCard()
    {
        var card = Card(Strings.CardAbout, 110, out var body);
        body.Controls.Add(ThemeManager.MakeLabel($"{AppConstants.AppTitle} v{AppConstants.Version}", subtle: true));
        var link = new LinkLabel { Text = Strings.AboutGetKeyLink, AutoSize = true };
        link.LinkClicked += (_, _) => OpenUrlInBrowser("https://www.virustotal.com/gui/my-apikey");
        body.Controls.Add(link);
        body.Controls.Add(ThemeManager.MakeLabel(Strings.AboutConfigFilePrefix + ConfigPathResolver.ConfigPath, subtle: true));
        return card;
    }

    // ---- key actions ----

    void AddKey()
    {
        using var dlg = new ApiKeyDialog();
        if (dlg.ShowDialog(this) == DialogResult.OK)
            AppServices.Vault.Add(dlg.KeyLabel, dlg.KeyValue);
    }

    void EditKey()
    {
        var id = SelectedKeyId();
        if (id == null) return;
        var entry = AppServices.Vault.Keys.FirstOrDefault(k => k.Id == id);
        if (entry == null) return;
        using var dlg = new ApiKeyDialog(entry.Label, entry.Key);
        if (dlg.ShowDialog(this) == DialogResult.OK)
            AppServices.Vault.UpdateMeta(id, dlg.KeyLabel, dlg.KeyValue);
    }

    void RemoveKey()
    {
        var id = SelectedKeyId();
        if (id == null) return;
        if (NativeMessageBox.Confirm("Bu anahtar silinsin mi?")) AppServices.Vault.Remove(id);
    }

    string? SelectedKeyId() => (_keysGrid.CurrentRow?.DataBoundItem as KeyRow)?.Id;

    void RefreshKeys()
    {
        var now = DateTime.UtcNow;
        var rows = AppServices.Vault.Keys.Select(k => new KeyRow
        {
            Id = k.Id,
            Label = string.IsNullOrWhiteSpace(k.Label) ? "Key" : k.Label,
            Anahtar = k.Masked,
            Durum = k.Disabled ? Strings.KeyStatusDisabled : k.IsExhausted(now) ? Strings.KeyStatusExhausted : Strings.KeyStatusActive,
        }).ToList();
        _keysGrid.DataSource = rows;
    }

    void InstallMenu()
    {
        if (!NativeMessageBox.Confirm(Strings.MenuInstallConfirm, Strings.FirstRunMenuTitle))
            return;
        RunMenuOp(() => ContextMenuInstaller.Install(Settings.ContextMenuExcludeSafe, out var e), Strings.MenuInstalledInfo);
    }

    /// <summary>Runs an elevation-capable menu op off the UI thread, then refreshes status.</summary>
    void RunMenuOp(Func<bool> op, string okMsg)
    {
        _ = Task.Run(() =>
        {
            bool ok = op();
            SafeUi(() =>
            {
                RefreshMenuStatus();
                if (ok) NativeMessageBox.Info(okMsg);
                else NativeMessageBox.Warn(Strings.MenuOpFailedWarn);
            });
        });
    }

    void RefreshMenuStatus()
    {
        var state = ContextMenuInstaller.Verify();
        _menuStatus.Text = Strings.MenuStatusPrefix + ContextMenuInstaller.Describe(state);
        _menuStatus.ForeColor = state switch
        {
            MenuState.Ok => Theme.Current.Success,
            MenuState.Stale => Theme.Current.Warning,
            MenuState.Missing => Theme.Current.SubtleText,
            _ => Theme.Current.Danger,
        };
    }

    // ---- ui helpers ----

    Panel Card(string title, int height, out FlowLayoutPanel body)
    {
        var card = ThemeManager.MakeCard();
        card.Height = height;
        card.Width = 700;

        var titleLbl = ThemeManager.MakeTitle(title);
        titleLbl.Dock = DockStyle.Top;

        body = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = false, BackColor = Color.Transparent };
        // Add controls bottom-up because Dock=Top stacks in reverse insertion order.
        card.Controls.Add(body);
        card.Controls.Add(titleLbl);
        return card;
    }

    Control LabeledNumeric(string label, int value, int min, int max, Action<int> onChange)
    {
        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Top };
        row.Controls.Add(ThemeManager.MakeLabel(label));
        var nud = new NumericUpDown { Minimum = min, Maximum = max, Value = Math.Clamp(value, min, max), Width = 70 };
        nud.ValueChanged += (_, _) => onChange((int)nud.Value);
        row.Controls.Add(nud);
        return row;
    }

    void SafeUi(Action a) { try { if (IsHandleCreated) BeginInvoke(a); else a(); } catch (Exception ex) { Log("UI dispatch failed: " + ex.Message, LogLevel.Warning); } }

    public void ApplyTheme()
    {
        ThemeManager.StyleGrid(_keysGrid);
        RefreshMenuStatus();
    }
}
