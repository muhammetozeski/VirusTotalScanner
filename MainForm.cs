using System.Drawing;
using System.Runtime.InteropServices;

namespace VirusTotalScanner;

/// <summary>
/// Main application window. Hosts the Tarama / Kotalar / Loglar / Ayarlar tabs, the tray
/// icon, drag-drop, theming and the first-run wizard. Accepts external paths (from the
/// context menu / drag-drop / a forwarded second instance) via <see cref="EnqueueExternalPaths"/>.
/// </summary>
internal sealed partial class MainForm : Form
{
    const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyDarkTitleBar();
        TaskbarProgress.Init(Handle);
    }

    // ---- removable-drive (USB) auto-scan ----
    const int WM_DEVICECHANGE = 0x0219;
    const int DBT_DEVICEARRIVAL = 0x8000;
    const int DBT_DEVTYP_VOLUME = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    struct DevBroadcastVolume { public int Size; public int DeviceType; public int Reserved; public int UnitMask; public short Flags; }

    protected override void WndProc(ref Message m)
    {
        base.WndProc(ref m);
        if (m.Msg == WM_DEVICECHANGE && (int)m.WParam == DBT_DEVICEARRIVAL && m.LParam != IntPtr.Zero)
        {
            try
            {
                if (Marshal.ReadInt32(m.LParam, 4) == DBT_DEVTYP_VOLUME) // dbch_devicetype
                {
                    var vol = Marshal.PtrToStructure<DevBroadcastVolume>(m.LParam);
                    for (int i = 0; i < 26; i++)
                        if ((vol.UnitMask & (1 << i)) != 0) { OnRemovableInserted((char)('A' + i)); break; }
                }
            }
            catch (Exception ex) { Log("Device-change handling failed: " + ex.Message, LogLevel.Warning); }
        }
    }

    void OnRemovableInserted(char letter)
    {
        if (!Settings.WatchUsb) return;
        try { if (new DriveInfo(letter + ":\\").DriveType != DriveType.Removable) return; }
        catch { return; }

        _pendingUsbDrive = letter + ":\\";
        _tray.BalloonTipTitle = "USB sürücü takıldı";
        _tray.BalloonTipText = $"{letter}: sürücüsünü taramak için bu bildirime tıkla.";
        _tray.BalloonTipIcon = ToolTipIcon.Info;
        _tray.ShowBalloonTip(6000);
    }

    void ApplyDarkTitleBar()
    {
        try
        {
            int dark = Theme.Current.IsDark ? 1 : 0;
            DwmSetWindowAttribute(Handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref dark, sizeof(int));
        }
        catch { }
    }

    readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    readonly ScanOverviewControl _overview = new();
    readonly ScanQueueControl _scan = new();
    readonly QuotaDashboardControl _quota = new();
    readonly LogViewerControl _logs = new();
    readonly ScanHistoryControl _history = new();
    readonly SettingsControl _settings = new();
    readonly NotifyIcon _tray = new();
    readonly DownloadsWatcher _downloadsWatcher = new(AppServices.Cache);
    readonly StatusStrip _status = new();
    readonly ToolStripStatusLabel _statusKeys = new();
    bool _reallyExit;
    readonly bool _startHidden;
    string? _pendingUsbDrive; // set when a removable drive is inserted; scanned if the toast is clicked
    ScanItem? _lastThreat;    // last threat toast's item; jumped to if that toast is clicked

    public MainForm(bool startHidden = false)
    {
        _startHidden = startHidden;
        Text = AppConstants.AppTitle;
        ClientSize = new Size(1120, 720);
        MinimumSize = new Size(840, 560);
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        AllowDrop = true;
        TryLoadIcon();

        if (_startHidden)
        {
            // Launched at login with --tray: show invisibly (Application.Run needs a shown form
            // to keep the loop alive), then Hide() on first Shown. Only the tray icon appears.
            WindowState = FormWindowState.Minimized;
            ShowInTaskbar = false;
            Opacity = 0;
        }

        BuildTabs();
        BuildStatusBar();
        BuildTray();

        Controls.Add(_tabs);
        Controls.Add(_status);

        _scan.NeedApiKey += () => _tabs.SelectedIndex = 5; // Ayarlar tab
        _scan.ThreatFound += OnThreatFound;
        _history.RescanRequested += paths => { _tabs.SelectedIndex = 1; _scan.StartScan(paths, recurse: false); };
        _overview.ScanRequested += paths => { _tabs.SelectedIndex = 1; _scan.StartScan(paths, recurse: true); };
        _overview.ScanRunningRequested += () => { _tabs.SelectedIndex = 1; _scan.ScanRunningProcesses(); };
        _overview.ScanDownloadsRequested += () => { _tabs.SelectedIndex = 1; _scan.ScanDownloadsFolder(); };
        _overview.RecheckRequested += () => { _tabs.SelectedIndex = 1; _scan.RescanSweep(); };
        _downloadsWatcher.ThreatFound += item => SafeUi(() => OnThreatFound(item));
        StartDownloadsWatchIfEnabled();

        AppServices.Scheduler.Started += () => SafeUi(TaskbarProgress.Indeterminate);
        AppServices.Scheduler.ProgressChanged += p => SafeUi(() => TaskbarProgress.Set(p.Done, p.Total));
        AppServices.Scheduler.Finished += () => SafeUi(() =>
        {
            var items = AppServices.Scheduler.Items;
            bool threats = items.Any(i => i.Report?.IsMalicious == true);
            if (threats) TaskbarProgress.Threat(); else TaskbarProgress.Clear();
            if (Settings.NotifyScanSummary && items.Count > 0) ShowScanSummaryToast(items);
        });
        System.Net.NetworkInformation.NetworkChange.NetworkAvailabilityChanged += (_, ev) => { if (ev.IsAvailable) SafeUi(RetryPendingOutbox); };
        AppServices.Vault.Changed += () => SafeUi(UpdateStatusBar);
        AppServices.Vault.CountersUpdated += () => SafeUi(UpdateStatusBar);
        Theme.Changed += () => SafeUi(ApplyTheme);

        DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        DragDrop += OnDragDrop;
        FormClosing += OnFormClosing;
        Shown += OnShownFirst;

        ApplyTheme();
        UpdateStatusBar();
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        if (keyData == (Keys.Control | Keys.K))
        {
            using var palette = new CommandPaletteForm(_scan.Commands());
            palette.ShowDialog(this);
            return true;
        }
        return base.ProcessCmdKey(ref msg, keyData);
    }

    void BuildTabs()
    {
        _tabs.Appearance = TabAppearance.Normal;
        AddTab("🏠  Genel Bakış", _overview);
        AddTab(Strings.TabScan, _scan);
        AddTab(Strings.TabQuota, _quota);
        AddTab(Strings.TabLogs, _logs);
        AddTab("🕘  Geçmiş", _history);
        AddTab(Strings.TabSettings, _settings);
    }

    void AddTab(string text, Control content)
    {
        var page = new TabPage(text) { Padding = new Padding(2) };
        content.Dock = DockStyle.Fill;
        page.Controls.Add(content);
        _tabs.TabPages.Add(page);
    }

    void BuildStatusBar()
    {
        _status.SizingGrip = false;
        _statusKeys.Spring = true;
        _statusKeys.TextAlign = ContentAlignment.MiddleLeft;
        _status.Items.Add(_statusKeys);
    }

    void BuildTray()
    {
        _tray.Text = AppConstants.AppTitle;
        _tray.Icon = Icon ?? SystemIcons.Application;
        _tray.Visible = true;
        var menu = new ContextMenuStrip();
        menu.Items.Add(Strings.TrayShow, null, (_, _) => RestoreFromTray());
        menu.Items.Add(Strings.TrayExit, null, (_, _) => { _reallyExit = true; Close(); });
        _tray.ContextMenuStrip = menu;
        _tray.DoubleClick += (_, _) => RestoreFromTray();
        _tray.BalloonTipClicked += OnBalloonClicked;
    }

    void OnBalloonClicked(object? sender, EventArgs e)
    {
        RestoreFromTray();
        if (_pendingUsbDrive is { } drive)
        {
            _pendingUsbDrive = null;
            _tabs.SelectedIndex = 1; // Tarama
            _scan.StartScan([drive], recurse: true);
        }
        else if (_lastThreat is { } threat)
        {
            _tabs.SelectedIndex = 1; // jump to the threat so the user can act (quarantine, open VT…)
            _scan.FocusItem(threat);
        }
    }

    void TryLoadIcon()
    {
        try { Icon = Icon.ExtractAssociatedIcon(AppConstants.ThisExePath); } catch { }
    }

    // ---- external input ----

    internal void SelectTab(int index)
    {
        if (index >= 0 && index < _tabs.TabPages.Count) _tabs.SelectedIndex = index;
    }

    internal void SelectFirstResult() => _scan.SelectFirst();

    public void EnqueueExternalPaths(string[] paths)
    {
        SafeUi(() =>
        {
            RestoreFromTray();
            // Ignore control tokens like "--show"; keep only real existing paths.
            var real = paths.Where(p => !p.StartsWith("--") && (File.Exists(p) || Directory.Exists(p))).ToArray();
            if (real.Length == 0) return;
            _tabs.SelectedIndex = 1;
            _scan.StartScan(real, recurse: true);
        });
    }

    void OnDragDrop(object? sender, DragEventArgs e)
    {
        if (e.Data?.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
        {
            _tabs.SelectedIndex = 1;
            _scan.StartScan(paths, recurse: true);
        }
    }

    void StartDownloadsWatchIfEnabled()
    {
        try
        {
            if (!Settings.WatchDownloads) { _downloadsWatcher.Stop(); return; }
            var folders = Settings.WatchFolders.Value
                .Split([';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            if (folders.Count == 0) folders = DownloadsWatcher.DefaultFolders();
            _downloadsWatcher.Start(folders);
        }
        catch (Exception ex) { Log("Downloads watch init failed: " + ex.Message, LogLevel.Warning); }
    }

    // ---- threat notification ----

    void ShowScanSummaryToast(System.Collections.Generic.IList<ScanItem> items)
    {
        int mal = items.Count(i => i.Report?.IsMalicious == true);
        _tray.BalloonTipTitle = mal > 0 ? "Tarama bitti — tehdit bulundu" : "Tarama bitti — temiz";
        _tray.BalloonTipText = $"{items.Count} dosya tarandı, {mal} tehdit.";
        _tray.BalloonTipIcon = mal > 0 ? ToolTipIcon.Warning : ToolTipIcon.Info;
        _tray.ShowBalloonTip(5000);
    }

    void OnThreatFound(ScanItem item)
    {
        _pendingUsbDrive = null; // a threat toast click should restore the window, not scan a stale drive
        _lastThreat = item;
        if (!Settings.NotifyOnThreat) return;
        if (item.Report != null && item.Report.DetectionCount < Settings.NotifyMinDetections) return; // below the user's severity floor
        SafeUi(() =>
        {
            _tray.BalloonTipTitle = Strings.ThreatBalloonTitle;
            _tray.BalloonTipText = $"{item.FileName}: {item.Report?.Verdict} ({item.Report?.DetectionCount}/{item.Report?.TotalEngines})";
            _tray.BalloonTipIcon = ToolTipIcon.Warning;
            _tray.ShowBalloonTip(5000);
        });
    }

    // ---- tray / closing ----

    void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (!_reallyExit && e.CloseReason == CloseReason.UserClosing && Settings.MinimizeToTray)
        {
            e.Cancel = true;
            Hide();
            _tray.BalloonTipTitle = AppConstants.AppTitle;
            _tray.BalloonTipText = Strings.TrayRunningText;
            _tray.ShowBalloonTip(2000);
            return;
        }
        _downloadsWatcher.Dispose();
        AppServices.Shutdown();
        _tray.Visible = false;
    }

    void RestoreFromTray()
    {
        ShowInTaskbar = true;
        Opacity = 1;
        Show();
        WindowState = FormWindowState.Normal;
        Activate();
        BringToFront();
    }

    // ---- first run ----

    void OnShownFirst(object? sender, EventArgs e)
    {
        if (_startHidden) { Hide(); return; } // straight to tray; no wizard at login

        if (!Settings.FirstRunCompleted)
            RunFirstRunWizard();
        else if (ContextMenuInstaller.NeedsRepair())
        {
            if (NativeMessageBox.Confirm(Strings.RepairMenuPrompt))
                ContextMenuInstaller.Repair(out _);
        }

        OfferResume();
        StartWatchCheck();
        RetryPendingOutbox();
    }

    /// <summary>Self-heal: re-scan files that failed while offline, now that we're back online.</summary>
    void RetryPendingOutbox()
    {
        try
        {
            PendingOutbox.PruneMissing();
            if (!PendingOutbox.ShouldRetry() || AppServices.Scheduler.IsRunning) return;
            var paths = PendingOutbox.Paths().Where(File.Exists).ToArray();
            if (paths.Length == 0) return;
            _tabs.SelectedIndex = 1; // Tarama
            _scan.StartScan(paths, recurse: false);
        }
        catch (Exception ex) { Log("Pending-outbox retry failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Re-check the borderline watch list in the background (keyless, zero quota); alert on any
    /// file whose detection count has climbed since it was added.</summary>
    void StartWatchCheck()
    {
        if (ReverdictWatchStore.Count == 0) return;
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(8000);
                var escalations = await WatchService.CheckAllAsync();
                if (escalations.Count > 0) SafeUi(() => ShowWatchEscalations(escalations));
            }
            catch (Exception ex) { Log("Watch startup check failed: " + ex.Message, LogLevel.Warning); }
        });
    }

    void ShowWatchEscalations(System.Collections.Generic.List<(WatchEntry Entry, int Old, int New)> esc)
    {
        if (!Settings.NotifyOnThreat || esc.Count == 0) return;
        var first = esc[0];
        _tray.BalloonTipTitle = "İzlenen dosya artık daha tehlikeli!";
        _tray.BalloonTipText = esc.Count == 1
            ? $"{first.Entry.Name}: {first.Old} → {first.New} motor tespit ediyor."
            : $"{esc.Count} izlenen dosyanın tespiti arttı (ör. {first.Entry.Name}).";
        _tray.BalloonTipIcon = ToolTipIcon.Warning;
        _tray.ShowBalloonTip(7000);
    }

    void OfferResume()
    {
        var s = ScanSessionStore.TryLoad();
        if (s == null || s.Paths.Length == 0) return;

        // Auto-resume without asking, if enabled.
        if (Settings.AutoResumeScans)
        {
            ScanSessionStore.Clear();
            _tabs.SelectedIndex = 1;
            _scan.StartScan(s.Paths, s.Recurse, s.BypassTrust);
            return;
        }

        if (!Settings.ResumeInterruptedScans) return;
        ScanSessionStore.Clear();

        string list = string.Join(", ", s.Paths.Take(3).Select(p => Path.GetFileName(p.TrimEnd('\\'))));
        if (s.Paths.Length > 3) list += " …";
        if (NativeMessageBox.Confirm(string.Format(Strings.ResumePromptFormat, s.Paths.Length, list), Strings.ResumePromptTitle))
        {
            _tabs.SelectedIndex = 1;
            _scan.StartScan(s.Paths, s.Recurse, s.BypassTrust);
        }
    }

    void RunFirstRunWizard()
    {
        NativeMessageBox.Info(Strings.FirstRunWelcome);

        if (!AppServices.Rotator.HasUsableKeys)
        {
            if (NativeMessageBox.Confirm(Strings.FirstRunAddKey))
            {
                using var dlg = new ApiKeyDialog();
                if (dlg.ShowDialog(this) == DialogResult.OK)
                    AppServices.Vault.Add(dlg.KeyLabel, dlg.KeyValue);
            }
        }

        if (ContextMenuInstaller.Verify() != MenuState.Ok &&
            NativeMessageBox.Confirm(Strings.FirstRunMenuPrompt, Strings.FirstRunMenuTitle))
        {
            _ = Task.Run(() => ContextMenuInstaller.Install(Settings.ContextMenuExcludeSafe, out _));
        }

        Settings.FirstRunCompleted.Value = true;
        SettingsManager.SaveSettings();
    }

    // ---- theme / status ----

    void ApplyTheme()
    {
        var p = Theme.Current;
        BackColor = p.Background;
        _tabs.BackColor = p.Background;
        _status.BackColor = p.Panel;
        _status.ForeColor = p.Text;
        ThemeManager.Apply(this);
        _overview.ApplyTheme();
        _scan.ApplyTheme();
        _quota.ApplyTheme();
        _settings.ApplyTheme();
        _history.ApplyTheme();
        _logs.RefreshState();
        if (IsHandleCreated) ApplyDarkTitleBar();
    }

    void UpdateStatusBar()
    {
        int total = AppServices.Vault.Keys.Count;
        int usable = AppServices.Vault.UsableKeyCount;
        _statusKeys.Text = string.Format(Strings.StatusBarFormat, usable, total, ConfigPathResolver.ConfigPath);
    }

    void SafeUi(Action a) { try { if (IsHandleCreated) BeginInvoke(a); else a(); } catch (Exception ex) { Log("UI dispatch failed: " + ex.Message, LogLevel.Warning); } }
}
