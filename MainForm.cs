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
    readonly ScanQueueControl _scan = new();
    readonly QuotaDashboardControl _quota = new();
    readonly LogViewerControl _logs = new();
    readonly SettingsControl _settings = new();
    readonly NotifyIcon _tray = new();
    readonly StatusStrip _status = new();
    readonly ToolStripStatusLabel _statusKeys = new();
    bool _reallyExit;
    readonly bool _startHidden;

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

        _scan.NeedApiKey += () => _tabs.SelectedIndex = 3;
        _scan.ThreatFound += OnThreatFound;

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

    void BuildTabs()
    {
        _tabs.Appearance = TabAppearance.Normal;
        AddTab("🛡  Tarama", _scan);
        AddTab("📊  Kotalar", _quota);
        AddTab("📜  Loglar", _logs);
        AddTab("⚙  Ayarlar", _settings);
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
        menu.Items.Add("Göster", null, (_, _) => RestoreFromTray());
        menu.Items.Add("Çıkış", null, (_, _) => { _reallyExit = true; Close(); });
        _tray.ContextMenuStrip = menu;
        _tray.DoubleClick += (_, _) => RestoreFromTray();
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
            _tabs.SelectedIndex = 0;
            _scan.StartScan(real, recurse: true);
        });
    }

    void OnDragDrop(object? sender, DragEventArgs e)
    {
        if (e.Data?.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
        {
            _tabs.SelectedIndex = 0;
            _scan.StartScan(paths, recurse: true);
        }
    }

    // ---- threat notification ----

    void OnThreatFound(ScanItem item)
    {
        if (!Settings.NotifyOnThreat) return;
        SafeUi(() =>
        {
            _tray.BalloonTipTitle = "Tehdit bulundu!";
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
            _tray.BalloonTipText = "Arka planda çalışıyor. Açmak için simgeye çift tıklayın.";
            _tray.ShowBalloonTip(2000);
            return;
        }
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
            if (NativeMessageBox.Confirm("Sağ tuş menüsü kaydı eski exe yolunu gösteriyor (uygulama taşınmış). Şimdi onarılsın mı?"))
                ContextMenuInstaller.Repair(out _);
        }

        OfferResume();
    }

    void OfferResume()
    {
        if (!Settings.ResumeInterruptedScans) return;
        var s = ScanSessionStore.TryLoad();
        if (s == null || s.Paths.Length == 0) return;
        ScanSessionStore.Clear();

        string list = string.Join(", ", s.Paths.Take(3).Select(p => Path.GetFileName(p.TrimEnd('\\'))));
        if (s.Paths.Length > 3) list += " …";
        if (NativeMessageBox.Confirm($"Yarım kalan bir tarama bulundu:\n{list}\n\nKaldığı yerden devam edilsin mi?", "Yarım kalan tarama"))
        {
            _tabs.SelectedIndex = 0;
            _scan.StartScan(s.Paths, s.Recurse, s.BypassTrust);
        }
    }

    void RunFirstRunWizard()
    {
        NativeMessageBox.Info(
            "VirusTotal Scanner'a hoş geldiniz!\n\n" +
            "• Dosya/klasörleri sürükleyip bırakarak veya sağ tuş menüsünden tarayabilirsiniz.\n" +
            "• Başlamak için bir VirusTotal API anahtarı ekleyin.");

        if (!AppServices.Rotator.HasUsableKeys)
        {
            if (NativeMessageBox.Confirm("Şimdi bir VirusTotal API anahtarı eklemek ister misiniz?"))
            {
                using var dlg = new ApiKeyDialog();
                if (dlg.ShowDialog(this) == DialogResult.OK)
                    AppServices.Vault.Add(dlg.KeyLabel, dlg.KeyValue);
            }
        }

        if (ContextMenuInstaller.Verify() != MenuState.Ok &&
            NativeMessageBox.Confirm("Sağ tuş menüsüne 'VirusTotal ile tara' eklensin mi?\n(Tüm kullanıcılar için; yönetici izni/UAC istenecek.)", "İzin"))
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
        _scan.ApplyTheme();
        _quota.ApplyTheme();
        _settings.ApplyTheme();
        _logs.RefreshState();
        if (IsHandleCreated) ApplyDarkTitleBar();
    }

    void UpdateStatusBar()
    {
        int total = AppServices.Vault.Keys.Count;
        int usable = AppServices.Vault.UsableKeyCount;
        _statusKeys.Text = $"  Anahtar: {usable}/{total} kullanılabilir   •   Ayar: {ConfigPathResolver.ConfigPath}";
    }

    void SafeUi(Action a) { try { if (IsHandleCreated) BeginInvoke(a); else a(); } catch { } }
}
