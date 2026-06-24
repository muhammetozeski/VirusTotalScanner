using System.Drawing;
using System.Drawing.Drawing2D;

namespace VirusTotalScanner;

/// <summary>
/// The "Genel Bakış" landing tab: instead of opening to a blank queue, the user sees a big drop-zone
/// with one obvious action, count tiles from their scan history, a recent-scans strip (click to reopen
/// from cache), and an amber attention strip that only appears when something needs a decision.
/// </summary>
internal sealed class ScanOverviewControl : UserControl
{
    readonly Panel _statusBanner = new() { Dock = DockStyle.Top, Height = 56, Margin = new Padding(8, 8, 8, 2) };
    readonly Label _statusLabel = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true, Padding = new Padding(14, 0, 0, 0), Font = new Font("Segoe UI", 11f, FontStyle.Bold) };
    readonly Button _statusBtn = new() { Dock = DockStyle.Right, Width = 160, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand, Visible = false };
    Action? _statusAction;
    readonly Panel _attention = new() { Dock = DockStyle.Top, Height = 40, Visible = false, Padding = new Padding(12, 0, 8, 0) };
    readonly Label _attentionLabel = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
    readonly Panel _drop = new() { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(0, 4, 0, 10), Margin = new Padding(8) };
    readonly Label _tehditNum = new(), _supheliNum = new(), _temizNum = new();
    readonly FlowLayoutPanel _recent = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(8, 4, 8, 8) };
    readonly Label _quota = new() { Dock = DockStyle.Bottom, Height = 26, TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(12, 0, 0, 0), Tag = "subtle" };

    /// <summary>Files dropped or picked here — the host switches to the scan tab and starts a scan.</summary>
    public event Action<string[]>? ScanRequested;
    /// <summary>Quick-action launchpad verbs, dispatched to the scan control by the host.</summary>
    public event Action? ScanRunningRequested, ScanDownloadsRequested, RecheckRequested;
    /// <summary>Status-banner "go to the relevant tab" — the host switches to the given tab index.</summary>
    public event Action<int>? GoToTab;
    /// <summary>A count tile was clicked — the host opens History pre-filtered to that category
    /// ("threat" / "suspicious" / "clean").</summary>
    public event Action<string>? GoToHistoryFiltered;
    /// <summary>The user turned on download-watching from the coverage card — the host (re)starts the watcher.</summary>
    public event Action? WatchDownloadsToggled;

    readonly FlowLayoutPanel _coverageRows = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Margin = new Padding(0) };

    public ScanOverviewControl()
    {
        Dock = DockStyle.Fill;
        AllowDrop = true;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, AutoScroll = true, ColumnCount = 1, RowCount = 6, Padding = new Padding(8) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); // full-width column, no horizontal scroll
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // status banner
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // coverage card
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // attention
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // drop-zone (sizes to content, DPI-safe)
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // count tiles (sizes to content)
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));     // recent (bounded panel; root AutoScrolls if needed)

        _attention.Controls.Add(_attentionLabel);
        BuildDropZone();
        BuildStatusBanner();

        root.Controls.Add(_statusBanner, 0, 0);
        root.Controls.Add(BuildCoverageCard(), 0, 1);
        root.Controls.Add(_attention, 0, 2);
        root.Controls.Add(_drop, 0, 3);
        root.Controls.Add(BuildTiles(), 0, 4);
        root.Controls.Add(BuildRecent(), 0, 5);
        Controls.Add(root);

        DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        DragDrop += OnDrop;

        ScanHistoryStore.Changed += OnStoreChanged;
        VisibleChanged += (_, _) => { if (Visible) Refresh2(); };
        Refresh2();
    }

    void OnStoreChanged() { try { if (IsHandleCreated) BeginInvoke(Refresh2); } catch { } }

    protected override void Dispose(bool disposing)
    {
        if (disposing) ScanHistoryStore.Changed -= OnStoreChanged;
        base.Dispose(disposing);
    }

    void BuildDropZone()
    {
        _drop.Paint += (_, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var r = _drop.ClientRectangle; r.Inflate(-10, -10);
            using var pen = new Pen(Theme.Current.Accent, 2) { DashStyle = DashStyle.Dash };
            using var path = Rounded(r, 16);
            g.DrawPath(pen, path);
        };

        // AutoSize content (no fixed pixel heights) so the hint + buttons always fit and scale with DPI.
        var inner = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 1, RowCount = 2, BackColor = Color.Transparent };
        inner.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        inner.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        inner.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var hint = new Label { Text = "🛡  Taramak için dosya/klasörü buraya sürükle", AutoSize = true, Anchor = AnchorStyles.None, TextAlign = ContentAlignment.MiddleCenter, Font = new Font("Segoe UI", 13f, FontStyle.Bold), Margin = new Padding(0, 12, 0, 8) };
        var buttons = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Anchor = AnchorStyles.None, FlowDirection = FlowDirection.LeftToRight, WrapContents = true, Margin = new Padding(0, 0, 0, 10) };
        buttons.Controls.Add(ThemeManager.MakeButton("📄  Dosya seç…", (_, _) => PickFiles(), accent: true));
        buttons.Controls.Add(ThemeManager.MakeButton("📁  Klasör seç…", (_, _) => PickFolder()));
        buttons.Controls.Add(ThemeManager.MakeButton("🔬  Çalışanları tara", (_, _) => ScanRunningRequested?.Invoke()));
        buttons.Controls.Add(ThemeManager.MakeButton("⬇  İndirilenleri tara", (_, _) => ScanDownloadsRequested?.Invoke()));
        buttons.Controls.Add(ThemeManager.MakeButton("🔁  Yeniden denetle", (_, _) => RecheckRequested?.Invoke()));
        inner.Controls.Add(hint, 0, 0);
        inner.Controls.Add(buttons, 0, 1);
        _drop.Controls.Add(inner);
        _drop.AllowDrop = true;
        _drop.DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        _drop.DragDrop += OnDrop;
        hint.AllowDrop = true;
        hint.DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        hint.DragDrop += OnDrop;
    }

    static Panel FlowCenter(Control inner)
    {
        var host = new Panel { Dock = DockStyle.Fill };
        inner.Anchor = AnchorStyles.None;
        host.Controls.Add(inner);
        host.Resize += (_, _) => inner.Location = new Point((host.Width - inner.Width) / 2, (host.Height - inner.Height) / 2);
        return host;
    }

    Control BuildCoverageCard()
    {
        var card = ThemeManager.MakeCard();
        card.Dock = DockStyle.Top;
        card.AutoSize = true;
        card.Margin = new Padding(8, 8, 8, 2);
        var title = ThemeManager.MakeTitle("🛡 Korumam ne kadar açık?", 10.5f);
        title.Dock = DockStyle.Top;
        card.Controls.Add(_coverageRows);
        card.Controls.Add(title);
        RefreshCoverage();
        return card;
    }

    /// <summary>Reads the passive-protection toggles directly so a user can see — and one-tap enable —
    /// what is actually guarding the machine going forward (download watch ships OFF, sweep is opt-in).</summary>
    void RefreshCoverage()
    {
        _coverageRows.Controls.Clear();
        _coverageRows.Controls.Add(CoverageRow("İndirilenler izleniyor", Settings.WatchDownloads,
            enable: () => { Settings.WatchDownloads.Value = true; SettingsManager.SaveSettings(); WatchDownloadsToggled?.Invoke(); Refresh2(); }, settings: null));
        _coverageRows.Controls.Add(CoverageRow("USB otomatik tarama", Settings.WatchUsb,
            enable: () => { Settings.WatchUsb.Value = true; SettingsManager.SaveSettings(); Refresh2(); }, settings: null));
        _coverageRows.Controls.Add(CoverageRow("Zamanlı tarama", SweepScheduler.IsInstalled(), enable: null, settings: () => GoToTab?.Invoke(5)));
        _coverageRows.Controls.Add(CoverageRow("Sağ-tık menüsü", Settings.ContextMenuInstalled, enable: null, settings: () => GoToTab?.Invoke(5)));
    }

    Control CoverageRow(string label, bool on, Action? enable, Action? settings)
    {
        // Fixed icon + label widths so every row's action button starts at the same x (aligned column),
        // and a uniform row height so button/no-button rows have even vertical rhythm.
        var row = new FlowLayoutPanel { AutoSize = true, MinimumSize = new Size(0, 30), WrapContents = false, Margin = new Padding(0, 1, 0, 1) };
        row.Controls.Add(new Label { Text = on ? "✓" : "✗", AutoSize = false, Width = 22, Height = 28, ForeColor = on ? Theme.Current.Success : Theme.Current.Warning, Font = new Font("Segoe UI", 10f, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft, Margin = new Padding(2, 0, 4, 0) });
        row.Controls.Add(new Label { Text = label, AutoSize = false, Width = 200, Height = 28, ForeColor = on ? Theme.Current.Text : Theme.Current.Warning, TextAlign = ContentAlignment.MiddleLeft, Margin = new Padding(0, 0, 8, 0) });
        if (!on)
        {
            if (enable != null) row.Controls.Add(ThemeManager.MakeButton("Aç", (_, _) => enable()));
            else if (settings != null) row.Controls.Add(ThemeManager.MakeButton("Ayarlar →", (_, _) => settings()));
        }
        return row;
    }

    Control BuildTiles()
    {
        var row = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 3, RowCount = 1 };
        row.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        for (int i = 0; i < 3; i++) row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.33f));
        row.Controls.Add(Tile("Tehdit", _tehditNum, () => Theme.Current.Danger, () => GoToHistoryFiltered?.Invoke("threat")), 0, 0);
        row.Controls.Add(Tile("Şüpheli", _supheliNum, () => Theme.Current.Warning, () => GoToHistoryFiltered?.Invoke("suspicious")), 1, 0);
        row.Controls.Add(Tile("Temiz", _temizNum, () => Theme.Current.Success, () => GoToHistoryFiltered?.Invoke("clean")), 2, 0);
        return row;
    }

    static Panel Tile(string label, Label number, Func<Color> color, Action onClick)
    {
        var card = ThemeManager.MakeCard();
        card.Dock = DockStyle.Fill;
        card.AutoSize = true;
        card.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        number.Text = "0";
        number.Font = new Font("Segoe UI", 26f, FontStyle.Bold);
        number.AutoSize = false;
        number.Dock = DockStyle.Top;
        number.Height = number.Font.Height + 14; // DPI-safe: derived from the rendered font height, not a magic px
        number.TextAlign = ContentAlignment.MiddleCenter;
        number.ForeColor = color();
        var cap = new Label { Text = label + "  ›", Dock = DockStyle.Bottom, AutoSize = true, TextAlign = ContentAlignment.MiddleCenter, Tag = "subtle", Padding = new Padding(0, 0, 0, 6) };
        card.Controls.Add(number);
        card.Controls.Add(cap);
        card.Paint += (_, _) => number.ForeColor = color(); // keep tinted across theme changes
        // Click the number to land on those files in History.
        card.Cursor = number.Cursor = cap.Cursor = Cursors.Hand;
        void Click(object? s, EventArgs e) => onClick();
        card.Click += Click; number.Click += Click; cap.Click += Click;
        return card;
    }

    Control BuildRecent()
    {
        var panel = new Panel { Dock = DockStyle.Top, Height = 240 }; // bounded; the inner list scrolls for >8 rows
        var title = ThemeManager.MakeTitle("Son taramalar", 11f);
        title.Dock = DockStyle.Top;
        panel.Controls.Add(_recent);
        panel.Controls.Add(_quota);
        panel.Controls.Add(title);
        return panel;
    }

    void Refresh2()
    {
        var all = ScanHistoryStore.All();
        int tehdit = 0, supheli = 0, temiz = 0;
        foreach (var e in all)
        {
            if (e.Total <= 0) continue;
            if (VerdictCategories.IsThreat(e.Detections)) tehdit++;
            else if (e.Detections > 0) supheli++;
            else temiz++;
        }
        _tehditNum.Text = tehdit.ToString();
        _supheliNum.Text = supheli.ToString();
        _temizNum.Text = temiz.ToString();

        _recent.Controls.Clear();
        foreach (var e in all.Reverse().Take(8))
            _recent.Controls.Add(RecentRow(e));
        if (all.Count == 0)
            _recent.Controls.Add(ThemeManager.MakeLabel("Henüz tarama yok — yukarıdan bir dosya bırak.", subtle: true));

        // Recency: lifetime tiles can't tell "clean today" from "haven't scanned in months".
        DateTime? lastScan = all.Count > 0 ? all.Max(e => e.WhenUtc) : null;
        string recency;
        if (lastScan == null) { recency = "Son tarama: hiç"; _stale = true; }
        else
        {
            var ago = DateTime.UtcNow - lastScan.Value;
            string when = ago.TotalHours < 24 ? "bugün" : ago.TotalDays < 2 ? "dün" : $"{(int)ago.TotalDays} gün önce";
            recency = "Son tarama: " + when;
            _stale = ago.TotalDays > Math.Max(1, Settings.RecheckPeriodDays);
        }

        int usable = AppServices.Vault.UsableKeyCount, total = AppServices.Vault.Keys.Count;
        int watching = ReverdictWatchStore.Count;
        _quota.Text = recency + $"   •   Anahtar: {usable}/{total} kullanılabilir"
            + (Settings.KeylessGuiLookup ? "  •  anahtarsız (GUI) mod açık" : "")
            + (watching > 0 ? $"  •  👁 {watching} dosya izleniyor" : "");
        _quota.ForeColor = _stale ? Theme.Current.Warning : Theme.Current.Text;

        UpdateAttention(tehdit);
        UpdateStatusBanner();
        RefreshCoverage();
    }

    Control RecentRow(HistoryEntry e)
    {
        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 1, 0, 1), Cursor = Cursors.Hand };
        var dot = new Label { Text = "●", AutoSize = true, Font = new Font("Segoe UI", 11f), ForeColor = DotColor(e), Margin = new Padding(0, 3, 4, 0) };
        var name = new Label { Text = e.Name, AutoSize = true, Margin = new Padding(0, 4, 8, 0) };
        var verdict = new Label { Text = $"{e.Verdict} {e.Ratio}".Trim(), AutoSize = true, Tag = "subtle", Margin = new Padding(0, 4, 8, 0) };
        var when = new Label { Text = e.WhenLocal.ToString("MM-dd HH:mm"), AutoSize = true, Tag = "subtle", Margin = new Padding(0, 4, 0, 0) };
        row.Controls.Add(dot); row.Controls.Add(name); row.Controls.Add(verdict); row.Controls.Add(when);
        void Open(object? s, EventArgs a) => Reopen(e);
        row.Click += Open; dot.Click += Open; name.Click += Open; verdict.Click += Open; when.Click += Open;
        return row;
    }

    static Color DotColor(HistoryEntry e)
    {
        if (e.Total <= 0) return Theme.Current.Accent;
        if (VerdictCategories.IsThreat(e.Detections)) return Theme.Current.Danger;
        if (e.Detections > 0) return Theme.Current.Warning;
        return Theme.Current.Success;
    }

    void Reopen(HistoryEntry e)
    {
        var report = string.IsNullOrEmpty(e.Md5) ? null : AppServices.Cache.TryGet(e.Md5, int.MaxValue);
        if (report == null)
        {
            bool here = e.Path != null && File.Exists(e.Path);
            string head = $"{e.Name} — {e.Verdict} {e.Ratio}\n\nTam ayrıntı önbellekte yok";
            if (here && NativeMessageBox.Confirm(head + ".\nDosyayı yeniden taramak ister misin?")) ScanRequested?.Invoke([e.Path!]);
            else if (!here) NativeMessageBox.Info(head + " ve dosya artık şurada değil:\n" + (e.Path ?? "(yol yok)"));
            return;
        }
        var item = new ScanItem(e.Path ?? e.Name) { Report = report, Status = ScanStatus.Completed, Md5 = e.Md5, Sha256 = e.Sha256 };
        using var dlg = new DetailDialog(item);
        dlg.ShowDialog(FindForm());
    }

    void BuildStatusBanner()
    {
        _statusBtn.FlatAppearance.BorderSize = 0;
        _statusBtn.Click += (_, _) => _statusAction?.Invoke();
        _statusBanner.Controls.Add(_statusBtn);   // docked edge first
        _statusBanner.Controls.Add(_statusLabel); // fill last
    }

    void SetBanner(string title, string rationale, Color accent, string btnText, Action? action)
    {
        _statusBanner.BackColor = Blend(accent, Theme.Current.Panel, 0.22f);
        _statusLabel.ForeColor = Theme.Current.Text;
        _statusLabel.Text = title + "  —  " + rationale;
        _statusAction = action;
        if (action != null && btnText.Length > 0)
        {
            _statusBtn.Text = btnText;
            _statusBtn.BackColor = accent;
            _statusBtn.ForeColor = Color.White;
            _statusBtn.Visible = true;
        }
        else _statusBtn.Visible = false;
    }

    /// <summary>The one live security answer the lifetime tiles can't give: is a known-malicious file
    /// still sitting on this disk right now? Red if so; amber for pending housekeeping; green otherwise.</summary>
    void UpdateStatusBanner()
    {
        HistoryEntry? liveThreat = null;
        try
        {
            liveThreat = ScanHistoryStore.All().FirstOrDefault(e =>
                VerdictCategories.IsThreat(e.Detections) && !string.IsNullOrEmpty(e.Path) && File.Exists(e.Path!));
        }
        catch { }

        if (liveThreat != null)
        {
            SetBanner("🔴  Dikkat gerek", $"Bilinen zararlı bir dosya hâlâ diskte: {liveThreat.Name}", Theme.Current.Danger, "Geçmişi aç →", () => GoToTab?.Invoke(4));
            return;
        }
        if (AppServices.Vault.UsableKeyCount == 0 && !Settings.KeylessGuiLookup)
        {
            SetBanner("🟡  Beklemede", "Kullanılabilir anahtar yok ve anahtarsız mod kapalı — tarama yapılamıyor.", Theme.Current.Warning, "Ayarlar →", () => GoToTab?.Invoke(5));
            return;
        }
        int quar = SafeQuarantineCount(), pending = PendingOutbox.Count, watch = ReverdictWatchStore.Count;
        if (quar > 0 || pending > 0 || watch > 0)
        {
            var bits = new List<string>();
            if (quar > 0) bits.Add($"{quar} dosya karantinada");
            if (pending > 0) bits.Add($"{pending} dosya çevrimdışı sırada");
            if (watch > 0) bits.Add($"{watch} dosya izlemede");
            SetBanner("🟡  Beklemede", string.Join(" · ", bits), Theme.Current.Warning, "Yeniden denetle", () => RecheckRequested?.Invoke());
            return;
        }
        SetBanner("🟢  Korunuyorsun", "Diskte bilinen canlı tehdit yok.", Theme.Current.Success, "", null);
    }

    bool _stale; // newest scan older than the recheck period (or never scanned)
    string? _sweepNotice;
    /// <summary>Set by the host when a scheduled sweep found threats while the app was closed — shown in
    /// the attention strip until the user acts on it.</summary>
    public void SetSweepNotice(string? msg) { _sweepNotice = msg; if (IsHandleCreated) UpdateAttention(0); }

    void UpdateAttention(int tehditCount)
    {
        var msgs = new List<string>();
        if (!string.IsNullOrEmpty(_sweepNotice)) msgs.Add(_sweepNotice);
        if (_stale) msgs.Add("Bir süredir tarama yapılmadı — 'İndirilenleri tara' ya da 'Yeniden denetle' ile güncel tut.");
        if (AppServices.Vault.UsableKeyCount == 0 && !Settings.KeylessGuiLookup)
            msgs.Add("Kullanılabilir API anahtarı yok — Ayarlar'dan anahtar ekle ya da anahtarsız modu aç.");
        int quarantined = SafeQuarantineCount();
        if (quarantined > 0) msgs.Add($"{quarantined} dosya karantinada (geri yüklenebilir).");
        int pending = PendingOutbox.Count;
        if (pending > 0) msgs.Add($"📤 {pending} dosya çevrimdışı sırada (internet gelince denenecek).");

        if (msgs.Count == 0) { _attention.Visible = false; return; }
        _attention.BackColor = Blend(Theme.Current.Warning, Theme.Current.Panel, 0.30f);
        _attentionLabel.ForeColor = Theme.Current.Text;
        _attentionLabel.Text = "⚠  " + string.Join("   •   ", msgs);
        _attention.Visible = true;
    }

    static int SafeQuarantineCount() { try { return QuarantineVault.List().Count; } catch { return 0; } }

    void OnDrop(object? sender, DragEventArgs e)
    {
        if (e.Data?.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
            ScanRequested?.Invoke(paths);
    }

    void PickFiles()
    {
        using var dlg = new OpenFileDialog { Multiselect = true, Title = "Taranacak dosyalar" };
        if (dlg.ShowDialog(FindForm()) == DialogResult.OK && dlg.FileNames.Length > 0)
            ScanRequested?.Invoke(dlg.FileNames);
    }

    void PickFolder()
    {
        using var dlg = new FolderBrowserDialog { Description = "Taranacak klasör (alt klasörler dahil)" };
        if (dlg.ShowDialog(FindForm()) == DialogResult.OK && !string.IsNullOrEmpty(dlg.SelectedPath))
            ScanRequested?.Invoke([dlg.SelectedPath]);
    }

    public void ApplyTheme()
    {
        _drop.Invalidate();
        Refresh2();
    }

    static Color Blend(Color a, Color b, float t) => Color.FromArgb(
        (int)(a.R * t + b.R * (1 - t)), (int)(a.G * t + b.G * (1 - t)), (int)(a.B * t + b.B * (1 - t)));

    static GraphicsPath Rounded(Rectangle r, int radius)
    {
        var p = new GraphicsPath();
        int d = radius * 2;
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }
}
