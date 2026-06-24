using System.Drawing;
using System.Text;
using System.Text.RegularExpressions;

namespace VirusTotalScanner;

/// <summary>
/// The main "Tarama" tab: action bar + drop hint, the scan queue grid on the left, the
/// detail pane on the right, and an overall progress/summary bar at the bottom.
/// </summary>
internal sealed class ScanQueueControl : UserControl
{
    readonly ScanScheduler _scheduler = AppServices.Scheduler;
    readonly DataGridView _grid = new();
    readonly ScanDetailControl _detail = new();
    readonly ProgressBar _overall = new();
    readonly Label _summary = new();
    readonly Button _pauseBtn;
    readonly Button _cancelBtn;
    readonly System.Windows.Forms.Timer _repaintTimer = new() { Interval = 250 };
    readonly ToolTip _tips = new() { AutoPopDelay = 15000, InitialDelay = 400, ReshowDelay = 100 };
    int _progressCol;
    bool _exhaustPromptShown; // show the quota-exhausted choice dialog once per exhaustion episode

    // ---- live search + verdict-filter chips ----
    enum Bucket { All, Clean, Suspicious, Malicious, Skipped, Error }
    readonly TextBox _search = new() { Width = 200 };
    readonly Dictionary<Bucket, Button> _chips = [];
    readonly Label _filterCount = new() { AutoSize = true, Margin = new Padding(10, 8, 0, 0) };
    System.ComponentModel.BindingList<ScanItem>? _view;
    Bucket _bucket = Bucket.All;

    // ---- "have I scanned this before?" recall bar ----
    readonly Panel _recallBar = new() { Dock = DockStyle.Top, Height = 30, Visible = false, Padding = new Padding(10, 4, 4, 4) };
    readonly Label _recallLabel = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };

    // ---- quarantine undo bar ----
    readonly Panel _undoBar = new() { Dock = DockStyle.Top, Height = 32, Visible = false, Padding = new Padding(10, 4, 4, 4) };
    readonly Label _undoLabel = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
    readonly System.Windows.Forms.Timer _undoTimer = new() { Interval = 12000 };
    QuarantineEntry? _undoEntry;

    /// <summary>Raised when a scan is requested but no API key is configured.</summary>
    public event Action? NeedApiKey;
    /// <summary>Raised when a threat is found (for tray notifications).</summary>
    public event Action<ScanItem>? ThreatFound;

    public ScanQueueControl()
    {
        Dock = DockStyle.Fill;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // action bar
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // filter strip
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // split
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // overall

        // ---- action bar ----
        var bar = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true, Padding = new Padding(6) };
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnSelectFiles, (_, _) => SelectFiles(), accent: true));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnSelectFolder, (_, _) => SelectFolder(), accent: true));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnHashLookup, (_, _) => _ = HashLookupAsync()));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnVerifyHash, (_, _) => _ = VerifyHashAsync()));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnScanRunning, (_, _) => ScanRunning()));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnIntegrityCheck, (_, _) => _ = VerifyBaselineAsync()));
        _pauseBtn = ThemeManager.MakeButton(Strings.BtnPause, (_, _) => TogglePause());
        _cancelBtn = ThemeManager.MakeButton(Strings.BtnCancel, (_, _) => _scheduler.Cancel());
        bar.Controls.Add(_pauseBtn);
        bar.Controls.Add(_cancelBtn);
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnExportCsv, (_, _) => ExportCsv()));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnExportReport, (_, _) => ExportReport()));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnFolderRollup, (_, _) => ShowFolderRollup()));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnFamilyClusters, (_, _) => { using var d = new FamilyClusterDialog(FamilyClusterService.Build(AppServices.Cache)); d.ShowDialog(FindForm()); }));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnQuarantineVault, (_, _) => ShowQuarantineVault()));
        bar.Controls.Add(ThemeManager.MakeButton("🕓  Olay zaman çizelgesi", (_, _) => { using var d = new IncidentTimelineDialog(); d.ShowDialog(FindForm()); }));
        bar.Controls.Add(ThemeManager.MakeButton("📥  İndirilenler triyajı", (_, _) => { using var d = new DownloadsTriageDialog(); d.ScanRequested += paths => StartScan(paths, recurse: false); d.ShowDialog(FindForm()); }));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnRecheck, (_, _) => _ = RunRecheckAsync()));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnClearCache, (_, _) => ClearCache()));
        bar.Controls.Add(ThemeManager.MakeButton("❓  Yardım", (_, _) => { using var d = new HelpDialog(); d.ShowDialog(FindForm()); }));
        var hint = ThemeManager.MakeLabel(Strings.DropHint, subtle: true);
        bar.Controls.Add(hint);
        AttachBarTooltips(bar);

        // ---- split ----
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical };
        ConfigureGrid();
        split.Panel1.Controls.Add(_grid);
        split.Panel1.Controls.Add(BuildRecallBar());
        split.Panel1.Controls.Add(BuildUndoBar());
        split.Panel2.Controls.Add(_detail);
        // Set min sizes / splitter only once the container has a real width (avoids the
        // "SplitterDistance must be between Panel1MinSize and Width - Panel2MinSize" crash).
        bool splitInit = false;
        split.SizeChanged += (_, _) =>
        {
            if (splitInit) return;
            const int min1 = 220, min2 = 300;
            if (split.Width <= min1 + min2 + 20) return;
            split.Panel1MinSize = min1;
            split.Panel2MinSize = min2;
            split.SplitterDistance = Math.Clamp((int)(split.Width * 0.55), min1, split.Width - min2);
            splitInit = true;
        };

        // ---- overall ----
        var bottom = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, AutoSize = true, Padding = new Padding(8, 4, 8, 8) };
        _overall.Dock = DockStyle.Fill;
        _overall.Height = 16;
        _overall.Style = ProgressBarStyle.Continuous;
        _summary.AutoSize = true;
        _summary.Text = Strings.StatusReady;
        bottom.Controls.Add(_overall, 0, 0);
        bottom.Controls.Add(_summary, 0, 1);

        root.Controls.Add(bar, 0, 0);
        root.Controls.Add(BuildFilterBar(), 0, 1);
        root.Controls.Add(split, 0, 2);
        root.Controls.Add(bottom, 0, 3);
        Controls.Add(root);

        _grid.SelectionChanged += (_, _) => { var it = SelectedItem(); _detail.Show(it); UpdateRecallBar(it); };
        _detail.QuarantineRequested += QuarantineItem;
        _detail.RescanRequested += i => { if (File.Exists(i.FilePath)) StartScan([i.FilePath], recurse: false); };

        _scheduler.UiPost = a => { try { if (IsHandleCreated) BeginInvoke(a); else a(); } catch (Exception ex) { Log("UI dispatch failed: " + ex.Message, LogLevel.Warning); } };
        _scheduler.ProgressChanged += OnProgress;
        _scheduler.ItemFinished += OnItemFinished;
        _scheduler.Started += () => SafeUi(() => { _exhaustPromptShown = false; UpdateRunningState(true); });
        _scheduler.Finished += () => SafeUi(() => { UpdateRunningState(false); _repaintTimer.Stop(); _grid.Invalidate(); ApplyFilter(); });
        AppServices.Rotator.OnAllExhausted += t => SafeUi(() => OnAllKeysExhausted(t));
        AppServices.Rotator.OnResumed += () => SafeUi(() => _exhaustPromptShown = false);

        _repaintTimer.Tick += (_, _) => { if (_scheduler.IsRunning) { _grid.Invalidate(); UpdateChipCounts(); } };

        UpdateRunningState(false);
    }

    // ---- live search + verdict-filter chips ----

    FlowLayoutPanel BuildFilterBar()
    {
        var strip = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true, Padding = new Padding(8, 2, 6, 4) };

        _search.PlaceholderText = "🔎  Ara (ad/yol)…";
        _search.Margin = new Padding(0, 4, 8, 4);
        _search.TextChanged += (_, _) => ApplyFilter();
        _search.KeyDown += (_, e) => { if (e.KeyCode == Keys.Escape) { _search.Clear(); e.Handled = true; } };
        strip.Controls.Add(_search);

        AddChip(strip, Bucket.All, "Tümü", null);
        AddChip(strip, Bucket.Clean, "Temiz", Theme.Current.Success);
        AddChip(strip, Bucket.Suspicious, "Şüpheli", Theme.Current.Warning);
        AddChip(strip, Bucket.Malicious, "Zararlı", Theme.Current.Danger);
        AddChip(strip, Bucket.Skipped, "Atlandı", null);
        AddChip(strip, Bucket.Error, "Hata", null);

        _filterCount.Tag = "subtle";
        strip.Controls.Add(_filterCount);
        SetBucket(Bucket.All);
        return strip;
    }

    void AddChip(FlowLayoutPanel strip, Bucket b, string label, Color? color)
    {
        var chip = new Button
        {
            Text = label,
            AutoSize = true,
            FlatStyle = FlatStyle.Flat,
            Margin = new Padding(0, 4, 6, 4),
            Padding = new Padding(8, 2, 8, 2),
            Tag = color,
            Cursor = Cursors.Hand,
        };
        chip.FlatAppearance.BorderSize = 1;
        chip.Click += (_, _) => SetBucket(b);
        _chips[b] = chip;
        strip.Controls.Add(chip);
    }

    void SetBucket(Bucket b)
    {
        _bucket = b;
        foreach (var (key, chip) in _chips)
        {
            bool active = key == b;
            var color = chip.Tag as Color? ?? Theme.Current.Accent;
            chip.FlatAppearance.BorderColor = color;
            chip.BackColor = active ? color : Theme.Current.Panel;
            chip.ForeColor = active ? Color.White : Theme.Current.Text;
            chip.Font = new Font(chip.Font, active ? FontStyle.Bold : FontStyle.Regular);
        }
        ApplyFilter();
    }

    static Bucket BucketOf(ScanItem i)
    {
        if (i.Status == ScanStatus.Failed) return Bucket.Error;
        if (i.Status is ScanStatus.TrustedSkipped or ScanStatus.Skipped or ScanStatus.Cancelled) return Bucket.Skipped;
        var r = i.Report;
        if (r == null) return Bucket.All; // in-progress / no verdict yet → only under "Tümü"
        if (r.IsMalicious) return Bucket.Malicious;
        if (r.DetectionCount > 0) return Bucket.Suspicious;
        return Bucket.Clean;
    }

    bool FilterActive => _bucket != Bucket.All || _search.Text.Trim().Length > 0;

    bool Passes(ScanItem i)
    {
        if (_bucket != Bucket.All && BucketOf(i) != _bucket) return false;
        string q = _search.Text.Trim();
        if (q.Length > 0 &&
            (i.FileName?.IndexOf(q, StringComparison.OrdinalIgnoreCase) ?? -1) < 0 &&
            (i.FilePath?.IndexOf(q, StringComparison.OrdinalIgnoreCase) ?? -1) < 0)
            return false;
        return true;
    }

    void ApplyFilter()
    {
        var keep = SelectedItem();
        if (!FilterActive)
        {
            if (!ReferenceEquals(_grid.DataSource, _scheduler.Items)) _grid.DataSource = _scheduler.Items;
        }
        else
        {
            _view ??= [];
            _view.RaiseListChangedEvents = false;
            _view.Clear();
            foreach (var it in _scheduler.Items) if (Passes(it)) _view.Add(it);
            _view.RaiseListChangedEvents = true;
            _view.ResetBindings();
            if (!ReferenceEquals(_grid.DataSource, _view)) _grid.DataSource = _view;
        }
        Reselect(keep);
        UpdateChipCounts();
    }

    void Reselect(ScanItem? item)
    {
        if (item == null) return;
        _grid.ClearSelection();
        foreach (DataGridViewRow row in _grid.Rows)
            if (ReferenceEquals(row.DataBoundItem, item)) { row.Selected = true; return; }
    }

    void UpdateChipCounts()
    {
        int all = 0, clean = 0, susp = 0, mal = 0, skip = 0, err = 0;
        foreach (var i in _scheduler.Items)
        {
            all++;
            switch (BucketOf(i))
            {
                case Bucket.Clean: clean++; break;
                case Bucket.Suspicious: susp++; break;
                case Bucket.Malicious: mal++; break;
                case Bucket.Skipped: skip++; break;
                case Bucket.Error: err++; break;
            }
        }
        SetChip(Bucket.All, "Tümü", all);
        SetChip(Bucket.Clean, "Temiz", clean);
        SetChip(Bucket.Suspicious, "Şüpheli", susp);
        SetChip(Bucket.Malicious, "Zararlı", mal);
        SetChip(Bucket.Skipped, "Atlandı", skip);
        SetChip(Bucket.Error, "Hata", err);
        _filterCount.Text = FilterActive ? $"gösterilen {_grid.Rows.Count} / toplam {all}" : "";
    }

    void SetChip(Bucket b, string label, int count) { if (_chips.TryGetValue(b, out var c)) c.Text = $"{label} ({count})"; }

    /// <summary>An item just got a verdict: keep counts live and slot it into the active filtered view
    /// without a full rebuild (so scroll position / selection survive during a running scan).</summary>
    void OnFilterItemFinished(ScanItem item)
    {
        UpdateChipCounts();
        if (FilterActive && _view != null && ReferenceEquals(_grid.DataSource, _view) && Passes(item) && !_view.Contains(item))
            _view.Add(item);
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        if (keyData == (Keys.Control | Keys.F)) { _search.Focus(); _search.SelectAll(); return true; }
        if (_search.Focused) return base.ProcessCmdKey(ref msg, keyData); // typing — don't hijack keys

        switch (keyData)
        {
            case Keys.Control | Keys.C:
                CopySafe(string.Join("\n", SelectedItems().Select(i => i.Sha256).Where(s => !string.IsNullOrEmpty(s))));
                return true;
            case Keys.Control | Keys.R: RescanSelected(); return true;
            case Keys.Control | Keys.Q: QuarantineSelected(); return true;
            case Keys.F5: _ = RunRecheckAsync(); return true;
        }

        // Enter/Space only when the grid itself has focus (so buttons keep their normal behavior).
        if (_grid.Focused)
        {
            if (keyData == Keys.Enter) { var i = SelectedItem(); if (i?.Report != null) OpenUrlInBrowser(i.Report.ReportUrl); return true; }
            if (keyData == Keys.Space && _scheduler.IsRunning) { TogglePause(); return true; }
        }
        return base.ProcessCmdKey(ref msg, keyData);
    }

    /// <summary>Plain-Turkish hover help on every action-bar button — teaches the deep features
    /// where the user meets them, matched by the button's text so no per-button wiring is needed.</summary>
    void AttachBarTooltips(Control bar)
    {
        var tips = new Dictionary<string, string>
        {
            [Strings.BtnSelectFiles] = "Taranacak dosya(lar) seç.",
            [Strings.BtnSelectFolder] = "Bir klasörü, alt klasörleriyle birlikte tara.",
            [Strings.BtnHashLookup] = "Elindeki bir MD5/SHA hash'ini VirusTotal'de ara (dosya gerekmez).",
            [Strings.BtnVerifyHash] = "Bir dosyanın beklenen hash ile birebir aynı olduğunu doğrula.",
            [Strings.BtnScanRunning] = "Şu an çalışan tüm süreçlerin imajlarını tara — 'şu an virüslü müyüm?'.",
            [Strings.BtnIntegrityCheck] = "İzlemeye aldığın dosyaların değişip değişmediğini (drift) denetle.",
            [Strings.BtnExportCsv] = "Sonuçları CSV tablosu olarak kaydet.",
            [Strings.BtnExportReport] = "Sonuçları HTML/CSV/JSON/metin rapora yaz.",
            [Strings.BtnFolderRollup] = "Taranan klasörleri tehdit/temiz sayılarıyla özetle.",
            [Strings.BtnFamilyClusters] = "Aynı zararlı ailesini paylaşan farklı dosyaları grupla.",
            [Strings.BtnQuarantineVault] = "Karantinaya alınanları gör; güvenliyse geri yükle.",
            [Strings.BtnRecheck] = "Eski önbellek kayıtlarını kotasız (GUI) yeniden sorgula.",
            [Strings.BtnClearCache] = "Yerel hash önbelleğini temizle (verdiktler tekrar VT'den alınır).",
            ["🕓  Olay zaman çizelgesi"] = "Diske gelen çalıştırılabilirleri varış gününe göre kümele.",
            [Strings.BtnPause] = "Devam eden taramayı duraklat / sürdür.",
            [Strings.BtnCancel] = "Devam eden taramayı iptal et.",
        };
        foreach (Control c in bar.Controls)
            if (c is Button b && tips.TryGetValue(b.Text, out var tip)) _tips.SetToolTip(b, tip);
    }

    // ---- "have I scanned this before?" recall bar ----

    Panel BuildRecallBar()
    {
        var close = new Button { Text = "✕", Dock = DockStyle.Right, Width = 30, FlatStyle = FlatStyle.Flat, TabStop = false, Cursor = Cursors.Hand };
        close.FlatAppearance.BorderSize = 0;
        close.Click += (_, _) => _recallBar.Visible = false;
        _recallBar.Controls.Add(_recallLabel);
        _recallBar.Controls.Add(close);
        close.BringToFront();
        return _recallBar;
    }

    Panel BuildUndoBar()
    {
        var undo = ThemeManager.MakeButton("↩  Geri al", (_, _) => DoUndoQuarantine());
        undo.Dock = DockStyle.Right;
        var close = new Button { Text = "✕", Dock = DockStyle.Right, Width = 30, FlatStyle = FlatStyle.Flat, TabStop = false, Cursor = Cursors.Hand };
        close.FlatAppearance.BorderSize = 0;
        close.Click += (_, _) => HideUndo();
        _undoBar.Controls.Add(_undoLabel);
        _undoBar.Controls.Add(undo);
        _undoBar.Controls.Add(close);
        close.BringToFront();
        undo.BringToFront();
        _undoTimer.Tick += (_, _) => HideUndo();
        return _undoBar;
    }

    void ShowQuarantineUndo(string fileName, QuarantineEntry entry)
    {
        _undoEntry = entry;
        _undoBar.BackColor = RecallBlend(Theme.Current.Success, Theme.Current.Panel, 0.22f);
        _undoLabel.ForeColor = Theme.Current.Text;
        _undoLabel.Text = $"✓  '{fileName}' karantinaya alındı (.VIRUS).";
        _undoBar.Visible = true;
        _undoTimer.Stop();
        _undoTimer.Start();
    }

    void HideUndo() { _undoTimer.Stop(); _undoBar.Visible = false; _undoEntry = null; }

    void DoUndoQuarantine()
    {
        var entry = _undoEntry;
        HideUndo();
        if (entry == null) return;
        if (QuarantineVault.Restore(entry, out var err))
            _summary.Text = $"↩ '{Path.GetFileName(entry.OriginalPath)}' geri yüklendi.";
        else
            NativeMessageBox.Error(string.Format(Strings.VaultRestoreFailedFormat, err));
    }

    void UpdateRecallBar(ScanItem? item)
    {
        string? md5 = item?.Md5;
        if (item == null || string.IsNullOrEmpty(md5)) { _recallBar.Visible = false; return; }
        var history = ScanHistoryStore.All();
        _recallLabel.ForeColor = Theme.Current.Text;

        // Highest-priority signal: the content at this PATH changed since the last time it was scanned —
        // the "clean file swapped/trojanized in place" case. Compare only against the immediately-prior
        // scan at this path (not any older differing one), so a revert to earlier content isn't a false
        // alarm, and exclude this scan's own just-recorded row.
        if (!string.IsNullOrEmpty(item.FilePath))
        {
            var atPath = history.Where(e =>
                string.Equals(e.Path, item.FilePath, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(e.Md5)).ToList();
            if (atPath.Count > 0 && string.Equals(atPath[^1].Md5, md5, StringComparison.OrdinalIgnoreCase))
                atPath.RemoveAt(atPath.Count - 1); // drop this scan's own record
            var priorAtPath = atPath.LastOrDefault();
            if (priorAtPath != null && !string.Equals(priorAtPath.Md5, md5, StringComparison.OrdinalIgnoreCase))
            {
                _recallBar.BackColor = RecallBlend(Theme.Current.Warning, Theme.Current.Panel, 0.30f);
                _recallLabel.Text = $"⚠ Bu yolda en son FARKLI bir dosya taramıştın ({priorAtPath.WhenLocal:yyyy-MM-dd} — {priorAtPath.Verdict} {priorAtPath.Ratio}); içerik o zamandan beri DEĞİŞTİ.".TrimEnd();
                _recallBar.Visible = true;
                return;
            }
        }

        // Otherwise: the exact same file (by hash) was scanned before.
        var prior = history.Where(e => string.Equals(e.Md5, md5, StringComparison.OrdinalIgnoreCase)).ToList();
        if (prior.Count < 2) { _recallBar.Visible = false; return; } // 1 = only the current scan's own record
        var last = prior[^2];
        _recallBar.BackColor = RecallBlend(Theme.Current.Accent, Theme.Current.Panel, 0.22f);
        _recallLabel.Text = $"🕘 Bu dosyayı daha önce {prior.Count - 1} kez taradın. Önceki: {last.WhenLocal:yyyy-MM-dd HH:mm} — {last.Verdict} {last.Ratio}".TrimEnd();
        _recallBar.Visible = true;
    }

    static Color RecallBlend(Color a, Color b, float t) => Color.FromArgb(
        (int)(a.R * t + b.R * (1 - t)), (int)(a.G * t + b.G * (1 - t)), (int)(a.B * t + b.B * (1 - t)));

    void ConfigureGrid()
    {
        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.MultiSelect = true;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColFile, DataPropertyName = nameof(ScanItem.FileName), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill, MinimumWidth = 160 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColSize, DataPropertyName = nameof(ScanItem.SizeText), Width = 80 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColStatus, DataPropertyName = nameof(ScanItem.StatusText), Width = 220 });
        var prog = new DataGridViewTextBoxColumn { HeaderText = Strings.ColProgress, Width = 110 };
        _progressCol = _grid.Columns.Add(prog);
        ThemeManager.StyleGrid(_grid);
        _grid.DataSource = _scheduler.Items;
        _grid.CellPainting += Grid_CellPainting;
        _grid.CellFormatting += Grid_CellFormatting;

        var menu = new ContextMenuStrip();
        var miOpenVt = (ToolStripMenuItem)menu.Items.Add(Strings.MenuOpenVt, null, (_, _) => { var i = SelectedItem(); if (i?.Report != null) OpenUrlInBrowser(i.Report.ReportUrl); });

        var copyMenu = new ToolStripMenuItem(Strings.MenuCopy);
        copyMenu.DropDownItems.Add("SHA-256", null, (_, _) => CopySafe(string.Join("\n", SelectedItems().Select(i => i.Sha256).Where(s => !string.IsNullOrEmpty(s)))));
        copyMenu.DropDownItems.Add("MD5", null, (_, _) => CopySafe(SelectedItem()?.Md5));
        copyMenu.DropDownItems.Add(Strings.MenuCopyFilePath, null, (_, _) => CopySafe(SelectedItem()?.FilePath));
        copyMenu.DropDownItems.Add(Strings.MenuCopyFileName, null, (_, _) => CopySafe(SelectedItem()?.FileName));
        copyMenu.DropDownItems.Add(Strings.MenuCopyVerdictLine, null, (_, _) => { var i = SelectedItem(); if (i != null) CopySafe(VerdictLine(i)); });
        menu.Items.Add(copyMenu);

        var shareMenu = new ToolStripMenuItem("📤  Paylaş");
        shareMenu.DropDownItems.Add("🖼  Kart resmi (panoya)", null, (_, _) =>
        {
            var i = SelectedItem();
            if (i == null) return;
            try { using var bmp = ShareCard.Render(i); Clipboard.SetImage(bmp); _summary.Text = "📋 Kart resmi panoya kopyalandı."; }
            catch (Exception ex) { NativeMessageBox.Error("Kopyalanamadı: " + ex.Message); }
        });
        shareMenu.DropDownItems.Add("📝  Özet metin (panoya)", null, (_, _) => { var i = SelectedItem(); if (i != null) CopySafe(ShareCard.Text(i)); });
        shareMenu.DropDownItems.Add("💾  Kart resmi kaydet…", null, (_, _) => SaveShareCard());
        menu.Items.Add(shareMenu);

        var miReveal = (ToolStripMenuItem)menu.Items.Add(Strings.MenuRevealFile, null, (_, _) => { var i = SelectedItem(); if (i != null && File.Exists(i.FilePath)) RevealInExplorer(i.FilePath); });
        var miNeighbors = (ToolStripMenuItem)menu.Items.Add(Strings.MenuNeighbors, null, (_, _) => ShowNeighbors());
        var miFindCopies = (ToolStripMenuItem)menu.Items.Add(Strings.MenuFindCopies, null, (_, _) => _ = FindCopiesAsync());
        var miPin = (ToolStripMenuItem)menu.Items.Add(Strings.MenuPinBaseline, null, (_, _) => _ = PinBaselineAsync());
        var miPersist = (ToolStripMenuItem)menu.Items.Add(Strings.MenuHuntPersistence, null, (_, _) => HuntPersistence());
        var miWatch = (ToolStripMenuItem)menu.Items.Add("👁  İzlemeye al (re-verdict)", null, (_, _) =>
        {
            var i = SelectedItem();
            if (i?.Sha256 == null) return;
            if (ReverdictWatchStore.Contains(i.Sha256)) ReverdictWatchStore.Remove(i.Sha256);
            else ReverdictWatchStore.Add(i);
        });
        menu.Items.Add(new ToolStripSeparator());
        var miRescan = (ToolStripMenuItem)menu.Items.Add(Strings.MenuRescan, null, (_, _) => RescanSelected());
        var miRescanNoTrust = (ToolStripMenuItem)menu.Items.Add(Strings.MenuRescanNoTrust, null, (_, _) => RescanIgnoringTrust());
        menu.Items.Add(new ToolStripSeparator());
        var miQuarantine = (ToolStripMenuItem)menu.Items.Add(Strings.MenuQuarantine, null, (_, _) => QuarantineSelected());

        // Context-aware: disable actions that don't apply to the selected row's current state.
        menu.Opening += (_, e) =>
        {
            var i = SelectedItem();
            if (i == null) { e.Cancel = true; return; }
            bool exists = File.Exists(i.FilePath);
            miOpenVt.Enabled = i.Report != null;
            copyMenu.Enabled = true;
            miReveal.Enabled = exists;
            miNeighbors.Enabled = exists;
            miFindCopies.Enabled = i.Report != null && !string.IsNullOrEmpty(i.Sha256);
            miPin.Enabled = exists;
            miPersist.Enabled = i != null;
            miWatch.Enabled = !string.IsNullOrEmpty(i?.Sha256);
            miWatch.Text = i?.Sha256 != null && ReverdictWatchStore.Contains(i.Sha256) ? "👁  İzlemeden çıkar" : "👁  İzlemeye al (re-verdict)";
            miRescan.Enabled = exists;
            miRescanNoTrust.Enabled = exists;
            miQuarantine.Enabled = exists;

            // Count-aware labels when several rows are selected (batch actions).
            int n = SelectedItems().Count;
            miRescan.Text = n > 1 ? $"🔄  {n} dosyayı yeniden tara" : Strings.MenuRescan;
            miQuarantine.Text = n > 1 ? $"⚠  {n} dosyayı karantinaya al (.VIRUS)" : Strings.MenuQuarantine;
        };
        miOpenVt.ShortcutKeyDisplayString = "Enter";
        miRescan.ShortcutKeyDisplayString = "Ctrl+R";
        miQuarantine.ShortcutKeyDisplayString = "Ctrl+Q";
        _grid.ContextMenuStrip = menu;

        // Double-click a row -> jump to the file in Explorer.
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) { var i = SelectedItem(); if (i != null && File.Exists(i.FilePath)) RevealInExplorer(i.FilePath); } };
    }

    static string VerdictLine(ScanItem i) =>
        i.Report is { } r ? $"{r.Verdict} ({r.DetectionCount}/{r.TotalEngines})  {i.FileName}" : $"{i.StatusText}  {i.FileName}";

    // Tint each row by its verdict so the list scans at a glance (red threat, yellow suspicious, …).
    void Grid_CellFormatting(object? sender, DataGridViewCellFormattingEventArgs e)
    {
        if (e.RowIndex < 0 || e.ColumnIndex == _progressCol) return;
        if (_grid.Rows[e.RowIndex].DataBoundItem is not ScanItem item) return;
        var p = Theme.Current;
        Color? c = item.Status switch
        {
            ScanStatus.TrustedSkipped => p.Accent,
            ScanStatus.Failed => p.Danger,
            ScanStatus.Skipped => p.SubtleText,
            ScanStatus.Completed when item.Report is { TotalEngines: > 0 } r =>
                r.IsMalicious ? p.Danger : r.DetectionCount > 0 ? p.Warning : p.Success,
            _ => null,
        };
        if (c.HasValue) e.CellStyle!.ForeColor = c.Value;
    }

    void Grid_CellPainting(object? sender, DataGridViewCellPaintingEventArgs e)
    {
        if (e.RowIndex < 0 || e.ColumnIndex != _progressCol) return;
        e.PaintBackground(e.CellBounds, true);
        if (_grid.Rows[e.RowIndex].DataBoundItem is ScanItem item)
        {
            var p = Theme.Current;
            int pct = item.Status is ScanStatus.Completed or ScanStatus.Skipped or ScanStatus.TrustedSkipped ? 100 : Math.Clamp(item.Progress, 0, 100);
            var rect = Rectangle.Inflate(e.CellBounds, -6, -7);
            using (var bg = new SolidBrush(p.Border)) e.Graphics!.FillRectangle(bg, rect);
            Color c = item.Status switch
            {
                ScanStatus.Failed or ScanStatus.Cancelled => p.Danger,
                ScanStatus.Completed => Theme.VerdictColor(item.Verdict),
                ScanStatus.TrustedSkipped => p.Accent,
                _ => p.Accent,
            };
            int w = (int)(rect.Width * pct / 100.0);
            if (w > 0) using (var fb = new SolidBrush(c)) e.Graphics!.FillRectangle(fb, rect.X, rect.Y, w, rect.Height);
            TextRenderer.DrawText(e.Graphics, pct + "%", new Font("Segoe UI", 8f), rect, p.Text,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
        e.Handled = true;
    }

    // ---- actions ----

    void SelectFiles()
    {
        using var dlg = new OpenFileDialog { Multiselect = true, Title = "Taranacak dosyalar" };
        if (dlg.ShowDialog() == DialogResult.OK) StartScan(dlg.FileNames, recurse: false);
    }

    void SelectFolder()
    {
        using var dlg = new FolderBrowserDialog { Description = Strings.FolderPickDescription };
        if (dlg.ShowDialog() == DialogResult.OK && !string.IsNullOrEmpty(dlg.SelectedPath))
            StartScan([dlg.SelectedPath], recurse: true);
    }

    public void StartScan(IEnumerable<string> paths, bool recurse, bool bypassTrust = false)
    {
        bool keyless = Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable;
        if (!_scheduler.IsRunning && !AppServices.Rotator.HasUsableKeys && !Settings.TrustSkipSigned && !keyless)
        {
            NeedApiKey?.Invoke();
            NativeMessageBox.Warn(Strings.NeedApiKeyWarn);
            return;
        }
        var opts = ScanOptions.FromSettings(recurse);
        opts.BypassTrust = bypassTrust;

        // Archive found? Ask once whether to scan the archive itself or expand and scan its members.
        var pathList = paths.ToList();
        if (!_scheduler.IsRunning && HasArchives(pathList))
            opts.ExpandArchives = NativeMessageBox.Confirm(Strings.ArchivePrompt, Strings.ArchiveFoundTitle);

        _ = Task.Run(async () =>
        {
            try { await _scheduler.RunAsync(pathList, opts); }
            catch (Exception ex) { Log("Scan start failed: " + ex, LogLevel.Error); }
        });
    }

    /// <summary>Quick bounded check for any archive among the selection (files + shallow folder walk).</summary>
    static bool HasArchives(IEnumerable<string> paths)
    {
        foreach (var p in paths)
        {
            try
            {
                if (File.Exists(p) && ArchiveExpander.IsArchive(p)) return true;
                if (Directory.Exists(p) &&
                    Directory.EnumerateFiles(p, "*", SearchOption.AllDirectories).Take(5000).Any(ArchiveExpander.IsArchive))
                    return true;
            }
            catch (Exception ex) { Log("Archive pre-check failed for " + p + ": " + ex.Message, LogLevel.Warning); }
        }
        return false;
    }

    async Task HashLookupAsync()
    {
        // Default is a precomputed example (notepad.exe's SHA-256) so there's something to test with.
        const string exampleHash = "ab15a95de88ab0624307ae0e28e333756a2a522f650a0be78749901f7dc32ecf";
        string? input = Dialogs.InputBox(Strings.HashLookupPrompt, Strings.HashLookupTitle, exampleHash);
        if (string.IsNullOrWhiteSpace(input)) return;
        input = input.Trim().ToLowerInvariant();
        if (!Regex.IsMatch(input, "^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$"))
        {
            NativeMessageBox.Warn(Strings.HashInvalidWarn);
            return;
        }
        if (!AppServices.Rotator.HasUsableKeys) { NeedApiKey?.Invoke(); return; }

        try
        {
            string key = await AppServices.Rotator.AcquireAsync();
            var report = await AppServices.Api.GetFileReportAsync(input, key);
            if (report == null) { NativeMessageBox.Info(Strings.HashNotFound); return; }
            var item = new ScanItem(input) { Report = report, Status = ScanStatus.Completed };
            item.Md5 = report.Md5; item.Sha256 = report.Sha256;
            _scheduler.Items.Add(item);
            _grid.ClearSelection();
            if (_grid.Rows.Count > 0) _grid.Rows[^1].Selected = true;
        }
        catch (Exception ex) { NativeMessageBox.Error(Strings.LookupFailedPrefix + ex.Message); }
    }

    void TogglePause()
    {
        if (_scheduler.IsPaused) { _scheduler.Resume(); _pauseBtn.Text = Strings.BtnPause; }
        else { _scheduler.Pause(); _pauseBtn.Text = Strings.BtnResume; }
    }

    void RescanSelected()
    {
        var paths = SelectedItems().Where(i => File.Exists(i.FilePath)).Select(i => i.FilePath).Distinct().ToArray();
        if (paths.Length > 0) StartScan(paths, recurse: false);
    }

    void RescanIgnoringTrust()
    {
        var paths = SelectedItems().Where(i => File.Exists(i.FilePath)).Select(i => i.FilePath).Distinct().ToArray();
        if (paths.Length > 0) StartScan(paths, recurse: false, bypassTrust: true);
    }

    /// <summary>Quarantine one specific item (from the detail-pane action strip), with the undo bar.</summary>
    void QuarantineItem(ScanItem i)
    {
        if (!File.Exists(i.FilePath)) return;
        if (!ConfirmGates.Quarantine.Ask(this, string.Format(Strings.QuarantineConfirmFormat, i.FileName))) return;
        if (QuarantineVault.Quarantine(i.FilePath, i.Report, i.Sha256, i.Md5, out var err))
        {
            var entry = QuarantineVault.List().LastOrDefault(e => string.Equals(e.OriginalPath, i.FilePath, StringComparison.OrdinalIgnoreCase));
            if (entry != null) ShowQuarantineUndo(i.FileName, entry); else NativeMessageBox.Info(Strings.QuarantineDoneInfo);
        }
        else NativeMessageBox.Error(Strings.QuarantineFailedPrefix + err);
    }

    void QuarantineSelected()
    {
        var items = SelectedItems().Where(i => File.Exists(i.FilePath)).ToList();
        if (items.Count == 0) return;
        string prompt = items.Count == 1
            ? string.Format(Strings.QuarantineConfirmFormat, items[0].FileName)
            : $"{items.Count} dosya karantinaya alınsın mı? (uzantıları .VIRUS yapılır, çalıştırılamaz; sonradan geri yüklenebilir)";
        if (!ConfirmGates.Quarantine.Ask(this, prompt)) return;

        int ok = 0;
        var errors = new List<string>();
        foreach (var i in items)
            if (QuarantineVault.Quarantine(i.FilePath, i.Report, i.Sha256, i.Md5, out var err)) ok++;
            else errors.Add(Path.GetFileName(i.FilePath) + ": " + err);

        if (items.Count == 1 && ok == 1)
        {
            // Non-blocking undo banner instead of a dead-end modal, live for ~12s.
            var entry = QuarantineVault.List().LastOrDefault(e => string.Equals(e.OriginalPath, items[0].FilePath, StringComparison.OrdinalIgnoreCase));
            if (entry != null) ShowQuarantineUndo(items[0].FileName, entry);
            else NativeMessageBox.Info(Strings.QuarantineDoneInfo);
        }
        else
            NativeMessageBox.Info($"{ok}/{items.Count} dosya karantinaya alındı." +
                (errors.Count > 0 ? Strings.ErrorsHeader + string.Join("\n", errors.Take(10)) : ""));
    }

    /// <summary>Moves one file into the reversible quarantine vault (used by the batch copy-finder).</summary>
    static bool QuarantinePath(string path, out string? error) =>
        QuarantineVault.Quarantine(path, null, null, null, out error);

    void ShowQuarantineVault()
    {
        using var dlg = new QuarantineVaultDialog();
        dlg.ShowDialog(FindForm());
    }

    async Task FindCopiesAsync()
    {
        var i = SelectedItem();
        if (i?.Report == null || string.IsNullOrEmpty(i.Sha256)) { NativeMessageBox.Info(Strings.NeedVtResultInfo); return; }
        long size = i.Report.Size > 0 ? i.Report.Size : (File.Exists(i.FilePath) ? new FileInfo(i.FilePath).Length : 0);
        if (size <= 0) { NativeMessageBox.Warn(Strings.FileSizeUnknown); return; }
        if (!NativeMessageBox.Confirm(string.Format(Strings.FindCopiesConfirmFormat, i.FileName))) return;

        using var cts = new CancellationTokenSource();
        string old = _summary.Text;
        List<string> matches;
        try
        {
            matches = await CopyFinderService.FindCopiesAsync(i.FilePath, i.Sha256!, size,
                (d, t) => { try { BeginInvoke(() => _summary.Text = string.Format(Strings.FindingCopiesFormat, d, t)); } catch { } }, cts.Token);
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex) { NativeMessageBox.Error(Strings.FindCopiesErrorPrefix + ex.Message); return; }
        finally { try { _summary.Text = old; } catch { } }

        if (matches.Count == 0) { NativeMessageBox.Info(Strings.NoCopiesFound); return; }

        var sb = new StringBuilder();
        sb.AppendLine(string.Format(Strings.CopiesFoundFormat, matches.Count));
        foreach (var m in matches.Take(30)) sb.AppendLine(m);
        if (matches.Count > 30) sb.AppendLine(string.Format(Strings.MorePlusFormat, matches.Count - 30));
        sb.AppendLine(Strings.QuarantineAllConfirm);
        if (!ConfirmGates.Quarantine.Ask(this, sb.ToString())) return;

        int ok = 0; var errors = new List<string>();
        foreach (var m in matches)
            if (QuarantinePath(m, out var err)) ok++; else errors.Add(Path.GetFileName(m) + ": " + err);
        NativeMessageBox.Info(string.Format(Strings.CopiesQuarantinedFormat, ok, matches.Count) + (errors.Count > 0 ? Strings.ErrorsHeader + string.Join("\n", errors.Take(10)) : ""));
    }

    void ExportCsv()
    {
        var items = _scheduler.Items.Where(i => i.Report != null).ToList();
        if (items.Count == 0) { NativeMessageBox.Info(Strings.NoResultsToExport); return; }
        using var dlg = new SaveFileDialog { Filter = "CSV|*.csv", FileName = "virustotal-sonuclar.csv" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        var sb = new StringBuilder();
        sb.AppendLine("Dosya;Verdict;Zararli;Supheli;Toplam;MD5;SHA256;Rapor");
        foreach (var i in items)
        {
            var r = i.Report!;
            sb.AppendLine($"\"{i.FileName}\";{r.Verdict};{r.Malicious};{r.Suspicious};{r.TotalEngines};{r.Md5};{r.Sha256};{r.ReportUrl}");
        }
        try { File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8); NativeMessageBox.Info(Strings.SavedPrefix + dlg.FileName); }
        catch (Exception ex) { NativeMessageBox.Error(Strings.SaveErrorPrefix + ex.Message); }
    }

    void ShowFolderRollup()
    {
        if (_scheduler.Items.Count == 0) { NativeMessageBox.Info(Strings.RunScanFirstInfo); return; }
        using var dlg = new FolderRollupDialog(_scheduler.Items.ToList());
        dlg.ShowDialog(FindForm());
    }

    async Task RunRecheckAsync()
    {
        var due = RecheckService.DueForRecheck(AppServices.Cache, Settings.RecheckPeriodDays);
        int days = Settings.RecheckPeriodDays.Value;
        if (due.Count == 0) { NativeMessageBox.Info(string.Format(Strings.RecheckNoneDueFormat, days)); return; }
        // One question for the whole batch — not a per-file nag.
        if (!NativeMessageBox.Confirm(string.Format(Strings.RecheckConfirmFormat, due.Count, days)))
            return;

        using var cts = new CancellationTokenSource();
        string oldSummary = _summary.Text;
        try
        {
            var changes = await RecheckService.RunAsync(AppServices.Cache, due,
                (done, total) => { try { BeginInvoke(() => _summary.Text = string.Format(Strings.RecheckingFormat, done, total)); } catch { } },
                cts.Token);

            if (changes.Count == 0)
                NativeMessageBox.Info(string.Format(Strings.RecheckNoChangeFormat, due.Count));
            else
            {
                var sb = new StringBuilder();
                sb.AppendLine(string.Format(Strings.RecheckChangedHeaderFormat, due.Count, changes.Count));
                foreach (var c in changes.Take(40))
                    sb.AppendLine($"{(c.GotWorse ? Strings.RecheckWorse : Strings.RecheckBetter)}: {c.OldVerdict} ({c.OldDetections}) → {c.NewVerdict} ({c.NewDetections})\n   {c.Url}");
                NativeMessageBox.Info(sb.ToString());
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { NativeMessageBox.Error(Strings.RecheckErrorPrefix + ex.Message); }
        finally { try { _summary.Text = oldSummary; } catch { } }
    }

    void HuntPersistence()
    {
        var i = SelectedItem();
        if (i == null) return;
        var hooks = PersistenceHunter.Find(i.FilePath);
        if (hooks.Count == 0) { NativeMessageBox.Info(string.Format(Strings.PersistenceNoneFormat, i.FileName)); return; }
        var sb = new StringBuilder();
        sb.AppendLine(string.Format(Strings.PersistenceFoundFormat, i.FileName, hooks.Count));
        foreach (var h in hooks.Take(25)) sb.AppendLine($"[{h.Location}] {h.Name}\n   {h.Command}\n");
        sb.AppendLine(Strings.PersistenceManualNote);
        NativeMessageBox.Warn(sb.ToString());
    }

    async Task PinBaselineAsync()
    {
        var i = SelectedItem();
        if (i == null || !File.Exists(i.FilePath)) return;
        if (await BaselineStore.PinAsync(i.FilePath))
            NativeMessageBox.Info(string.Format(Strings.BaselineAddedFormat, i.FileName, BaselineStore.Count));
        else NativeMessageBox.Error(Strings.BaselineAddFailed);
    }

    async Task VerifyBaselineAsync()
    {
        if (BaselineStore.Count == 0) { NativeMessageBox.Info(Strings.BaselineEmptyInfo); return; }
        using var cts = new CancellationTokenSource();
        string old = _summary.Text;
        List<DriftResult> res;
        try
        {
            res = await BaselineStore.VerifyAsync(
                (d, t) => { try { BeginInvoke(() => _summary.Text = string.Format(Strings.IntegrityCheckingFormat, d, t)); } catch { } }, cts.Token);
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex) { NativeMessageBox.Error(Strings.IntegrityErrorPrefix + ex.Message); return; }
        finally { try { _summary.Text = old; } catch { } }

        int alarms = res.Count(r => r.IsAlarm);
        int changed = res.Count(r => r.Kind != DriftKind.Unchanged);
        var sb = new StringBuilder();
        sb.AppendLine(string.Format(Strings.IntegrityResultFormat, res.Count, alarms, changed));
        if (changed == 0) sb.AppendLine(Strings.IntegrityAllUnchanged);
        else foreach (var r in res.Where(r => r.Kind != DriftKind.Unchanged).OrderByDescending(r => r.IsAlarm).Take(40))
            sb.AppendLine($"{(r.IsAlarm ? "🔴" : "•")} {Path.GetFileName(r.Path)} — {r.Detail}");
        if (alarms > 0) NativeMessageBox.Error(sb.ToString()); else NativeMessageBox.Info(sb.ToString());
    }

    void ScanRunning()
    {
        var (paths, unreadable) = RunningProcesses.ImagePaths();
        if (paths.Count == 0) { NativeMessageBox.Info(Strings.NoRunnableProcessInfo); return; }
        if (!NativeMessageBox.Confirm(string.Format(Strings.ScanRunningConfirmFormat, paths.Count, unreadable)))
            return;
        StartScan(paths.ToArray(), recurse: false);
    }

    void ShowNeighbors()
    {
        var i = SelectedItem();
        if (i == null) return;
        var data = NeighborsService.Build(i.FilePath, AppServices.Cache);
        if (data == null) { NativeMessageBox.Info(Strings.FolderNotFoundInfo); return; }
        using var dlg = new NeighborsDialog(data, paths => StartScan(paths, recurse: false));
        dlg.ShowDialog(FindForm());
    }

    async Task VerifyHashAsync()
    {
        using var fd = new OpenFileDialog { Title = Strings.VerifyHashFileTitle };
        if (fd.ShowDialog() != DialogResult.OK) return;
        string? exp = Dialogs.InputBox(Strings.VerifyHashPrompt, Strings.VerifyHashTitle);
        if (string.IsNullOrWhiteSpace(exp)) return;
        try
        {
            var r = await HashService.VerifyExpectedAsync(fd.FileName, exp);
            if (r.Algorithm == "?") { NativeMessageBox.Warn(Strings.VerifyHashFormatWarn); return; }
            if (r.Matched) NativeMessageBox.Info(string.Format(Strings.VerifyHashMatchedFormat, r.Algorithm, r.Actual, fd.FileName));
            else NativeMessageBox.Error(string.Format(Strings.VerifyHashMismatchFormat, r.Algorithm, r.Expected, r.Actual));
        }
        catch (Exception ex) { NativeMessageBox.Error(Strings.VerifyHashErrorPrefix + ex.Message); }
    }

    void OnAllKeysExhausted(DateTime resumeUtc)
    {
        // Once per episode, and only while actually scanning. If the keyless GUI is already the
        // engine, there is nothing to ask — the scan keeps going without quota.
        if (_exhaustPromptShown || !_scheduler.IsRunning) return;
        if (Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable) return;
        _exhaustPromptShown = true;

        using var dlg = new QuotaExhaustedDialog(resumeUtc);
        if (dlg.ShowDialog(FindForm()) != DialogResult.OK) return;
        switch (dlg.Choice)
        {
            case QuotaExhaustedChoice.Keyless:
                Settings.KeylessGuiLookup.Value = true;
                SettingsManager.SaveSettings();
                NativeMessageBox.Info(Strings.KeylessEnabledInfo);
                break;
            case QuotaExhaustedChoice.NewKey:
                using (var key = new ApiKeyDialog())
                    if (key.ShowDialog(FindForm()) == DialogResult.OK)
                        AppServices.Vault.Add(key.KeyLabel, key.KeyValue);
                break;
            case QuotaExhaustedChoice.Wait:
            default:
                break; // the rotator is already counting down to the soonest reset
        }
    }

    void ExportReport()
    {
        var items = _scheduler.Items.Where(i => i.Report != null || i.Status == ScanStatus.TrustedSkipped).ToList();
        if (items.Count == 0) { NativeMessageBox.Info(Strings.NoResultsToExport); return; }
        using var dlg = new SaveFileDialog
        {
            Filter = Strings.ReportFilter,
            FileName = "virustotal-rapor.html",
        };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        try { ReportWriter.Write(dlg.FileName, items); NativeMessageBox.Info(Strings.ReportSavedPrefix + dlg.FileName); }
        catch (Exception ex) { NativeMessageBox.Error(Strings.ReportWriteErrorPrefix + ex.Message); }
    }

    void ClearCache()
    {
        if (NativeMessageBox.Confirm(string.Format(Strings.CacheClearConfirmFormat, AppServices.Cache.Count)))
        {
            AppServices.Cache.Clear();
            NativeMessageBox.Info(Strings.CacheClearedInfo);
        }
    }

    // ---- event sinks ----

    void OnProgress(OverallProgress p)
    {
        _overall.Value = Math.Clamp((int)p.Percent, 0, 100);
        string text = string.Format(Strings.ProgressSummaryFormat, p.Total, p.Done, p.Malicious, p.Suspicious, p.Clean, p.SignedSkipped, p.Failed);
        if (p.Done < p.Total && p.FilesPerSec > 0)
        {
            string eta = p.Remaining is { } rem ? $"  •  Kalan ~{ShortDuration(rem)}" : "";
            text += $"{eta}  •  {p.FilesPerSec:0.#} dosya/sn  •  Geçen {ShortDuration(p.Elapsed)}";
        }
        _summary.Text = text;
    }

    static string ShortDuration(TimeSpan t)
    {
        if (t.TotalHours >= 1) return $"{(int)t.TotalHours} sa {t.Minutes} dk";
        if (t.TotalMinutes >= 1) return $"{t.Minutes} dk {t.Seconds} sn";
        return $"{Math.Max(0, (int)t.TotalSeconds)} sn";
    }

    void OnItemFinished(ScanItem item)
    {
        if (ReferenceEquals(item, SelectedItem())) _detail.Show(item);
        if (item.Report?.IsMalicious == true) ThreatFound?.Invoke(item);
        OnFilterItemFinished(item);
        ScanHistoryStore.Record(item, "Tarama");
    }

    void UpdateRunningState(bool running)
    {
        _pauseBtn.Enabled = running;
        _cancelBtn.Enabled = running;
        if (!running) _pauseBtn.Text = Strings.BtnPause;
        if (running) { _repaintTimer.Start(); }
    }

    // ---- helpers ----

    /// <summary>Selects the first queue row and shows its detail (used by the dev snapshot).</summary>
    public void SelectFirst()
    {
        if (_grid.Rows.Count == 0) return;
        _grid.ClearSelection();
        _grid.CurrentCell = _grid.Rows[0].Cells[0];
        _grid.Rows[0].Selected = true;
        _detail.Show(SelectedItem());
    }

    /// <summary>Select and reveal a specific item (e.g. jumped to from a threat toast).</summary>
    public void FocusItem(ScanItem item)
    {
        foreach (DataGridViewRow row in _grid.Rows)
            if (ReferenceEquals(row.DataBoundItem, item))
            {
                _grid.ClearSelection();
                _grid.CurrentCell = row.Cells[0];
                row.Selected = true;
                break;
            }
        _detail.Show(item);
    }

    ScanItem? SelectedItem() => _grid.CurrentRow?.DataBoundItem as ScanItem;

    /// <summary>All currently-selected items (multi-select), for batch actions.</summary>
    List<ScanItem> SelectedItems()
    {
        var list = _grid.SelectedRows.Cast<DataGridViewRow>().Select(r => r.DataBoundItem).OfType<ScanItem>().ToList();
        if (list.Count == 0 && SelectedItem() is { } one) list.Add(one);
        return list;
    }
    static void CopySafe(string? s) { if (!string.IsNullOrEmpty(s)) { try { Clipboard.SetText(s); } catch (Exception ex) { Log("Clipboard copy failed: " + ex.Message, LogLevel.Warning); } } }

    void SaveShareCard()
    {
        var i = SelectedItem();
        if (i == null) return;
        using var dlg = new SaveFileDialog { Filter = "PNG|*.png", FileName = Path.GetFileNameWithoutExtension(i.FileName) + "-vt.png" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        try { using var bmp = ShareCard.Render(i); bmp.Save(dlg.FileName, System.Drawing.Imaging.ImageFormat.Png); }
        catch (Exception ex) { NativeMessageBox.Error(Strings.SaveErrorPrefix + ex.Message); }
    }
    void SafeUi(Action a) { try { if (IsHandleCreated) BeginInvoke(a); else a(); } catch (Exception ex) { Log("UI dispatch failed: " + ex.Message, LogLevel.Warning); } }

    public void ApplyTheme()
    {
        ThemeManager.StyleGrid(_grid);
        _detail.ApplyTheme();
        if (_chips.Count > 0) SetBucket(_bucket); // re-tint chips for the new theme
        _grid.Invalidate();
    }

    /// <summary>Every action, by Turkish name, for the Ctrl+K command palette.</summary>
    public List<CommandRecord> Commands() =>
    [
        new() { Name = "Dosya seç…", Desc = "Taranacak dosya(lar) seç", Run = SelectFiles },
        new() { Name = "Klasör seç…", Desc = "Bir klasörü alt klasörleriyle tara", Run = SelectFolder },
        new() { Name = "Hash sorgula…", Desc = "Bir MD5/SHA hash'ini VirusTotal'de ara", Run = () => _ = HashLookupAsync() },
        new() { Name = "Hash doğrula…", Desc = "Bir dosyayı beklenen hash ile karşılaştır", Run = () => _ = VerifyHashAsync() },
        new() { Name = "Çalışanları tara", Desc = "Çalışan tüm süreç imajlarını tara", Run = ScanRunning },
        new() { Name = "Bütünlük denetimi", Desc = "İzlenen dosyalarda değişiklik/drift ara", Run = () => _ = VerifyBaselineAsync() },
        new() { Name = "Aile kümeleri", Desc = "Aynı zararlı ailesini paylaşan dosyaları grupla", Run = () => { using var d = new FamilyClusterDialog(FamilyClusterService.Build(AppServices.Cache)); d.ShowDialog(FindForm()); } },
        new() { Name = "Karantina kasası", Desc = "Karantinaya alınanları görüntüle / geri yükle", Run = ShowQuarantineVault },
        new() { Name = "Olay zaman çizelgesi", Desc = "Gelen çalıştırılabilirleri varış zamanına göre kümele", Run = () => { using var d = new IncidentTimelineDialog(); d.ShowDialog(FindForm()); } },
        new() { Name = "Verdikt yeniden denetle", Desc = "Eski önbellek kayıtlarını kotasız yeniden sorgula", Run = () => _ = RunRecheckAsync() },
        new() { Name = "Klasör özeti", Desc = "Taranan klasörleri tehdit sayısıyla özetle", Run = ShowFolderRollup },
        new() { Name = "Rapor (HTML)", Desc = "Sonuçları HTML/CSV/JSON/metin rapora yaz", Run = ExportReport },
        new() { Name = "Dışa aktar (CSV)", Desc = "Sonuçları CSV olarak kaydet", Run = ExportCsv },
        new() { Name = "Önbelleği temizle", Desc = "Yerel hash önbelleğini sil", Run = ClearCache },
        new() { Name = "Diğer kopyaları bul (disk)", Desc = "Seçili dosyanın birebir kopyalarını diskte ara", Run = () => _ = FindCopiesAsync() },
        new() { Name = "Autostart kancalarını bul", Desc = "Seçili dosya için kalıcılık kayıtlarını ara", Run = HuntPersistence },
        new() { Name = "Klasör komşuları", Desc = "Seçili dosyanın klasöründeki diğer dosyalar", Run = ShowNeighbors },
    ];

    // ---- entry points used by the landing-tab launchpad ----
    public void ScanRunningProcesses() => ScanRunning();
    public void RescanSweep() => _ = RunRecheckAsync();
    public void ScanDownloadsFolder()
    {
        var dl = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (Directory.Exists(dl)) StartScan([dl], recurse: false);
        else NativeMessageBox.Info("İndirilenler klasörü bulunamadı.");
    }
}
