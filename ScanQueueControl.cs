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
    int _progressCol;

    /// <summary>Raised when a scan is requested but no API key is configured.</summary>
    public event Action? NeedApiKey;
    /// <summary>Raised when a threat is found (for tray notifications).</summary>
    public event Action<ScanItem>? ThreatFound;

    public ScanQueueControl()
    {
        Dock = DockStyle.Fill;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // action bar
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // split
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // overall

        // ---- action bar ----
        var bar = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true, Padding = new Padding(6) };
        bar.Controls.Add(ThemeManager.MakeButton("📄  Dosya seç…", (_, _) => SelectFiles(), accent: true));
        bar.Controls.Add(ThemeManager.MakeButton("📁  Klasör seç…", (_, _) => SelectFolder(), accent: true));
        bar.Controls.Add(ThemeManager.MakeButton("🔎  Hash sorgula…", (_, _) => _ = HashLookupAsync()));
        _pauseBtn = ThemeManager.MakeButton("⏸  Duraklat", (_, _) => TogglePause());
        _cancelBtn = ThemeManager.MakeButton("⏹  İptal", (_, _) => _scheduler.Cancel());
        bar.Controls.Add(_pauseBtn);
        bar.Controls.Add(_cancelBtn);
        bar.Controls.Add(ThemeManager.MakeButton("⬇  Dışa aktar (CSV)", (_, _) => ExportCsv()));
        bar.Controls.Add(ThemeManager.MakeButton("📄  Rapor (HTML)", (_, _) => ExportReport()));
        bar.Controls.Add(ThemeManager.MakeButton("🗑  Önbelleği temizle", (_, _) => ClearCache()));
        var hint = ThemeManager.MakeLabel("  Dosya/klasörleri buraya da sürükleyip bırakabilirsiniz.", subtle: true);
        bar.Controls.Add(hint);

        // ---- split ----
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical };
        ConfigureGrid();
        split.Panel1.Controls.Add(_grid);
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
        _summary.Text = "Hazır.";
        bottom.Controls.Add(_overall, 0, 0);
        bottom.Controls.Add(_summary, 0, 1);

        root.Controls.Add(bar, 0, 0);
        root.Controls.Add(split, 0, 1);
        root.Controls.Add(bottom, 0, 2);
        Controls.Add(root);

        _grid.SelectionChanged += (_, _) => _detail.Show(SelectedItem());

        _scheduler.UiPost = a => { try { if (IsHandleCreated) BeginInvoke(a); else a(); } catch (Exception ex) { Log("UI dispatch failed: " + ex.Message, LogLevel.Warning); } };
        _scheduler.ProgressChanged += OnProgress;
        _scheduler.ItemFinished += OnItemFinished;
        _scheduler.Started += () => SafeUi(() => UpdateRunningState(true));
        _scheduler.Finished += () => SafeUi(() => { UpdateRunningState(false); _repaintTimer.Stop(); _grid.Invalidate(); });

        _repaintTimer.Tick += (_, _) => { if (_scheduler.IsRunning) _grid.Invalidate(); };

        UpdateRunningState(false);
    }

    void ConfigureGrid()
    {
        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Dosya", DataPropertyName = nameof(ScanItem.FileName), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill, MinimumWidth = 160 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Boyut", DataPropertyName = nameof(ScanItem.SizeText), Width = 80 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Durum", DataPropertyName = nameof(ScanItem.StatusText), Width = 220 });
        var prog = new DataGridViewTextBoxColumn { HeaderText = "İlerleme", Width = 110 };
        _progressCol = _grid.Columns.Add(prog);
        ThemeManager.StyleGrid(_grid);
        _grid.DataSource = _scheduler.Items;
        _grid.CellPainting += Grid_CellPainting;

        var menu = new ContextMenuStrip();
        menu.Items.Add("VirusTotal'de aç", null, (_, _) => { var i = SelectedItem(); if (i?.Report != null) OpenUrlInBrowser(i.Report.ReportUrl); });
        menu.Items.Add("SHA-256 kopyala", null, (_, _) => CopySafe(SelectedItem()?.Sha256));
        menu.Items.Add("MD5 kopyala", null, (_, _) => CopySafe(SelectedItem()?.Md5));
        menu.Items.Add("Dosya konumunu aç", null, (_, _) => { var i = SelectedItem(); if (i != null && File.Exists(i.FilePath)) RevealInExplorer(i.FilePath); });
        menu.Items.Add("Yeniden tara", null, (_, _) => RescanSelected());
        menu.Items.Add("Güveni yok say, VT ile tara", null, (_, _) => RescanIgnoringTrust());
        menu.Items.Add("Karantinaya al", null, (_, _) => QuarantineSelected());
        _grid.ContextMenuStrip = menu;
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
        using var dlg = new FolderBrowserDialog { Description = "Taranacak klasör (alt klasörler dahil)" };
        if (dlg.ShowDialog() == DialogResult.OK && !string.IsNullOrEmpty(dlg.SelectedPath))
            StartScan([dlg.SelectedPath], recurse: true);
    }

    public void StartScan(IEnumerable<string> paths, bool recurse, bool bypassTrust = false)
    {
        bool keyless = Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable;
        if (!_scheduler.IsRunning && !AppServices.Rotator.HasUsableKeys && !Settings.TrustSkipSigned && !keyless)
        {
            NeedApiKey?.Invoke();
            NativeMessageBox.Warn("Taramadan önce bir API anahtarı ekleyin, ya da Güven Kaynakları'ndan imza-atlamayı / anahtarsız (GUI) modu açın.");
            return;
        }
        var opts = ScanOptions.FromSettings(recurse);
        opts.BypassTrust = bypassTrust;
        _ = Task.Run(async () =>
        {
            try { await _scheduler.RunAsync(paths, opts); }
            catch (Exception ex) { Log("Scan start failed: " + ex, LogLevel.Error); }
        });
    }

    async Task HashLookupAsync()
    {
        // Default is a precomputed example (notepad.exe's SHA-256) so there's something to test with.
        const string exampleHash = "ab15a95de88ab0624307ae0e28e333756a2a522f650a0be78749901f7dc32ecf";
        string? input = Dialogs.InputBox("Sorgulanacak MD5 / SHA-1 / SHA-256 hash:", "Hash sorgula", exampleHash);
        if (string.IsNullOrWhiteSpace(input)) return;
        input = input.Trim().ToLowerInvariant();
        if (!Regex.IsMatch(input, "^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$"))
        {
            NativeMessageBox.Warn("Geçerli bir MD5/SHA-1/SHA-256 hash girin.");
            return;
        }
        if (!AppServices.Rotator.HasUsableKeys) { NeedApiKey?.Invoke(); return; }

        try
        {
            string key = await AppServices.Rotator.AcquireAsync();
            var report = await AppServices.Api.GetFileReportAsync(input, key);
            if (report == null) { NativeMessageBox.Info("Bu hash VirusTotal'de bulunamadı."); return; }
            var item = new ScanItem(input) { Report = report, Status = ScanStatus.Completed };
            item.Md5 = report.Md5; item.Sha256 = report.Sha256;
            _scheduler.Items.Add(item);
            _grid.ClearSelection();
            if (_grid.Rows.Count > 0) _grid.Rows[^1].Selected = true;
        }
        catch (Exception ex) { NativeMessageBox.Error("Sorgu başarısız: " + ex.Message); }
    }

    void TogglePause()
    {
        if (_scheduler.IsPaused) { _scheduler.Resume(); _pauseBtn.Text = "⏸  Duraklat"; }
        else { _scheduler.Pause(); _pauseBtn.Text = "▶  Devam et"; }
    }

    void RescanSelected()
    {
        var i = SelectedItem();
        if (i != null && File.Exists(i.FilePath)) StartScan([i.FilePath], recurse: false);
    }

    void RescanIgnoringTrust()
    {
        var i = SelectedItem();
        if (i != null && File.Exists(i.FilePath)) StartScan([i.FilePath], recurse: false, bypassTrust: true);
    }

    void QuarantineSelected()
    {
        var i = SelectedItem();
        if (i == null || !File.Exists(i.FilePath)) return;
        if (!ConfirmGates.Quarantine.Ask(this, $"'{i.FileName}' karantinaya alınsın mı? (uzantısı .VIRUS yapılır, çalıştırılamaz)")) return;
        try
        {
            Directory.CreateDirectory(ConfigPathResolver.QuarantineFolder);
            string dest = Path.Combine(ConfigPathResolver.QuarantineFolder, i.FileName + ".VIRUS");
            File.Move(i.FilePath, dest, overwrite: true);
            Log($"Quarantined: {i.FilePath} -> {dest}", LogLevel.Warning);
            NativeMessageBox.Info("Dosya karantinaya alındı (çalıştırılamaz):\n" + dest);
        }
        catch (Exception ex) { NativeMessageBox.Error("Karantina başarısız: " + ex.Message); }
    }

    void ExportCsv()
    {
        var items = _scheduler.Items.Where(i => i.Report != null).ToList();
        if (items.Count == 0) { NativeMessageBox.Info("Dışa aktarılacak sonuç yok."); return; }
        using var dlg = new SaveFileDialog { Filter = "CSV|*.csv", FileName = "virustotal-sonuclar.csv" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        var sb = new StringBuilder();
        sb.AppendLine("Dosya;Verdict;Zararli;Supheli;Toplam;MD5;SHA256;Rapor");
        foreach (var i in items)
        {
            var r = i.Report!;
            sb.AppendLine($"\"{i.FileName}\";{r.Verdict};{r.Malicious};{r.Suspicious};{r.TotalEngines};{r.Md5};{r.Sha256};{r.ReportUrl}");
        }
        try { File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8); NativeMessageBox.Info("Kaydedildi: " + dlg.FileName); }
        catch (Exception ex) { NativeMessageBox.Error("Kaydetme hatası: " + ex.Message); }
    }

    void ExportReport()
    {
        var items = _scheduler.Items.Where(i => i.Report != null || i.Status == ScanStatus.TrustedSkipped).ToList();
        if (items.Count == 0) { NativeMessageBox.Info("Dışa aktarılacak sonuç yok."); return; }
        using var dlg = new SaveFileDialog
        {
            Filter = "HTML rapor|*.html|JSON|*.json|Metin|*.txt",
            FileName = "virustotal-rapor.html",
        };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        try { ReportWriter.Write(dlg.FileName, items); NativeMessageBox.Info("Rapor kaydedildi: " + dlg.FileName); }
        catch (Exception ex) { NativeMessageBox.Error("Rapor yazılamadı: " + ex.Message); }
    }

    void ClearCache()
    {
        if (NativeMessageBox.Confirm($"Yerel hash önbelleği ({AppServices.Cache.Count} kayıt) temizlensin mi?"))
        {
            AppServices.Cache.Clear();
            NativeMessageBox.Info("Önbellek temizlendi.");
        }
    }

    // ---- event sinks ----

    void OnProgress(OverallProgress p)
    {
        _overall.Value = Math.Clamp((int)p.Percent, 0, 100);
        _summary.Text = $"Toplam {p.Total} • Tamamlanan {p.Done} • Zararlı {p.Malicious} • Şüpheli {p.Suspicious} • Temiz {p.Clean} • İmzalı↷atlandı {p.SignedSkipped} • Hata {p.Failed}";
    }

    void OnItemFinished(ScanItem item)
    {
        if (ReferenceEquals(item, SelectedItem())) _detail.Show(item);
        if (item.Report?.IsMalicious == true) ThreatFound?.Invoke(item);
    }

    void UpdateRunningState(bool running)
    {
        _pauseBtn.Enabled = running;
        _cancelBtn.Enabled = running;
        if (!running) _pauseBtn.Text = "⏸  Duraklat";
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

    ScanItem? SelectedItem() => _grid.CurrentRow?.DataBoundItem as ScanItem;
    static void CopySafe(string? s) { if (!string.IsNullOrEmpty(s)) { try { Clipboard.SetText(s); } catch (Exception ex) { Log("Clipboard copy failed: " + ex.Message, LogLevel.Warning); } } }
    void SafeUi(Action a) { try { if (IsHandleCreated) BeginInvoke(a); else a(); } catch (Exception ex) { Log("UI dispatch failed: " + ex.Message, LogLevel.Warning); } }

    public void ApplyTheme()
    {
        ThemeManager.StyleGrid(_grid);
        _detail.ApplyTheme();
        _grid.Invalidate();
    }
}
