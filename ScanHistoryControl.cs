using System.Drawing;

namespace VirusTotalScanner;

/// <summary>The "Geçmiş" tab: a searchable, filterable log of every scan, read from
/// <see cref="ScanHistoryStore"/>. Double-click reopens the full result (from the cache); right-click
/// offers rescan / open-location / copy-hash / open-VT.</summary>
internal sealed class ScanHistoryControl : UserControl
{
    readonly DataGridView _grid = new();
    readonly TextBox _search = new() { Width = 220 };
    string _categoryFilter = ""; // "", "threat", "suspicious", "clean" — set by an overview tile drill-down
    readonly Panel _escBanner = new() { Dock = DockStyle.Fill, Visible = false, Cursor = Cursors.Hand, Padding = new Padding(12, 6, 12, 6) };
    readonly Label _escLabel = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
    readonly CheckBox _threatsOnly = new() { Text = Strings.HistoryThreatsOnlyLabel, AutoSize = true, Margin = new Padding(10, 6, 0, 0) };
    readonly CheckBox _starredOnly = new() { Text = Strings.HistoryStarredOnlyLabel, AutoSize = true, Margin = new Padding(10, 6, 0, 0) };
    readonly Label _count = new() { AutoSize = true, Margin = new Padding(12, 7, 0, 0), Tag = "subtle" };

    /// <summary>Raised when the user asks to rescan a path from history.</summary>
    public event Action<string[]>? RescanRequested;

    public ScanHistoryControl()
    {
        Dock = DockStyle.Fill;
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // strip
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // escalation banner (shown only when there are flips)
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // grid

        var strip = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true, Padding = new Padding(8, 6, 6, 4) };
        _search.PlaceholderText = Strings.SearchPlaceholder;
        _search.Margin = new Padding(0, 4, 8, 4);
        _search.TextChanged += (_, _) => { _categoryFilter = ""; Reload(); };
        _search.KeyDown += (_, e) => { if (e.KeyCode == Keys.Escape) _search.Clear(); };
        _threatsOnly.CheckedChanged += (_, _) => { _categoryFilter = ""; Reload(); };
        _starredOnly.CheckedChanged += (_, _) => { _categoryFilter = ""; Reload(); };
        var clear = ThemeManager.MakeButton(Strings.BtnHistoryClear, (_, _) =>
        {
            if (ScanHistoryStore.Count > 0 && NativeMessageBox.Confirm(Strings.HistoryClearConfirm))
                ScanHistoryStore.Clear();
        });
        var reverdict = ThemeManager.MakeButton(Strings.BtnHistoryReverdict, (_, _) =>
        {
            using var dlg = new HistoryReverdictDialog();
            dlg.ScanRequested += paths => RescanRequested?.Invoke(paths);
            dlg.ShowDialog(FindForm());
        });
        var report = ThemeManager.MakeButton(Strings.BtnHistoryExportReport, (_, _) =>
        {
            var menu = new ContextMenuStrip();
            void AddRange(string label, int? days)
            {
                menu.Items.Add(label, null, (_, _) =>
                {
                    var cutoff = days.HasValue ? DateTime.UtcNow.AddDays(-days.Value) : DateTime.MinValue;
                    var rows = ScanHistoryStore.All().Where(e => e.WhenUtc >= cutoff).ToList();
                    if (rows.Count == 0) { NativeMessageBox.Info(Strings.HistoryNoRecordsInRange); return; }
                    using var dlg = new SaveFileDialog { Filter = Strings.HistoryReportFilter, FileName = Strings.HistoryReportFileName };
                    if (dlg.ShowDialog() != DialogResult.OK) return;
                    try
                    {
                        ReportWriter.WriteHistory(dlg.FileName, rows, label);
                        NativeMessageBox.Info(string.Format(Strings.HistoryReportWrittenFormat, rows.Count, label));
                        try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + dlg.FileName + "\""); } catch { }
                    }
                    catch (Exception ex) { NativeMessageBox.Error(Strings.ReportWriteErrorPrefix + ex.Message); }
                });
            }
            AddRange(Strings.HistoryRangeLast7Days, 7);
            AddRange(Strings.HistoryRangeLast30Days, 30);
            AddRange(Strings.HistoryRangeLast90Days, 90);
            AddRange(Strings.ChipAll, null);
            menu.Show(Cursor.Position);
        });
        var recurring = ThemeManager.MakeButton(Strings.BtnHistoryRecurring, (_, _) =>
        {
            using var dlg = new RecurrenceDialog(RecurrenceService.Find());
            dlg.ScanRequested += paths => RescanRequested?.Invoke(paths);
            dlg.ShowDialog(FindForm());
        });
        var hotspots = ThemeManager.MakeButton(Strings.BtnHistoryHotspots, (_, _) =>
        {
            using var dlg = new ThreatHotspotDialog(ThreatHotspotService.Find());
            dlg.ScanRequested += paths => RescanRequested?.Invoke(paths);
            dlg.ShowDialog(FindForm());
        });
        strip.Controls.Add(_search);
        strip.Controls.Add(_threatsOnly);
        strip.Controls.Add(_starredOnly);
        strip.Controls.Add(reverdict);
        strip.Controls.Add(recurring);
        strip.Controls.Add(hotspots);
        strip.Controls.Add(report);
        strip.Controls.Add(clear);
        strip.Controls.Add(_count);

        BuildGrid();

        _escBanner.Controls.Add(_escLabel);
        _escBanner.Click += OpenReverdict;
        _escLabel.Click += OpenReverdict;

        root.Controls.Add(strip, 0, 0);
        root.Controls.Add(_escBanner, 0, 1);
        root.Controls.Add(_grid, 0, 2);
        Controls.Add(root);

        ScanHistoryStore.Changed += OnStoreChanged;
        EscalationStore.Changed += OnEscChanged;
        RefreshEscBanner();
        Reload();
    }

    void OnStoreChanged() { try { if (IsHandleCreated) BeginInvoke(Reload); } catch { } }
    void OnEscChanged() { try { if (IsHandleCreated) BeginInvoke(RefreshEscBanner); } catch { } }

    void OpenReverdict(object? s, EventArgs e)
    {
        // Banner now opens the zero-quota dossier (reads the persisted flips); a live re-check that spends
        // quota is an explicit button inside it, instead of being the banner's only, unavoidable action.
        using var dlg = new EscalationDossierDialog();
        dlg.ScanRequested += paths => RescanRequested?.Invoke(paths);
        dlg.ShowDialog(FindForm());
    }

    /// <summary>Pinned red banner above the grid summarizing the persisted clean→threat flips.</summary>
    void RefreshEscBanner()
    {
        int n = EscalationStore.Count;
        if (n == 0) { _escBanner.Visible = false; return; }
        _escBanner.BackColor = Color.FromArgb(60, 30, 30);
        _escLabel.ForeColor = Color.FromArgb(255, 140, 140);
        var latest = EscalationStore.All().OrderByDescending(r => r.FlipUtc).First();
        _escLabel.Text = string.Format(Strings.HistoryEscalationBannerFormat, n, latest.Name, latest.NewRatio);
        _escBanner.Visible = true;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { ScanHistoryStore.Changed -= OnStoreChanged; EscalationStore.Changed -= OnEscChanged; }
        base.Dispose(disposing);
    }

    void BuildGrid()
    {
        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.AllowUserToAddRows = false;
        _grid.ReadOnly = true;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColHistoryStar, DataPropertyName = nameof(HistoryEntry.Star), Width = 30, DefaultCellStyle = new DataGridViewCellStyle { Alignment = DataGridViewContentAlignment.MiddleCenter } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColHistoryDate, DataPropertyName = nameof(HistoryEntry.WhenLocal), Width = 130, DefaultCellStyle = new DataGridViewCellStyle { Format = "yyyy-MM-dd HH:mm" } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColFile, DataPropertyName = nameof(HistoryEntry.Name), Width = 190 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColVerdict, DataPropertyName = nameof(HistoryEntry.Verdict), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColDetections, DataPropertyName = nameof(HistoryEntry.Ratio), Width = 60, DefaultCellStyle = new DataGridViewCellStyle { Alignment = DataGridViewContentAlignment.MiddleRight } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColHistorySource, DataPropertyName = nameof(HistoryEntry.Source), Width = 80 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColHistoryNote, DataPropertyName = nameof(HistoryEntry.Note), Width = 160 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColPath, DataPropertyName = nameof(HistoryEntry.Path), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        ThemeManager.StyleGrid(_grid);

        // Click the ★ cell to toggle the star.
        _grid.CellClick += (_, e) =>
        {
            if (e.RowIndex >= 0 && e.ColumnIndex == 0 && _grid.Rows[e.RowIndex].DataBoundItem is HistoryEntry h)
            {
                h.Starred = !h.Starred;
                ScanHistoryStore.Persist();
            }
        };

        _grid.CellFormatting += (_, e) =>
        {
            if (_grid.Rows[e.RowIndex].DataBoundItem is not HistoryEntry h || h.Detections <= 0) return;
            // Match the queue/overview: real threat = red, low-detection suspicious = amber (per the
            // user's verdict categories), instead of painting every nonzero hit bright red.
            e.CellStyle!.ForeColor = VerdictCategories.IsThreat(h.Detections) ? Theme.Current.Danger : Theme.Current.Warning;
        };
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) Reopen(Selected()); };

        var menu = new ContextMenuStrip();
        menu.Items.Add(Strings.MenuHistoryRescan, null, (_, _) => { var h = Selected(); if (EnsureFile(h)) RescanRequested?.Invoke([h!.Path!]); });
        menu.Items.Add(Strings.MenuHistoryOpenDetails, null, (_, _) => Reopen(Selected()));
        menu.Items.Add(Strings.MenuRevealFile, null, (_, _) => { var h = Selected(); if (EnsureFile(h)) try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + h!.Path + "\""); } catch { } });
        menu.Items.Add(Strings.BtnEscalationCopySha, null, (_, _) => { var h = Selected(); if (!string.IsNullOrEmpty(h?.Sha256)) try { Clipboard.SetText(h.Sha256); } catch { } });
        menu.Items.Add(Strings.MenuHistoryToggleStar, null, (_, _) => { if (Selected() is { } h) { h.Starred = !h.Starred; ScanHistoryStore.Persist(); } });
        menu.Items.Add(Strings.MenuHistoryEditNote, null, (_, _) =>
        {
            if (Selected() is not { } h) return;
            string? note = Dialogs.InputBox(Strings.HistoryNotePrompt, Strings.ColHistoryNote, h.Note ?? "");
            if (note != null) { h.Note = note; ScanHistoryStore.Persist(); }
        });
        _grid.ContextMenuStrip = menu;
    }

    HistoryEntry? Selected() => _grid.CurrentRow?.DataBoundItem as HistoryEntry;

    /// <summary>Apply a category drill-down from an overview count tile (threat / suspicious / clean),
    /// clearing the other filters first so the click lands exactly on those files.</summary>
    public void ApplyExternalFilter(string category)
    {
        _threatsOnly.Checked = false; _starredOnly.Checked = false; _search.Text = ""; // handlers clear _categoryFilter…
        _categoryFilter = category; // …so set it after, then reload authoritatively
        Reload();
    }

    void Reload()
    {
        string q = _search.Text.Trim();
        var rows = ScanHistoryStore.All()
            .Reverse() // newest first
            .Where(e => _categoryFilter switch
            {
                "threat" => VerdictCategories.IsThreat(e.Detections),
                "suspicious" => e.Detections > 0 && !VerdictCategories.IsThreat(e.Detections),
                "clean" => e.Detections == 0,
                _ => true,
            })
            .Where(e => !_threatsOnly.Checked || e.Detections > 0)
            .Where(e => !_starredOnly.Checked || e.Starred)
            .Where(e => q.Length == 0
                || (e.Name?.IndexOf(q, StringComparison.OrdinalIgnoreCase) ?? -1) >= 0
                || (e.Path?.IndexOf(q, StringComparison.OrdinalIgnoreCase) ?? -1) >= 0)
            .ToList();
        _grid.DataSource = rows;
        _count.Text = string.Format(Strings.HistoryCountFormat, rows.Count) + (ScanHistoryStore.Count != rows.Count ? string.Format(Strings.HistoryCountTotalSuffixFormat, ScanHistoryStore.Count) : "");
    }

    /// <summary>Reopen the full result detail by rebuilding a ScanItem from the cached report.</summary>
    void Reopen(HistoryEntry? e)
    {
        if (e == null) return;
        var report = string.IsNullOrEmpty(e.Md5) ? null : AppServices.Cache.TryGet(e.Md5, int.MaxValue);
        if (report == null)
        {
            // Evicted from cache: offer to re-scan (if the file is still there) instead of a dead end.
            bool here = e.Path != null && File.Exists(e.Path);
            string head = string.Format(Strings.HistoryReopenHeadFormat, e.Name, e.Verdict, e.Ratio);
            if (here && NativeMessageBox.Confirm(head + Strings.HistoryReopenRescanSuffix))
                RescanRequested?.Invoke([e.Path!]);
            else if (!here)
                NativeMessageBox.Info(head + Strings.ReopenFileGoneSuffix + (e.Path ?? Strings.ReopenNoPath));
            return;
        }
        var item = new ScanItem(e.Path ?? e.Name) { Report = report, Status = ScanStatus.Completed, Md5 = e.Md5, Sha256 = e.Sha256 };
        using var dlg = new DetailDialog(item);
        dlg.ShowDialog(FindForm());
    }

    /// <summary>True if the row's file still exists; otherwise tells the user plainly.</summary>
    static bool EnsureFile(HistoryEntry? h)
    {
        if (h?.Path != null && File.Exists(h.Path)) return true;
        NativeMessageBox.Info(h?.Path != null ? Strings.HistoryFileGoneFormat + h.Path : Strings.HistoryNoPathInfo);
        return false;
    }

    public void ApplyTheme()
    {
        ThemeManager.StyleGrid(_grid);
        _grid.Invalidate();
    }
}
