using System.Drawing;

namespace VirusTotalScanner;

/// <summary>The "Geçmiş" tab: a searchable, filterable log of every scan, read from
/// <see cref="ScanHistoryStore"/>. Double-click reopens the full result (from the cache); right-click
/// offers rescan / open-location / copy-hash / open-VT.</summary>
internal sealed class ScanHistoryControl : UserControl
{
    readonly DataGridView _grid = new();
    readonly TextBox _search = new() { Width = 220 };
    readonly CheckBox _threatsOnly = new() { Text = "Sadece tehditler", AutoSize = true, Margin = new Padding(10, 6, 0, 0) };
    readonly CheckBox _starredOnly = new() { Text = "★ Yıldızlılar", AutoSize = true, Margin = new Padding(10, 6, 0, 0) };
    readonly Label _count = new() { AutoSize = true, Margin = new Padding(12, 7, 0, 0), Tag = "subtle" };

    /// <summary>Raised when the user asks to rescan a path from history.</summary>
    public event Action<string[]>? RescanRequested;

    public ScanHistoryControl()
    {
        Dock = DockStyle.Fill;
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var strip = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true, Padding = new Padding(8, 6, 6, 4) };
        _search.PlaceholderText = "🔎  Ara (ad/yol)…";
        _search.Margin = new Padding(0, 4, 8, 4);
        _search.TextChanged += (_, _) => Reload();
        _search.KeyDown += (_, e) => { if (e.KeyCode == Keys.Escape) _search.Clear(); };
        _threatsOnly.CheckedChanged += (_, _) => Reload();
        _starredOnly.CheckedChanged += (_, _) => Reload();
        var clear = ThemeManager.MakeButton("🗑  Geçmişi temizle", (_, _) =>
        {
            if (ScanHistoryStore.Count > 0 && NativeMessageBox.Confirm("Tüm tarama geçmişi silinsin mi? (önbellek etkilenmez)"))
                ScanHistoryStore.Clear();
        });
        strip.Controls.Add(_search);
        strip.Controls.Add(_threatsOnly);
        strip.Controls.Add(_starredOnly);
        strip.Controls.Add(clear);
        strip.Controls.Add(_count);

        BuildGrid();

        root.Controls.Add(strip, 0, 0);
        root.Controls.Add(_grid, 0, 1);
        Controls.Add(root);

        ScanHistoryStore.Changed += OnStoreChanged;
        Reload();
    }

    void OnStoreChanged() { try { if (IsHandleCreated) BeginInvoke(Reload); } catch { } }

    protected override void Dispose(bool disposing)
    {
        if (disposing) ScanHistoryStore.Changed -= OnStoreChanged;
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
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "★", DataPropertyName = nameof(HistoryEntry.Star), Width = 30, DefaultCellStyle = new DataGridViewCellStyle { Alignment = DataGridViewContentAlignment.MiddleCenter } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Tarih", DataPropertyName = nameof(HistoryEntry.WhenLocal), Width = 130, DefaultCellStyle = new DataGridViewCellStyle { Format = "yyyy-MM-dd HH:mm" } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Dosya", DataPropertyName = nameof(HistoryEntry.Name), Width = 190 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Verdikt", DataPropertyName = nameof(HistoryEntry.Verdict), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Tespit", DataPropertyName = nameof(HistoryEntry.Ratio), Width = 60, DefaultCellStyle = new DataGridViewCellStyle { Alignment = DataGridViewContentAlignment.MiddleRight } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Kaynak", DataPropertyName = nameof(HistoryEntry.Source), Width = 80 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Not", DataPropertyName = nameof(HistoryEntry.Note), Width = 160 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Yol", DataPropertyName = nameof(HistoryEntry.Path), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
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
            if (_grid.Rows[e.RowIndex].DataBoundItem is HistoryEntry h && h.Detections > 0)
                e.CellStyle!.ForeColor = Theme.Current.Danger;
        };
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) Reopen(Selected()); };

        var menu = new ContextMenuStrip();
        menu.Items.Add("🔁  Tekrar tara", null, (_, _) => { var h = Selected(); if (EnsureFile(h)) RescanRequested?.Invoke([h!.Path!]); });
        menu.Items.Add("🔎  Ayrıntıyı aç", null, (_, _) => Reopen(Selected()));
        menu.Items.Add("📁  Dosya konumunu aç", null, (_, _) => { var h = Selected(); if (EnsureFile(h)) try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + h!.Path + "\""); } catch { } });
        menu.Items.Add("📋  SHA-256 kopyala", null, (_, _) => { var h = Selected(); if (!string.IsNullOrEmpty(h?.Sha256)) try { Clipboard.SetText(h.Sha256); } catch { } });
        menu.Items.Add("⭐  Yıldız aç/kapat", null, (_, _) => { if (Selected() is { } h) { h.Starred = !h.Starred; ScanHistoryStore.Persist(); } });
        menu.Items.Add("📝  Not ekle/düzenle…", null, (_, _) =>
        {
            if (Selected() is not { } h) return;
            string? note = Dialogs.InputBox("Bu tarama için not:", "Not", h.Note ?? "");
            if (note != null) { h.Note = note; ScanHistoryStore.Persist(); }
        });
        _grid.ContextMenuStrip = menu;
    }

    HistoryEntry? Selected() => _grid.CurrentRow?.DataBoundItem as HistoryEntry;

    void Reload()
    {
        string q = _search.Text.Trim();
        var rows = ScanHistoryStore.All()
            .Reverse() // newest first
            .Where(e => !_threatsOnly.Checked || e.Detections > 0)
            .Where(e => !_starredOnly.Checked || e.Starred)
            .Where(e => q.Length == 0
                || (e.Name?.IndexOf(q, StringComparison.OrdinalIgnoreCase) ?? -1) >= 0
                || (e.Path?.IndexOf(q, StringComparison.OrdinalIgnoreCase) ?? -1) >= 0)
            .ToList();
        _grid.DataSource = rows;
        _count.Text = $"{rows.Count} kayıt" + (ScanHistoryStore.Count != rows.Count ? $" / {ScanHistoryStore.Count} toplam" : "");
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
            string head = $"{e.Name} — {e.Verdict} {e.Ratio}\n\nTam ayrıntı önbellekte yok";
            if (here && NativeMessageBox.Confirm(head + ".\nDosyayı yeniden taramak ister misin?"))
                RescanRequested?.Invoke([e.Path!]);
            else if (!here)
                NativeMessageBox.Info(head + " ve dosya artık şurada değil:\n" + (e.Path ?? "(yol yok)"));
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
        NativeMessageBox.Info(h?.Path != null ? "Dosya artık şurada değil:\n" + h.Path : "Bu kaydın dosya yolu yok.");
        return false;
    }

    public void ApplyTheme()
    {
        ThemeManager.StyleGrid(_grid);
        _grid.Invalidate();
    }
}
