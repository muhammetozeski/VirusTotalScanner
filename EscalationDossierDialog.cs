using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Zero-quota view of the durable clean→threat flip ledger (<see cref="EscalationStore"/>): which
/// once-cleared files later turned malicious, when, their old→new ratio, how long they sat clean, and
/// whether they are still on disk to neutralize now. Reads only persisted records — NO VirusTotal calls.
/// A live re-check (which does spend quota) is one explicit button away.</summary>
internal sealed class EscalationDossierDialog : Form
{
    readonly DataGridView _grid = new();
    readonly Label _status = new() { AutoSize = true, Margin = new Padding(8, 8, 0, 0) };
    List<DossierRow> _rows = [];

    /// <summary>Forwarded up to the host so a flipped file still on disk can be re-scanned.</summary>
    public event Action<string[]>? ScanRequested;

    sealed class DossierRow
    {
        public required EscalationRecord Rec { get; init; }
        public string? FilePath { get; init; }
        public bool OnDisk { get; init; }

        public DateTime FlipLocal => Rec.FlipLocal;
        public string Name => Rec.Name;
        public string OldRatio => Rec.OldRatio;
        public string NewRatio => Rec.NewRatio;
        public int DaysClean => Math.Max(0, (int)(Rec.FlipUtc - Rec.FirstScanUtc).TotalDays);
        public string Presence => OnDisk ? "✓ diskte" : "— yok";
        public string Sha => Rec.Hash;
    }

    public EscalationDossierDialog()
    {
        Text = "🔴 Sonradan tehdit oldu — dosya geçmişi";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(900, 500);
        MinimumSize = new Size(680, 360);

        var live = ThemeManager.MakeButton("🔄  Canlı yeniden denetle (kota)", (_, _) =>
        {
            using var dlg = new HistoryReverdictDialog();
            dlg.ScanRequested += p => ScanRequested?.Invoke(p);
            dlg.ShowDialog(this);
            Load2(); // a re-check may have added new flips
        });
        var quarantine = ThemeManager.MakeButton("🛡  Karantinaya al", (_, _) => QuarantineSelected());
        var reveal = ThemeManager.MakeButton("📁  Konumu aç", (_, _) => RevealSelected());
        var copySha = ThemeManager.MakeButton("📋  SHA-256 kopyala", (_, _) => CopyShaSelected());
        var openVt = ThemeManager.MakeButton("🌐  VT'de aç", (_, _) => OpenVtSelected());
        var close = new Button { Text = "Kapat", DialogResult = DialogResult.Cancel, Width = 90 };

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(8, 8, 8, 4) };
        top.Controls.Add(live);
        top.Controls.Add(quarantine);
        top.Controls.Add(reveal);
        top.Controls.Add(copySha);
        top.Controls.Add(openVt);
        top.Controls.Add(_status);

        BuildGrid();
        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 44, Padding = new Padding(10, 6, 10, 6) };
        close.Dock = DockStyle.Right;
        bottom.Controls.Add(close);

        Controls.Add(_grid);
        Controls.Add(top);
        Controls.Add(bottom);
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleGrid(_grid);
        foreach (var b in new[] { live, quarantine, reveal, copySha, openVt }) ThemeManager.StyleButton(b);
        ThemeManager.StyleButton(close);

        Load2();
    }

    void BuildGrid()
    {
        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.AllowUserToAddRows = false;
        _grid.ReadOnly = true;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Tehdit oldu", DataPropertyName = nameof(DossierRow.FlipLocal), Width = 130, DefaultCellStyle = new DataGridViewCellStyle { Format = "yyyy-MM-dd HH:mm" } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Dosya", DataPropertyName = nameof(DossierRow.Name), Width = 180 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Eskiden", DataPropertyName = nameof(DossierRow.OldRatio), Width = 75 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Şimdi", DataPropertyName = nameof(DossierRow.NewRatio), Width = 75 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Temiz kaldı (gün)", DataPropertyName = nameof(DossierRow.DaysClean), Width = 115 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Durum", DataPropertyName = nameof(DossierRow.Presence), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "SHA-256", DataPropertyName = nameof(DossierRow.Sha), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

        _grid.CellFormatting += (_, e) =>
        {
            if (_grid.Rows[e.RowIndex].DataBoundItem is not DossierRow r) return;
            if (e.ColumnIndex == 3) e.CellStyle!.ForeColor = Theme.Current.Danger;          // "Şimdi" ratio in red
            if (e.ColumnIndex == 5 && r.OnDisk) e.CellStyle!.ForeColor = Theme.Current.Warning; // still on disk = actionable
        };
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) RevealSelected(); };
    }

    void Load2()
    {
        var hist = ScanHistoryStore.All();
        _rows = EscalationStore.All().OrderByDescending(r => r.FlipUtc).Select(r =>
        {
            var path = hist.FirstOrDefault(h => !string.IsNullOrEmpty(h.Sha256) && string.Equals(h.Sha256, r.Hash, StringComparison.OrdinalIgnoreCase))?.Path;
            bool onDisk = !string.IsNullOrEmpty(path) && File.Exists(path);
            return new DossierRow { Rec = r, FilePath = path, OnDisk = onDisk };
        }).ToList();
        _grid.DataSource = null;
        _grid.DataSource = _rows;
        int live = _rows.Count(r => r.OnDisk);
        _status.Text = _rows.Count == 0
            ? "Kayıtlı sonradan-tehdit dönüşü yok."
            : $"{_rows.Count} dosya sonradan tehdide döndü — {live} tanesi hâlâ diskte.";
    }

    DossierRow? Selected() => _grid.CurrentRow?.DataBoundItem as DossierRow;

    void QuarantineSelected()
    {
        var r = Selected();
        if (r == null) return;
        if (!r.OnDisk || string.IsNullOrEmpty(r.FilePath)) { _status.Text = "Bu dosya artık diskte değil — karantinaya alınamaz."; return; }
        if (QuarantineVault.Quarantine(r.FilePath, null, r.Rec.Hash, null, out var err)) { _status.Text = $"Karantinaya alındı: {r.Name}"; Load2(); }
        else _status.Text = "Karantinaya alınamadı: " + err;
    }

    void RevealSelected()
    {
        var r = Selected();
        if (r?.OnDisk == true && !string.IsNullOrEmpty(r.FilePath))
            try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + r.FilePath + "\""); } catch { }
        else _status.Text = "Dosya diskte bulunamadı.";
    }

    void CopyShaSelected()
    {
        var r = Selected();
        if (r == null || string.IsNullOrEmpty(r.Sha)) return;
        try { Clipboard.SetText(r.Sha); _status.Text = "SHA-256 kopyalandı."; } catch { }
    }

    void OpenVtSelected()
    {
        var r = Selected();
        if (r == null || string.IsNullOrEmpty(r.Sha)) return;
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://www.virustotal.com/gui/file/" + r.Sha) { UseShellExecute = true }); }
        catch (Exception ex) { _status.Text = "Açılamadı: " + ex.Message; }
    }
}
