using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Zero-quota view of the durable clean→threat flip ledger (<see cref="EscalationStore"/>): which
/// once-cleared files later turned malicious, when, their old→new ratio, how long they sat clean, and
/// whether they are still on disk to neutralize now. Reads only persisted records — NO VirusTotal calls.
/// A live re-check (which does spend quota) is one explicit button away.</summary>
internal sealed class EscalationDossierDialog : Form
{
    readonly DataGridView _grid = new EntityGridView();
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
        public string Presence => OnDisk ? Strings.EscalationPresenceOnDisk : Strings.EscalationPresenceGone;
        public string Sha => Rec.Hash;
    }

    public EscalationDossierDialog()
    {
        Text = Strings.DlgEscalationTitle;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(900, 500);
        MinimumSize = new Size(680, 360);

        var live = ThemeManager.MakeButton(Strings.BtnEscalationLiveReverdict, (_, _) =>
        {
            using var dlg = new HistoryReverdictDialog();
            dlg.ScanRequested += p => ScanRequested?.Invoke(p);
            dlg.ShowDialog(this);
            Load2(); // a re-check may have added new flips
        });
        var quarantine = ThemeManager.MakeButton(Strings.DetailActionQuarantine, (_, _) => QuarantineSelected());
        var reveal = ThemeManager.MakeButton(Strings.BtnEscalationReveal, (_, _) => RevealSelected());
        var copySha = ThemeManager.MakeButton(Strings.BtnEscalationCopySha, (_, _) => CopyShaSelected());
        var openVt = ThemeManager.MakeButton(Strings.BtnEscalationOpenVt, (_, _) => OpenVtSelected());
        var close = new Button { Text = Strings.BtnClose, DialogResult = DialogResult.Cancel, Width = 90 };

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
        EntityGrid.Standardize<DossierRow>(_grid,
        [
            new(Strings.MenuCopySha256, e => e.Sha),
            new(Strings.MenuCopyFileName, e => e.Name),
            new(Strings.MenuCopyFilePath, e => e.FilePath),
            new(Strings.MenuCopyVtUrl, e => VtUrl(e.Sha)),
        ],
        [
            new(Strings.DetailActionQuarantine, _ => QuarantineSelected()),
            new(Strings.BtnEscalationReveal, _ => RevealSelected()),
            new(Strings.BtnEscalationOpenVt, _ => OpenVtSelected()),
        ]);
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
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColEscalationFlippedDate, DataPropertyName = nameof(DossierRow.FlipLocal), Width = 130, DefaultCellStyle = new DataGridViewCellStyle { Format = "yyyy-MM-dd HH:mm" } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColFile, DataPropertyName = nameof(DossierRow.Name), Width = 180 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColReverdictOldRatio, DataPropertyName = nameof(DossierRow.OldRatio), Width = 75 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColReverdictNewRatio, DataPropertyName = nameof(DossierRow.NewRatio), Width = 75 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColEscalationDaysClean, DataPropertyName = nameof(DossierRow.DaysClean), Width = 115 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColStatus, DataPropertyName = nameof(DossierRow.Presence), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.MenuCopySha256, DataPropertyName = nameof(DossierRow.Sha), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

        _grid.CellFormatting += (_, e) =>
        {
            if (_grid.Rows[e.RowIndex].DataBoundItem is not DossierRow r) return;
            string prop = e.ColumnIndex >= 0 ? _grid.Columns[e.ColumnIndex].DataPropertyName : "";
            if (prop == nameof(DossierRow.NewRatio)) e.CellStyle!.ForeColor = Theme.Current.Danger;          // "Şimdi" ratio in red
            if (prop == nameof(DossierRow.Presence) && r.OnDisk) e.CellStyle!.ForeColor = Theme.Current.Warning; // still on disk = actionable
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
            ? Strings.EscalationNoRecords
            : string.Format(Strings.EscalationSummaryFormat, _rows.Count, live);
    }

    DossierRow? Selected() => _grid.CurrentRow?.DataBoundItem as DossierRow;

    void QuarantineSelected()
    {
        var r = Selected();
        if (r == null) return;
        if (!r.OnDisk || string.IsNullOrEmpty(r.FilePath)) { _status.Text = Strings.EscalationCannotQuarantineGone; return; }
        if (QuarantineVault.Quarantine(r.FilePath, null, r.Rec.Hash, null, out var err)) { _status.Text = string.Format(Strings.EscalationQuarantinedFormat, r.Name); Load2(); }
        else _status.Text = Strings.EscalationQuarantineFailedPrefix + err;
    }

    void RevealSelected()
    {
        var r = Selected();
        if (r?.OnDisk == true && !string.IsNullOrEmpty(r.FilePath))
            try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + r.FilePath + "\""); } catch { }
        else _status.Text = Strings.EscalationFileNotOnDisk;
    }

    void CopyShaSelected()
    {
        var r = Selected();
        if (r == null || string.IsNullOrEmpty(r.Sha)) return;
        try { Clipboard.SetText(r.Sha); _status.Text = Strings.EscalationShaCopied; } catch { }
    }

    void OpenVtSelected()
    {
        var r = Selected();
        if (r == null || string.IsNullOrEmpty(r.Sha)) return;
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://www.virustotal.com/gui/file/" + r.Sha) { UseShellExecute = true }); }
        catch (Exception ex) { _status.Text = Strings.EscalationOpenFailedPrefix + ex.Message; }
    }
}
