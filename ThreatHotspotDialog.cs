using System.Drawing;

namespace VirusTotalScanner;

/// <summary>"Tehdit odakları" — folders that keep producing different threats, so the user can act on the
/// SOURCE (close it / rescan the directory) instead of deleting one file at a time. Double-click or the
/// reveal button opens the folder; rescan re-checks the whole directory. Local-only.</summary>
internal sealed class ThreatHotspotDialog : Form
{
    readonly DataGridView _grid = new();

    public event Action<string[]>? ScanRequested;

    public ThreatHotspotDialog(List<ThreatHotspotService.Hotspot> items)
    {
        Text = Strings.DlgThreatHotspotTitle;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(900, 480);
        MinimumSize = new Size(660, 340);

        var header = new Label
        {
            Dock = DockStyle.Top,
            Height = 32,
            Padding = new Padding(10, 9, 10, 0),
            Text = items.Count == 0
                ? Strings.ThreatHotspotNone
                : string.Format(Strings.ThreatHotspotHeaderFormat, items.Count),
        };

        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.AllowUserToAddRows = false;
        _grid.ReadOnly = true;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColFolder, DataPropertyName = nameof(ThreatHotspotService.Hotspot.Directory), Width = 260 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColDistinctThreats, DataPropertyName = nameof(ThreatHotspotService.Hotspot.DistinctThreats), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColSpan, DataPropertyName = nameof(ThreatHotspotService.Hotspot.Span), Width = 180 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColSamples, DataPropertyName = nameof(ThreatHotspotService.Hotspot.SamplesText), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _grid.DataSource = items;
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) Reveal(); };

        var rescan = ThemeManager.MakeButton(Strings.BtnRescanFolder, (_, _) =>
        {
            if (Selected()?.Directory is { Length: > 0 } d && Directory.Exists(d)) { ScanRequested?.Invoke([d]); Close(); }
        });
        var reveal = ThemeManager.MakeButton(Strings.BtnOpenFolder, (_, _) => Reveal());
        var close = new Button { Text = Strings.BtnClose, DialogResult = DialogResult.OK, Dock = DockStyle.Right, Width = 100 };

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(8, 6, 8, 4) };
        top.Controls.Add(rescan);
        top.Controls.Add(reveal);

        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 44, Padding = new Padding(10, 6, 10, 6) };
        bottom.Controls.Add(close);

        Controls.Add(_grid);
        Controls.Add(top);
        Controls.Add(header);
        Controls.Add(bottom);
        AcceptButton = close;
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleGrid(_grid);
        ThemeManager.StyleButton(rescan);
        ThemeManager.StyleButton(reveal);
        ThemeManager.StyleButton(close);
    }

    ThreatHotspotService.Hotspot? Selected() => _grid.CurrentRow?.DataBoundItem as ThreatHotspotService.Hotspot;

    void Reveal()
    {
        if (Selected()?.Directory is { Length: > 0 } d && Directory.Exists(d))
            try { System.Diagnostics.Process.Start("explorer.exe", "\"" + d + "\""); } catch { }
    }
}
