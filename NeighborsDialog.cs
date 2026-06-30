using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Shows the folder-neighbors view for a flagged file: already-scanned siblings (with
/// verdicts) and a one-click scan of the never-scanned ones.</summary>
internal sealed class NeighborsDialog : Form
{
    public NeighborsDialog(NeighborsService.FolderNeighbors data, Action<string[]> scanRest)
    {
        Text = Strings.DlgNeighborsTitle;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(820, 460);
        MinimumSize = new Size(560, 320);

        var header = new Label
        {
            Dock = DockStyle.Top,
            Height = 40,
            Padding = new Padding(10, 10, 10, 0),
            Text = string.Format(Strings.NeighborsHeaderFormat, data.Folder, data.Cached.Count, data.NeverScanned.Count),
        };

        var grid = new EntityGridView
        {
            Dock = DockStyle.Fill,
            AutoGenerateColumns = false,
            AllowUserToAddRows = false,
            ReadOnly = true,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        };
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColFile, DataPropertyName = nameof(NeighborsService.Neighbor.Path), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColVerdict, DataPropertyName = nameof(NeighborsService.Neighbor.Verdict), Width = 110 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColDetections, DataPropertyName = nameof(NeighborsService.Neighbor.Detections), Width = 70 });
        grid.DataSource = data.Cached;
        grid.CellFormatting += (_, e) =>
        {
            if (grid.Rows[e.RowIndex].DataBoundItem is NeighborsService.Neighbor n && n.Detections > 0)
                e.CellStyle!.ForeColor = Theme.Current.Danger;
        };

        var scanBtn = new Button
        {
            Text = data.NeverScanned.Count > 0 ? string.Format(Strings.NeighborsScanRestFormat, data.NeverScanned.Count) : Strings.NeighborsNoNew,
            Dock = DockStyle.Right,
            Width = 220,
            Enabled = data.NeverScanned.Count > 0,
        };
        scanBtn.Click += (_, _) => { scanRest(data.NeverScanned.ToArray()); DialogResult = DialogResult.OK; };
        var close = new Button { Text = Strings.BtnClose, DialogResult = DialogResult.Cancel, Dock = DockStyle.Right, Width = 100 };
        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(10, 7, 10, 7) };
        bottom.Controls.Add(close);
        bottom.Controls.Add(scanBtn);

        Controls.Add(grid);
        Controls.Add(header);
        Controls.Add(bottom);
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleGrid(grid);
        EntityGrid.Standardize<NeighborsService.Neighbor>(grid,
        [
            new(Strings.MenuCopyFilePath, n => n.Path),
            new(Strings.ColVerdict, n => n.Verdict),
        ],
        [
            new(Strings.MenuRevealFile, t => { foreach (var n in t) if (File.Exists(n.Path)) RevealInExplorer(n.Path); },
                enabled: t => t.Any(n => File.Exists(n.Path))),
        ]);
        ThemeManager.StyleButton(scanBtn);
        ThemeManager.StyleButton(close);
    }
}
