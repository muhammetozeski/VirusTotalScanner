using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Shows the folder-neighbors view for a flagged file: already-scanned siblings (with
/// verdicts) and a one-click scan of the never-scanned ones.</summary>
internal sealed class NeighborsDialog : Form
{
    public NeighborsDialog(NeighborsService.FolderNeighbors data, Action<string[]> scanRest)
    {
        Text = "📂 Klasör komşuları";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(820, 460);
        MinimumSize = new Size(560, 320);

        var header = new Label
        {
            Dock = DockStyle.Top,
            Height = 40,
            Padding = new Padding(10, 10, 10, 0),
            Text = $"{data.Folder}\n{data.Cached.Count} taranmış komşu • {data.NeverScanned.Count} hiç taranmamış dosya",
        };

        var grid = new DataGridView
        {
            Dock = DockStyle.Fill,
            AutoGenerateColumns = false,
            AllowUserToAddRows = false,
            ReadOnly = true,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        };
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Dosya", DataPropertyName = nameof(NeighborsService.Neighbor.Path), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Verdikt", DataPropertyName = nameof(NeighborsService.Neighbor.Verdict), Width = 110 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Tespit", DataPropertyName = nameof(NeighborsService.Neighbor.Detections), Width = 70 });
        grid.DataSource = data.Cached;
        grid.CellFormatting += (_, e) =>
        {
            if (grid.Rows[e.RowIndex].DataBoundItem is NeighborsService.Neighbor n && n.Detections > 0)
                e.CellStyle!.ForeColor = Theme.Current.Danger;
        };

        var scanBtn = new Button
        {
            Text = data.NeverScanned.Count > 0 ? $"🔎  Kalanları tara ({data.NeverScanned.Count})" : "Taranacak yeni dosya yok",
            Dock = DockStyle.Right,
            Width = 220,
            Enabled = data.NeverScanned.Count > 0,
        };
        scanBtn.Click += (_, _) => { scanRest(data.NeverScanned.ToArray()); DialogResult = DialogResult.OK; };
        var close = new Button { Text = "Kapat", DialogResult = DialogResult.Cancel, Dock = DockStyle.Right, Width = 100 };
        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(10, 7, 10, 7) };
        bottom.Controls.Add(close);
        bottom.Controls.Add(scanBtn);

        Controls.Add(grid);
        Controls.Add(header);
        Controls.Add(bottom);
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleGrid(grid);
        ThemeManager.StyleButton(scanBtn);
        ThemeManager.StyleButton(close);
    }
}
