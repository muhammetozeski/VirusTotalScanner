using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Lists malware-family clusters from the cache: families that 2+ distinct hashes share,
/// with member counts, the distinct paths they were seen at, and detection range.</summary>
internal sealed class FamilyClusterDialog : Form
{
    sealed class Row
    {
        public string Family { get; init; } = "";
        public int Members { get; init; }
        public int Locations { get; init; }
        public string Detections { get; init; } = "";
        public string FirstSeen { get; init; } = "";
        public string Paths { get; init; } = "";
    }

    public FamilyClusterDialog(List<FamilyClusterService.Cluster> clusters)
    {
        Text = "🧬 Aile kümeleri";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(860, 480);
        MinimumSize = new Size(620, 340);

        var rows = clusters.Select(c => new Row
        {
            Family = c.Family,
            Members = c.Members,
            Locations = c.Paths.Count,
            Detections = c.MinDetections == c.MaxDetections ? $"{c.MinDetections}" : $"{c.MinDetections}–{c.MaxDetections}",
            FirstSeen = c.FirstSeen.HasValue ? c.FirstSeen.Value.ToString("yyyy-MM-dd") : "-",
            Paths = string.Join("  |  ", c.Paths.Take(4)) + (c.Paths.Count > 4 ? $"  (+{c.Paths.Count - 4})" : ""),
        }).ToList();

        var header = new Label
        {
            Dock = DockStyle.Top,
            Height = 32,
            Padding = new Padding(10, 9, 10, 0),
            Text = rows.Count == 0
                ? "Aynı aileyi paylaşan 2+ farklı hash yok (önbellekte tekrar eden bir aile bulunmadı)."
                : $"{rows.Count} aile kümesi — aynı zararlı ailesini paylaşan farklı dosyalar.",
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
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Aile", DataPropertyName = nameof(Row.Family), Width = 130 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Üye", DataPropertyName = nameof(Row.Members), Width = 55 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Konum", DataPropertyName = nameof(Row.Locations), Width = 60 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Tespit", DataPropertyName = nameof(Row.Detections), Width = 70 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "İlk görülme", DataPropertyName = nameof(Row.FirstSeen), Width = 100 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Yollar", DataPropertyName = nameof(Row.Paths), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        grid.DataSource = rows;

        var close = new Button { Text = "Kapat", DialogResult = DialogResult.OK, Dock = DockStyle.Right, Width = 100 };
        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 44, Padding = new Padding(10, 6, 10, 6) };
        bottom.Controls.Add(close);

        Controls.Add(grid);
        Controls.Add(header);
        Controls.Add(bottom);
        AcceptButton = close;
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleGrid(grid);
        ThemeManager.StyleButton(close);
    }
}
