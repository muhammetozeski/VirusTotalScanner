using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Per-folder rollup of a finished scan: each containing folder with its verdict
/// breakdown (threats worst-first), signed-vs-unsigned split, and unknown-to-VT count.</summary>
internal sealed class FolderRollupDialog : Form
{
    sealed class Row
    {
        public string Folder { get; init; } = "";
        public int Files { get; set; }
        public int Threats { get; set; }
        public int Suspicious { get; set; }
        public int Clean { get; set; }
        public int Signed { get; set; }
        public int Unknown { get; set; }
    }

    public FolderRollupDialog(IEnumerable<ScanItem> items)
    {
        Text = "📊 Klasör özeti";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(820, 460);
        MinimumSize = new Size(560, 320);

        var rows = Build(items);
        var total = rows.Aggregate(new Row { Folder = "TOPLAM" }, (acc, r) =>
        {
            acc.Files += r.Files; acc.Threats += r.Threats; acc.Suspicious += r.Suspicious;
            acc.Clean += r.Clean; acc.Signed += r.Signed; acc.Unknown += r.Unknown; return acc;
        });

        var summary = new Label
        {
            Dock = DockStyle.Top,
            AutoSize = false,
            Height = 38,
            Padding = new Padding(10, 10, 10, 0),
            Text = $"{rows.Count} klasör • {total.Files} dosya • {total.Threats} tehdit • {total.Suspicious} şüpheli • " +
                   $"{total.Clean} temiz • {total.Signed} imzalı-atlandı • {total.Unknown} bilinmiyor/hata",
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
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Klasör", DataPropertyName = nameof(Row.Folder), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        AddNum(grid, "Dosya", nameof(Row.Files));
        AddNum(grid, "Tehdit", nameof(Row.Threats));
        AddNum(grid, "Şüpheli", nameof(Row.Suspicious));
        AddNum(grid, "Temiz", nameof(Row.Clean));
        AddNum(grid, "İmzalı", nameof(Row.Signed));
        AddNum(grid, "Bilinmiyor", nameof(Row.Unknown));
        grid.DataSource = rows;

        // Paint folders that contain a threat red, fully-clean folders green-ish.
        grid.CellFormatting += (_, e) =>
        {
            if (grid.Rows[e.RowIndex].DataBoundItem is not Row r) return;
            if (r.Threats > 0) e.CellStyle!.ForeColor = Theme.Current.Danger;
            else if (r.Suspicious > 0) e.CellStyle!.ForeColor = Theme.Current.Warning;
        };

        var close = new Button { Text = "Kapat", DialogResult = DialogResult.OK, Dock = DockStyle.Right, Width = 100 };
        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 44, Padding = new Padding(10, 6, 10, 6) };
        bottom.Controls.Add(close);

        Controls.Add(grid);
        Controls.Add(summary);
        Controls.Add(bottom);
        AcceptButton = close;
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleGrid(grid);
        ThemeManager.StyleButton(close);
    }

    static void AddNum(DataGridView grid, string header, string prop) =>
        grid.Columns.Add(new DataGridViewTextBoxColumn
        {
            HeaderText = header,
            DataPropertyName = prop,
            Width = 80,
            DefaultCellStyle = new DataGridViewCellStyle { Alignment = DataGridViewContentAlignment.MiddleRight },
        });

    static List<Row> Build(IEnumerable<ScanItem> items)
    {
        var map = new Dictionary<string, Row>(StringComparer.OrdinalIgnoreCase);
        foreach (var it in items)
        {
            string folder = SafeDir(it.FilePath);
            if (!map.TryGetValue(folder, out var r)) map[folder] = r = new Row { Folder = folder };
            r.Files++;
            if (it.Status == ScanStatus.TrustedSkipped) r.Signed++;
            else if (it.Report is { } rep && rep.TotalEngines > 0)
            {
                if (rep.IsMalicious) r.Threats++;
                else if (rep.DetectionCount > 0) r.Suspicious++;
                else r.Clean++;
            }
            else r.Unknown++;
        }
        // Worst folders first.
        return map.Values
            .OrderByDescending(r => r.Threats)
            .ThenByDescending(r => r.Suspicious)
            .ThenBy(r => r.Folder, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    static string SafeDir(string path)
    {
        try { return Path.GetDirectoryName(path) ?? path; }
        catch { return path; }
    }
}
