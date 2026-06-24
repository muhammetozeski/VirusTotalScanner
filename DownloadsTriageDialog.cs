using System.Drawing;

namespace VirusTotalScanner;

/// <summary>The "İndirilenler" triage view: recent Downloads/Desktop files with origin host, signature
/// and cached verdict, so the user can see what they pulled in lately and scan the unchecked ones.</summary>
internal sealed class DownloadsTriageDialog : Form
{
    readonly ComboBox _window = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 140 };
    readonly Button _scanUnscanned;
    readonly Label _status = new() { AutoSize = true, Margin = new Padding(8, 8, 0, 0) };
    readonly DataGridView _grid = new();
    CancellationTokenSource? _cts;
    List<DownloadItem> _items = [];

    static readonly int[] WindowDays = [7, 30, 90, 365];

    /// <summary>Raised to scan the given paths (wired by the host to the scan tab).</summary>
    public event Action<string[]>? ScanRequested;

    public DownloadsTriageDialog()
    {
        Text = "📥 İndirilenler triyajı";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(900, 520);
        MinimumSize = new Size(640, 360);

        foreach (var d in WindowDays) _window.Items.Add($"Son {d} gün");
        _window.SelectedIndex = 1; // 30 days

        var refreshBtn = ThemeManager.MakeButton("🔄  Yenile", (_, _) => _ = RunAsync(), accent: true);
        _scanUnscanned = ThemeManager.MakeButton("🔎  Taranmamışları tara", (_, _) =>
        {
            var unscanned = _items.Where(i => !i.Scanned && File.Exists(i.Path)).Select(i => i.Path).ToArray();
            if (unscanned.Length == 0) { _status.Text = "Taranmamış dosya yok."; return; }
            ScanRequested?.Invoke(unscanned);
            Close();
        });
        var close = new Button { Text = "Kapat", DialogResult = DialogResult.Cancel, Width = 90 };

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(8, 8, 8, 4) };
        top.Controls.Add(new Label { Text = "Pencere:", AutoSize = true, Margin = new Padding(0, 8, 6, 0) });
        top.Controls.Add(_window);
        top.Controls.Add(refreshBtn);
        top.Controls.Add(_scanUnscanned);
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
        ThemeManager.StyleButton(refreshBtn);
        ThemeManager.StyleButton(_scanUnscanned);
        ThemeManager.StyleButton(close);

        Shown += (_, _) => _ = RunAsync();
        FormClosed += (_, _) => _cts?.Cancel();
    }

    void BuildGrid()
    {
        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.AllowUserToAddRows = false;
        _grid.ReadOnly = true;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Tarih", DataPropertyName = nameof(DownloadItem.ArrivalLocal), Width = 130, DefaultCellStyle = new DataGridViewCellStyle { Format = "yyyy-MM-dd HH:mm" } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Dosya", DataPropertyName = nameof(DownloadItem.Name), Width = 190 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Kaynak (indirme)", DataPropertyName = nameof(DownloadItem.Host), Width = 170 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "İmza", DataPropertyName = nameof(DownloadItem.Signature), Width = 140 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Verdikt", DataPropertyName = nameof(DownloadItem.Verdict), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Yol", DataPropertyName = nameof(DownloadItem.Path), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

        _grid.CellFormatting += (_, e) =>
        {
            if (_grid.Rows[e.RowIndex].DataBoundItem is not DownloadItem d) return;
            if (d.Detections > 0) e.CellStyle!.ForeColor = Theme.Current.Danger;
            else if (e.ColumnIndex == 3 && d.Signature == "imzasız") e.CellStyle!.ForeColor = Theme.Current.Warning;
        };
        _grid.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0 && _grid.Rows[e.RowIndex].DataBoundItem is DownloadItem d && File.Exists(d.Path))
                try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + d.Path + "\""); } catch { }
        };
    }

    async Task RunAsync()
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        int days = WindowDays[_window.SelectedIndex];

        _window.Enabled = false;
        _status.Text = "Taranıyor…";
        _grid.DataSource = null;
        try
        {
            _items = await DownloadsTriageService.BuildAsync(AppServices.Cache, days,
                (d, t) => { try { BeginInvoke(() => _status.Text = $"Taranıyor… {d}/{t}"); } catch { } }, ct);
            if (ct.IsCancellationRequested) return;
            _grid.DataSource = _items;
            int unscanned = _items.Count(i => !i.Scanned);
            int threats = _items.Count(i => i.Detections > 0);
            _status.Text = $"{_items.Count} dosya • {unscanned} taranmamış • {threats} tehdit (önbellekten)";
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _status.Text = "Hata: " + ex.Message; Log("Downloads triage failed: " + ex, LogLevel.Warning); }
        finally { _window.Enabled = true; }
    }
}
