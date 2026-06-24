using System.Drawing;

namespace VirusTotalScanner;

/// <summary>"Sonradan tehdit oldu mu?" — re-queries every once-cleared file still on disk and lists the
/// ones VirusTotal now flags, with their old→new ratio and where they still live.</summary>
internal sealed class HistoryReverdictDialog : Form
{
    readonly Button _rescan;
    readonly Label _status = new() { AutoSize = true, Margin = new Padding(8, 8, 0, 0) };
    readonly DataGridView _grid = new();
    CancellationTokenSource? _cts;
    List<ReverdictEscalation> _items = [];

    /// <summary>Raised to re-scan the given paths (wired by the host to the scan tab).</summary>
    public event Action<string[]>? ScanRequested;

    public HistoryReverdictDialog()
    {
        Text = "⚠ Sonradan tehdit oldu mu?";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(880, 500);
        MinimumSize = new Size(640, 360);

        var refreshBtn = ThemeManager.MakeButton("🔄  Yeniden denetle", (_, _) => _ = RunAsync(), accent: true);
        _rescan = ThemeManager.MakeButton("🔁  Seçileni yeniden tara", (_, _) =>
        {
            var paths = SelectedPaths();
            if (paths.Length == 0) { _status.Text = "Diskte bulunan bir satır seç."; return; }
            ScanRequested?.Invoke(paths);
            Close();
        });
        var reveal = ThemeManager.MakeButton("📁  Konumu aç", (_, _) =>
        {
            if (_grid.CurrentRow?.DataBoundItem is ReverdictEscalation e && !string.IsNullOrEmpty(e.Path) && File.Exists(e.Path))
                try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + e.Path + "\""); } catch { }
        });
        var close = new Button { Text = "Kapat", DialogResult = DialogResult.Cancel, Width = 90 };

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(8, 8, 8, 4) };
        top.Controls.Add(refreshBtn);
        top.Controls.Add(_rescan);
        top.Controls.Add(reveal);
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
        ThemeManager.StyleButton(_rescan);
        ThemeManager.StyleButton(reveal);
        ThemeManager.StyleButton(close);

        Shown += (_, _) => _ = RunAsync();
        FormClosed += (_, _) => _cts?.Cancel();
    }

    string[] SelectedPaths() =>
        _grid.SelectedRows.Cast<DataGridViewRow>()
            .Select(r => r.DataBoundItem as ReverdictEscalation)
            .Where(e => e != null && !string.IsNullOrEmpty(e.Path) && File.Exists(e!.Path!))
            .Select(e => e!.Path!).Distinct().ToArray();

    void BuildGrid()
    {
        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.AllowUserToAddRows = false;
        _grid.ReadOnly = true;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "İlk tarama", DataPropertyName = nameof(ReverdictEscalation.FirstSeenLocal), Width = 130, DefaultCellStyle = new DataGridViewCellStyle { Format = "yyyy-MM-dd HH:mm" } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Dosya", DataPropertyName = nameof(ReverdictEscalation.Name), Width = 190 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Eskiden", DataPropertyName = nameof(ReverdictEscalation.OldRatio), Width = 80 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Şimdi", DataPropertyName = nameof(ReverdictEscalation.NewRatio), Width = 80 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Konum", DataPropertyName = nameof(ReverdictEscalation.Path), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

        _grid.CellFormatting += (_, e) =>
        {
            if (e.ColumnIndex == 3) e.CellStyle!.ForeColor = Theme.Current.Danger; // "Şimdi" ratio in red
        };
        _grid.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0 && _grid.Rows[e.RowIndex].DataBoundItem is ReverdictEscalation x && !string.IsNullOrEmpty(x.Path) && File.Exists(x.Path))
                try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + x.Path + "\""); } catch { }
        };
    }

    async Task RunAsync()
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;

        if (!(Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable))
        {
            _status.Text = "Anahtarsız (GUI) mod kapalı — bu denetim kotasız yeniden sorgu gerektirir.";
            return;
        }

        _status.Text = "Geçmiş yeniden denetleniyor…";
        _grid.DataSource = null;
        try
        {
            _items = await HistoryReverdictService.CheckAsync(
                (d, t) => { try { BeginInvoke(() => _status.Text = $"Yeniden denetleniyor… {d}/{t}"); } catch { } }, ct);
            if (ct.IsCancellationRequested) return;
            _grid.DataSource = _items;
            _status.Text = _items.Count == 0
                ? "Sonradan tehdide dönüşen, hâlâ diskte olan dosya bulunamadı."
                : $"{_items.Count} dosya bir zamanlar temizdi, şimdi işaretli ve hâlâ diskte.";
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _status.Text = "Hata: " + ex.Message; Log("History re-verdict failed: " + ex, LogLevel.Warning); }
    }
}
