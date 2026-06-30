using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Chronological triage view: which executables landed on disk, grouped by day, with the few
/// known-bad ones highlighted next to whatever arrived alongside them. Reads the local cache only.</summary>
internal sealed class IncidentTimelineDialog : Form
{
    readonly ComboBox _window = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 150 };
    readonly Button _scan;
    readonly Label _status = new() { AutoSize = true, Margin = new Padding(8, 8, 0, 0) };
    readonly DataGridView _days = new EntityGridView();
    readonly DataGridView _files = new EntityGridView();
    CancellationTokenSource? _cts;

    static readonly int[] WindowDays = [30, 60, 90, 180];

    public IncidentTimelineDialog()
    {
        Text = Strings.DlgIncidentTimelineTitle;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(920, 560);
        MinimumSize = new Size(680, 400);

        foreach (var d in WindowDays) _window.Items.Add(string.Format(Strings.IncidentWindowItemFormat, d));
        _window.SelectedIndex = 1; // 60 days

        _scan = ThemeManager.MakeButton(Strings.BtnIncidentScan, (_, _) => _ = RunAsync(), accent: true);
        var close = new Button { Text = Strings.BtnClose, DialogResult = DialogResult.Cancel, Width = 90 };

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(8, 8, 8, 4) };
        top.Controls.Add(new Label { Text = Strings.IncidentWindowLabel, AutoSize = true, Margin = new Padding(0, 8, 6, 0) });
        top.Controls.Add(_window);
        top.Controls.Add(_scan);
        top.Controls.Add(_status);

        BuildDaysGrid();
        BuildFilesGrid();

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 200 };
        split.Panel1.Controls.Add(_days);
        split.Panel2.Controls.Add(_files);

        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 44, Padding = new Padding(10, 6, 10, 6) };
        close.Dock = DockStyle.Right;
        bottom.Controls.Add(close);

        Controls.Add(split);
        Controls.Add(top);
        Controls.Add(bottom);
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleGrid(_days);
        ThemeManager.StyleGrid(_files);
        EntityGrid.Standardize<TimelineFile>(_files,
        [
            new(Strings.MenuCopyFilePath, f => f.Path),
            new(Strings.MenuCopyFileName, f => f.Name),
        ],
        [
            new(Strings.MenuRevealFile, files => RevealFiles(files),
                enabled: t => t.Any(f => File.Exists(f.Path))),
        ]);
        ThemeManager.StyleButton(_scan);
        ThemeManager.StyleButton(close);

        Shown += (_, _) => _ = RunAsync();
        FormClosed += (_, _) => _cts?.Cancel();
    }

    void BuildDaysGrid()
    {
        _days.Dock = DockStyle.Fill;
        _days.AutoGenerateColumns = false;
        _days.AllowUserToAddRows = false;
        _days.ReadOnly = true;
        _days.RowHeadersVisible = false;
        _days.MultiSelect = false;
        _days.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _days.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColDay, DataPropertyName = nameof(TimelineDay.DayText), Width = 160 });
        AddNum(_days, Strings.ColFile, nameof(TimelineDay.Count));
        AddNum(_days, Strings.ColThreat, nameof(TimelineDay.Threats));
        AddNum(_days, Strings.ColFromInternet, nameof(TimelineDay.FromNet), 90);
        _days.SelectionChanged += (_, _) => ShowSelectedDay();
        _days.CellFormatting += (_, e) =>
        {
            if (_days.Rows[e.RowIndex].DataBoundItem is TimelineDay d && d.Threats > 0)
                e.CellStyle!.ForeColor = Theme.Current.Danger;
        };
    }

    void BuildFilesGrid()
    {
        _files.Dock = DockStyle.Fill;
        _files.AutoGenerateColumns = false;
        _files.AllowUserToAddRows = false;
        _files.ReadOnly = true;
        _files.RowHeadersVisible = false;
        _files.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _files.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColTime, DataPropertyName = nameof(TimelineFile.ArrivalLocal), Width = 130, DefaultCellStyle = new DataGridViewCellStyle { Format = "HH:mm:ss" } });
        _files.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColFile, DataPropertyName = nameof(TimelineFile.Name), Width = 200 });
        _files.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColVerdict, DataPropertyName = nameof(TimelineFile.Verdict), Width = 90 });
        AddNum(_files, Strings.ColDetections, nameof(TimelineFile.Detections), 60);
        _files.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColDownloadSource, DataPropertyName = nameof(TimelineFile.Host), Width = 180 });
        _files.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColPath, DataPropertyName = nameof(TimelineFile.Path), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _files.CellFormatting += (_, e) =>
        {
            if (_files.Rows[e.RowIndex].DataBoundItem is not TimelineFile f) return;
            string prop = e.ColumnIndex >= 0 ? _files.Columns[e.ColumnIndex].DataPropertyName : "";
            if (f.Detections > 0) e.CellStyle!.ForeColor = Theme.Current.Danger;
            else if (prop == nameof(TimelineFile.Detections) && !f.Known) e.Value = "—";
        };
        _files.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0 && _files.Rows[e.RowIndex].DataBoundItem is TimelineFile f && File.Exists(f.Path))
                try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + f.Path + "\""); } catch { }
        };
    }

    static void AddNum(DataGridView g, string header, string prop, int width = 70) =>
        g.Columns.Add(new DataGridViewTextBoxColumn
        {
            HeaderText = header,
            DataPropertyName = prop,
            Width = width,
            DefaultCellStyle = new DataGridViewCellStyle { Alignment = DataGridViewContentAlignment.MiddleRight },
        });

    async Task RunAsync()
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        int days = WindowDays[_window.SelectedIndex];

        _scan.Enabled = false;
        _window.Enabled = false;
        _days.DataSource = null;
        _files.DataSource = null;
        _status.Text = Strings.IncidentScanning;

        try
        {
            var result = await IncidentTimelineService.BuildAsync(
                AppServices.Cache, days,
                (d, t) => { try { BeginInvoke(() => _status.Text = string.Format(Strings.IncidentScanningProgressFormat, d, t)); } catch { } },
                ct);
            if (ct.IsCancellationRequested) return;

            _days.DataSource = result;
            int totalFiles = result.Sum(d => d.Count);
            int totalThreats = result.Sum(d => d.Threats);
            _status.Text = string.Format(Strings.IncidentSummaryFormat, result.Count, totalFiles, totalThreats);
            if (result.Count > 0) { _days.ClearSelection(); _days.Rows[0].Selected = true; ShowSelectedDay(); }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _status.Text = Strings.ApiKeyErrorPrefix + ex.Message;
            Log("Incident timeline failed: " + ex, LogLevel.Warning);
        }
        finally { _scan.Enabled = true; _window.Enabled = true; }
    }

    void ShowSelectedDay()
    {
        _files.DataSource = (_days.CurrentRow?.DataBoundItem as TimelineDay)?.Files;
    }

    static void RevealFiles(IReadOnlyList<TimelineFile> files)
    {
        foreach (var f in files)
            if (File.Exists(f.Path)) RevealInExplorer(f.Path);
    }
}
