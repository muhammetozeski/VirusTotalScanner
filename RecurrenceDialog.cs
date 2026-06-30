using System.Drawing;

namespace VirusTotalScanner;

/// <summary>"Tekrar eden tehditler" — threats whose same content was flagged across two or more separate
/// scans, answering "I cleared this already, why is it back?". Double-click opens the last location;
/// the rescan button re-checks it (its source may still be live). Local-only.</summary>
internal sealed class RecurrenceDialog : Form
{
    readonly DataGridView _grid = new EntityGridView();
    readonly List<RecurrenceService.Recurrence> _items;

    public event Action<string[]>? ScanRequested;

    public RecurrenceDialog(List<RecurrenceService.Recurrence> items)
    {
        _items = items;
        Text = Strings.DlgRecurrenceTitle;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(880, 480);
        MinimumSize = new Size(640, 340);

        var header = new Label
        {
            Dock = DockStyle.Top,
            Height = 32,
            Padding = new Padding(10, 9, 10, 0),
            Text = items.Count == 0
                ? Strings.RecurrenceNone
                : string.Format(Strings.RecurrenceHeaderFormat, items.Count),
        };

        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.AllowUserToAddRows = false;
        _grid.ReadOnly = true;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColFile, DataPropertyName = nameof(RecurrenceService.Recurrence.Name), Width = 200 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColRecurrenceTimes, DataPropertyName = nameof(RecurrenceService.Recurrence.Events), Width = 55 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColSpan, DataPropertyName = nameof(RecurrenceService.Recurrence.Span), Width = 180 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColLocations, DataPropertyName = nameof(RecurrenceService.Recurrence.Locations), Width = 60 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColPaths, DataPropertyName = nameof(RecurrenceService.Recurrence.PathsText), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _grid.DataSource = items;
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) RevealSelected(); };

        var rescan = ThemeManager.MakeButton(Strings.BtnRescanSelected, (_, _) => RescanSelected());
        var reveal = ThemeManager.MakeButton(Strings.BtnOpenLastLocation, (_, _) => RevealSelected());
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
        EntityGrid.Standardize<RecurrenceService.Recurrence>(_grid,
        [
            new(Strings.ColFile, e => e.Name),
            new(Strings.ColPaths, e => e.PathsText),
            new(Strings.BtnOpenLastLocation, e => e.LastPath),
        ],
        [
            new(Strings.BtnRescanSelected, _ => RescanSelected()),
            new(Strings.BtnOpenLastLocation, _ => RevealSelected()),
        ]);
        ThemeManager.StyleButton(rescan);
        ThemeManager.StyleButton(reveal);
        ThemeManager.StyleButton(close);
    }

    RecurrenceService.Recurrence? Selected() => _grid.CurrentRow?.DataBoundItem as RecurrenceService.Recurrence;

    void RescanSelected()
    {
        if (Selected()?.LastPath is { Length: > 0 } p && File.Exists(p)) { ScanRequested?.Invoke([p]); Close(); }
    }

    void RevealSelected()
    {
        if (Selected()?.LastPath is { Length: > 0 } p && File.Exists(p))
            try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + p + "\""); } catch { }
    }
}
