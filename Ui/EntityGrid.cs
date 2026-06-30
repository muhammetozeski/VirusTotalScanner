using System.Drawing;

namespace VirusTotalScanner;

/// <summary>
/// A DataGridView that survives the WinForms quirk behind the central mark column: when a data-bound grid
/// gets its window handle while the bound list is EMPTY and the first visible column is the unbound mark
/// checkbox, <c>OnHandleCreated → MakeFirstDisplayedCellCurrentCell</c> indexes the CurrencyManager at -1
/// and throws <see cref="IndexOutOfRangeException"/> ("Index -1 does not have a value"). The list works
/// fine the moment a row exists; we just swallow that one startup race here.
/// </summary>
internal sealed class EntityGridView : DataGridView
{
    protected override void OnHandleCreated(EventArgs e)
    {
        try { base.OnHandleCreated(e); }
        catch (IndexOutOfRangeException) { /* empty-bound-grid + unbound first column .NET race */ }
    }

    protected override void SetSelectedRowCore(int rowIndex, bool selected)
    {
        try { base.SetSelectedRowCore(rowIndex, selected); }
        catch (IndexOutOfRangeException) { /* same empty/transient currency-manager race */ }
    }
}

/// <summary>One labelled, copyable property of a row entity (file path, SHA-256, VT page, …).
/// Drives the shared right-click "Kopyala" submenu so every list exposes the same identifiers.</summary>
internal sealed class RowProp<T>(string label, Func<T, string?> value)
{
    public string Label { get; } = label;
    public Func<T, string?> Value { get; } = value;
}

/// <summary>A context-menu command over the marked-or-selected rows of a list.</summary>
internal sealed class RowAction<T>(string label, Action<IReadOnlyList<T>> run,
    Func<IReadOnlyList<T>, bool>? enabled = null, bool separatorBefore = false)
{
    public string Label { get; } = label;
    public Action<IReadOnlyList<T>> Run { get; } = run;
    public Func<IReadOnlyList<T>, bool>? Enabled { get; } = enabled;
    public bool SeparatorBefore { get; } = separatorBefore;
}

/// <summary>
/// The single place every list in the app is wired through, so all of them behave identically:
/// real multi-select, a leading "mark" checkbox column, a right-click that first selects the row
/// under the cursor (then opens the menu), and a shared context menu =
/// Kopyala&lt;props&gt; + seçilenleri işaretle/işareti kaldır + list-specific actions.
///
/// This pulls the grids out of the spaghetti where each one re-invented — or silently lost — these
/// behaviours (e.g. <see cref="ThemeManager.StyleGrid"/> was forcing MultiSelect=false on all of them,
/// so bulk selection was dead everywhere).
/// </summary>
internal static class EntityGrid
{
    /// <summary>Column name of the leading "mark" checkbox.</summary>
    public const string MarkColumn = "__mark";

    /// <summary>Wire a configured, data-bound grid into the standard entity-list behaviour. Call this
    /// AFTER <see cref="ThemeManager.StyleGrid"/> (which otherwise overrides MultiSelect/ReadOnly).</summary>
    public static void Standardize<T>(DataGridView grid,
        IReadOnlyList<RowProp<T>> copyProps,
        IReadOnlyList<RowAction<T>>? actions = null,
        bool checkboxes = true) where T : class
    {
        EnableMultiSelect(grid);
        if (checkboxes) AddMarkColumn(grid);
        EnableRightClickSelect(grid);
        grid.ContextMenuStrip = BuildMenu(grid, copyProps, actions ?? [], checkboxes);
    }

    /// <summary>Restore real multi-select (StyleGrid forces it off on every grid).</summary>
    public static void EnableMultiSelect(DataGridView grid)
    {
        grid.MultiSelect = true;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
    }

    /// <summary>Insert the leading mark checkbox column (idempotent). Toggling is handled by us so it
    /// works even though the grid stays globally ReadOnly.</summary>
    public static DataGridViewCheckBoxColumn AddMarkColumn(DataGridView grid)
    {
        if (FindMark(grid) is { } existing) return existing;

        var col = new DataGridViewCheckBoxColumn
        {
            Name = MarkColumn,
            HeaderText = "",
            Width = 30,
            MinimumWidth = 30,
            Resizable = DataGridViewTriState.False,
            SortMode = DataGridViewColumnSortMode.NotSortable,
            ThreeState = false,
            // MUST stay ReadOnly: a non-read-only column makes the (otherwise ReadOnly) grid partially
            // editable, and an editable, data-bound grid with ZERO rows throws IndexOutOfRangeException
            // ("Index -1") from MakeFirstDisplayedCellCurrentCell when its handle is created. We toggle the
            // mark ourselves on click (below), so user editing isn't needed anyway.
            ReadOnly = true,
            DefaultCellStyle = new DataGridViewCellStyle { Alignment = DataGridViewContentAlignment.MiddleCenter },
        };
        grid.Columns.Insert(0, col);

        // Toggle the mark ourselves on a left click of column 0 — programmatic Value sets are NOT blocked
        // by the cell/grid being ReadOnly.
        grid.CellMouseUp += (_, e) =>
        {
            if (e.Button == MouseButtons.Left && e.RowIndex >= 0 && e.ColumnIndex == MarkIndex(grid))
                ToggleMark(grid, e.RowIndex);
        };
        // Click the mark-column header to select / clear all marks at once.
        grid.ColumnHeaderMouseClick += (_, e) =>
        {
            if (e.ColumnIndex == MarkIndex(grid)) SetAllMarks(grid, !AllMarked(grid));
        };
        return col;
    }

    /// <summary>Right-click first selects the row under the cursor (unless it is already part of the
    /// current multi-selection), then the context menu opens on the correct row — fixing the
    /// "previous selection's menu shows up" bug.</summary>
    public static void EnableRightClickSelect(DataGridView grid)
    {
        grid.MouseDown += (_, e) =>
        {
            if (e.Button != MouseButtons.Right) return;
            var hit = grid.HitTest(e.X, e.Y);
            if (hit.RowIndex < 0) return;
            var row = grid.Rows[hit.RowIndex];
            if (row.Selected) return; // keep an existing multi-selection intact
            grid.ClearSelection();
            row.Selected = true;
            int col = hit.ColumnIndex >= 0 && grid.Columns[hit.ColumnIndex].Name != MarkColumn
                ? hit.ColumnIndex
                : FirstDataColumn(grid);
            try { if (col >= 0) grid.CurrentCell = row.Cells[col]; } catch { /* row may be transient */ }
        };
    }

    // ---- selection / mark accessors ----

    /// <summary>Rows whose mark checkbox is ticked.</summary>
    public static List<T> Marked<T>(DataGridView grid) where T : class
    {
        int col = MarkIndex(grid);
        var list = new List<T>();
        if (col < 0) return list;
        foreach (DataGridViewRow r in grid.Rows)
            if (r.DataBoundItem is T t && r.Cells[col].Value is true) list.Add(t);
        return list;
    }

    /// <summary>Currently highlighted rows.</summary>
    public static List<T> Selected<T>(DataGridView grid) where T : class =>
        grid.SelectedRows.Cast<DataGridViewRow>().Select(r => r.DataBoundItem).OfType<T>().ToList();

    /// <summary>The rows an action applies to: marked rows if any, else the highlighted rows,
    /// else the single current row.</summary>
    public static List<T> Targets<T>(DataGridView grid) where T : class
    {
        var marked = Marked<T>(grid);
        if (marked.Count > 0) return marked;
        var sel = Selected<T>(grid);
        if (sel.Count > 0) return sel;
        return grid.CurrentRow?.DataBoundItem is T one ? [one] : [];
    }

    /// <summary>Set the mark on every highlighted row.</summary>
    public static void MarkSelected(DataGridView grid, bool mark)
    {
        int col = MarkIndex(grid);
        if (col < 0) return;
        foreach (DataGridViewRow r in grid.SelectedRows) r.Cells[col].Value = mark;
    }

    public static void SetAllMarks(DataGridView grid, bool mark)
    {
        int col = MarkIndex(grid);
        if (col < 0) return;
        foreach (DataGridViewRow r in grid.Rows) r.Cells[col].Value = mark;
    }

    static bool AllMarked(DataGridView grid)
    {
        int col = MarkIndex(grid);
        if (col < 0 || grid.Rows.Count == 0) return false;
        foreach (DataGridViewRow r in grid.Rows) if (r.Cells[col].Value is not true) return false;
        return true;
    }

    // ---- menu building ----

    static ContextMenuStrip BuildMenu<T>(DataGridView grid,
        IReadOnlyList<RowProp<T>> props, IReadOnlyList<RowAction<T>> actions, bool checkboxes) where T : class
    {
        var menu = new ContextMenuStrip();

        if (props.Count > 0)
        {
            var copy = new ToolStripMenuItem(Strings.MenuCopy);
            foreach (var p in props)
            {
                var prop = p;
                copy.DropDownItems.Add(prop.Label, null, (_, _) => CopyProp(grid, prop));
            }
            menu.Items.Add(copy);
        }

        if (checkboxes)
        {
            if (menu.Items.Count > 0) menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(Strings.MenuMarkSelected, null, (_, _) => MarkSelected(grid, true));
            menu.Items.Add(Strings.MenuUnmarkSelected, null, (_, _) => MarkSelected(grid, false));
        }

        bool firstAction = true;
        foreach (var a in actions)
        {
            var act = a;
            if ((firstAction && menu.Items.Count > 0) || act.SeparatorBefore)
                menu.Items.Add(new ToolStripSeparator());
            firstAction = false;
            var item = (ToolStripMenuItem)menu.Items.Add(act.Label, null, (_, _) => act.Run(Targets<T>(grid)));
            item.Tag = act;
        }

        menu.Opening += (_, e) =>
        {
            var targets = Targets<T>(grid);
            if (targets.Count == 0) { e.Cancel = true; return; }
            foreach (ToolStripItem it in menu.Items)
                if (it is ToolStripMenuItem mi && mi.Tag is RowAction<T> ra && ra.Enabled != null)
                    mi.Enabled = ra.Enabled(targets);
        };
        return menu;
    }

    static void CopyProp<T>(DataGridView grid, RowProp<T> prop) where T : class
    {
        var vals = Targets<T>(grid).Select(prop.Value).Where(s => !string.IsNullOrEmpty(s)).ToList();
        if (vals.Count == 0) return;
        try { Clipboard.SetText(string.Join(Environment.NewLine, vals)); }
        catch (Exception ex) { Log("Clipboard copy failed: " + ex.Message, LogLevel.Warning); }
    }

    // ---- internals ----

    static DataGridViewCheckBoxColumn? FindMark(DataGridView grid)
    {
        foreach (DataGridViewColumn c in grid.Columns)
            if (c.Name == MarkColumn) return c as DataGridViewCheckBoxColumn;
        return null;
    }

    static int MarkIndex(DataGridView grid)
    {
        foreach (DataGridViewColumn c in grid.Columns)
            if (c.Name == MarkColumn) return c.Index;
        return -1;
    }

    static int FirstDataColumn(DataGridView grid)
    {
        foreach (DataGridViewColumn c in grid.Columns)
            if (c.Name != MarkColumn && c.Visible) return c.Index;
        return -1;
    }

    static void ToggleMark(DataGridView grid, int rowIndex)
    {
        int col = MarkIndex(grid);
        if (col < 0) return;
        var cell = grid.Rows[rowIndex].Cells[col];
        cell.Value = cell.Value is not true;
    }
}
