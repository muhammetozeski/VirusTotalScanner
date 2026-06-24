using System.Drawing;

namespace VirusTotalScanner;

/// <summary>One searchable action for the command palette.</summary>
internal sealed class CommandRecord
{
    public string Name { get; init; } = "";
    public string Desc { get; init; } = "";
    public Action Run { get; init; } = () => { };
}

/// <summary>
/// A Ctrl+K fuzzy-search overlay listing every action by Turkish name — the discoverability fix for a
/// tool this deep, surfacing buried IR/forensic features that otherwise live in submenus or the CLI.
/// Keyboard-first: type to filter, ↑/↓ to move, Enter to run, Esc/click-away to close.
/// </summary>
internal sealed class CommandPaletteForm : Form
{
    readonly TextBox _search = new();
    readonly ListBox _list = new();
    readonly List<CommandRecord> _all;
    List<CommandRecord> _filtered;

    public CommandPaletteForm(List<CommandRecord> commands)
    {
        _all = commands;
        _filtered = commands;

        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        ClientSize = new Size(540, 420);
        KeyPreview = true;

        var t = Theme.Current;
        _search.Dock = DockStyle.Top;
        _search.Font = new Font("Segoe UI", 13f);
        _search.BorderStyle = BorderStyle.FixedSingle;
        _search.PlaceholderText = "⌘  Komut ara…  (örn. kopya, karantina, drift)";
        _search.TextChanged += (_, _) => Filter();

        _list.Dock = DockStyle.Fill;
        _list.BorderStyle = BorderStyle.None;
        _list.DrawMode = DrawMode.OwnerDrawFixed;
        _list.ItemHeight = 46;
        _list.Font = new Font("Segoe UI", 10f);
        _list.DrawItem += DrawRow;
        _list.DoubleClick += (_, _) => RunSelected();

        Controls.Add(_list);
        Controls.Add(_search);

        _search.KeyDown += OnKey;
        _list.KeyDown += OnKey;

        BackColor = t.Panel;
        _search.BackColor = t.Background;
        _search.ForeColor = t.Text;
        _list.BackColor = t.Panel;
        _list.ForeColor = t.Text;

        Filter();
        Shown += (_, _) => _search.Focus();
        Deactivate += (_, _) => Close(); // click away closes
    }

    void OnKey(object? sender, KeyEventArgs e)
    {
        switch (e.KeyCode)
        {
            case Keys.Escape: Close(); e.Handled = true; break;
            case Keys.Down: MoveSel(1); e.Handled = true; break;
            case Keys.Up: MoveSel(-1); e.Handled = true; break;
            case Keys.Enter: RunSelected(); e.Handled = true; break;
        }
    }

    void MoveSel(int delta)
    {
        if (_list.Items.Count == 0) return;
        int i = Math.Clamp(_list.SelectedIndex + delta, 0, _list.Items.Count - 1);
        _list.SelectedIndex = i;
    }

    void Filter()
    {
        string q = _search.Text.Trim();
        _filtered = q.Length == 0
            ? _all
            : _all.Where(c => Fuzzy(c.Name, q) || c.Desc.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
        _list.BeginUpdate();
        _list.Items.Clear();
        foreach (var c in _filtered) _list.Items.Add(c);
        _list.EndUpdate();
        if (_list.Items.Count > 0) _list.SelectedIndex = 0;
    }

    void RunSelected()
    {
        if (_list.SelectedItem is not CommandRecord c) return;
        Close();
        try { c.Run(); }
        catch (Exception ex) { Log("Command palette action failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Case-insensitive subsequence match, so "krp" finds "Kopyaları bul".</summary>
    static bool Fuzzy(string text, string q)
    {
        text = text.ToLowerInvariant();
        q = q.ToLowerInvariant();
        int ti = 0;
        foreach (char ch in q)
        {
            ti = text.IndexOf(ch, ti);
            if (ti < 0) return false;
            ti++;
        }
        return true;
    }

    void DrawRow(object? sender, DrawItemEventArgs e)
    {
        if (e.Index < 0 || e.Index >= _filtered.Count) return;
        var c = _filtered[e.Index];
        var t = Theme.Current;
        bool sel = (e.State & DrawItemState.Selected) != 0;
        using (var bg = new SolidBrush(sel ? t.Accent : t.Panel)) e.Graphics.FillRectangle(bg, e.Bounds);
        using var nameFont = new Font("Segoe UI", 10.5f, FontStyle.Bold);
        using var descFont = new Font("Segoe UI", 9f);
        using var nameBrush = new SolidBrush(sel ? Color.White : t.Text);
        using var descBrush = new SolidBrush(sel ? Color.FromArgb(230, 230, 230) : t.SubtleText);
        e.Graphics.DrawString(c.Name, nameFont, nameBrush, e.Bounds.X + 12, e.Bounds.Y + 6);
        e.Graphics.DrawString(c.Desc, descFont, descBrush, e.Bounds.X + 12, e.Bounds.Y + 25);
    }
}
