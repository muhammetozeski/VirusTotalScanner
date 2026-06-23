using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Applies the current <see cref="Theme"/> palette recursively to a control tree,
/// and provides small styled-control factories used across the GUI.</summary>
internal static class ThemeManager
{
    public static void Apply(Control root)
    {
        var p = Theme.Current;
        ApplyRecursive(root, p);
    }

    static void ApplyRecursive(Control c, Palette p)
    {
        switch (c)
        {
            case DataGridView grid:
                StyleGrid(grid);
                break;
            case Button btn:
                StyleButton(btn, accent: btn.Tag as string == "accent");
                break;
            case TextBox tb:
                tb.BackColor = p.Surface; tb.ForeColor = p.Text; tb.BorderStyle = BorderStyle.FixedSingle;
                break;
            case NumericUpDown nud:
                nud.BackColor = p.Surface; nud.ForeColor = p.Text; nud.BorderStyle = BorderStyle.FixedSingle;
                break;
            case ComboBox cb:
                cb.BackColor = p.Surface; cb.ForeColor = p.Text; cb.FlatStyle = FlatStyle.Flat;
                break;
            case CheckBox chk:
                chk.ForeColor = p.Text; chk.BackColor = Color.Transparent;
                break;
            case RadioButton rb:
                rb.ForeColor = p.Text; rb.BackColor = Color.Transparent;
                break;
            case LinkLabel link:
                link.LinkColor = p.Accent; link.ActiveLinkColor = p.Accent; link.VisitedLinkColor = p.Accent;
                link.BackColor = Color.Transparent;
                break;
            case Label lbl:
                lbl.ForeColor = lbl.Tag as string == "subtle" ? p.SubtleText : p.Text;
                lbl.BackColor = Color.Transparent;
                break;
            case RichTextBox rtb:
                rtb.BackColor = p.Surface; rtb.ForeColor = p.Text; rtb.BorderStyle = BorderStyle.None;
                break;
            case ListView lv:
                lv.BackColor = p.Surface; lv.ForeColor = p.Text;
                break;
            case TabControl:
            case Panel: // also covers FlowLayoutPanel / TableLayoutPanel / MeterBar
            case SplitContainer:
            case UserControl:
            case Form:
                c.ForeColor = p.Text;
                if (c.Tag as string == "card") c.BackColor = p.Panel;
                else if (c.Tag as string == "surface") c.BackColor = p.Surface;
                else c.BackColor = p.Background;
                break;
            default:
                c.ForeColor = p.Text;
                break;
        }

        if (c is SplitContainer sc)
        {
            ApplyRecursive(sc.Panel1, p);
            ApplyRecursive(sc.Panel2, p);
        }
        else
        {
            foreach (Control child in c.Controls)
                ApplyRecursive(child, p);
        }
    }

    public static void StyleButton(Button b, bool accent = false)
    {
        var p = Theme.Current;
        b.FlatStyle = FlatStyle.Flat;
        b.FlatAppearance.BorderSize = 1;
        b.UseVisualStyleBackColor = false;
        b.Cursor = Cursors.Hand;
        if (accent)
        {
            b.BackColor = p.Accent;
            b.ForeColor = p.AccentText;
            b.FlatAppearance.BorderColor = p.Accent;
            b.FlatAppearance.MouseOverBackColor = ControlPaint.Light(p.Accent, 0.1f);
        }
        else
        {
            b.BackColor = p.Surface;
            b.ForeColor = p.Text;
            b.FlatAppearance.BorderColor = p.Border;
            b.FlatAppearance.MouseOverBackColor = ControlPaint.Light(p.Surface, 0.2f);
        }
    }

    public static void StyleGrid(DataGridView g)
    {
        var p = Theme.Current;
        g.EnableHeadersVisualStyles = false;
        g.BackgroundColor = p.Surface;
        g.GridColor = p.Border;
        g.BorderStyle = BorderStyle.None;
        g.DefaultCellStyle.BackColor = p.Surface;
        g.DefaultCellStyle.ForeColor = p.Text;
        g.DefaultCellStyle.SelectionBackColor = p.GridSelection;
        g.DefaultCellStyle.SelectionForeColor = p.Text;
        g.ColumnHeadersDefaultCellStyle.BackColor = p.GridHeader;
        g.ColumnHeadersDefaultCellStyle.ForeColor = p.Text;
        g.ColumnHeadersDefaultCellStyle.SelectionBackColor = p.GridHeader;
        g.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.Single;
        g.RowHeadersVisible = false;
        g.AllowUserToAddRows = false;
        g.AllowUserToDeleteRows = false;
        g.ReadOnly = true;
        g.AllowUserToResizeRows = false;
        g.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        g.MultiSelect = false;
        g.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None;
        g.RowTemplate.Height = 26;
        g.ColumnHeadersHeight = 30;
        g.AlternatingRowsDefaultCellStyle.BackColor = p.IsDark
            ? ControlPaint.Light(p.Surface, 0.04f)
            : ControlPaint.Dark(p.Surface, 0.02f);
    }

    // ---- factories ----

    public static Button MakeButton(string text, EventHandler? onClick = null, bool accent = false)
    {
        var b = new Button
        {
            Text = text,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(10, 6, 10, 6),
            Margin = new Padding(4),
            Tag = accent ? "accent" : null,
        };
        if (onClick != null) b.Click += onClick;
        StyleButton(b, accent);
        return b;
    }

    public static Label MakeTitle(string text, float size = 13f, bool subtle = false) => new()
    {
        Text = text,
        AutoSize = true,
        Font = new Font("Segoe UI", size, FontStyle.Bold),
        Margin = new Padding(4),
        Tag = subtle ? "subtle" : null,
    };

    public static Label MakeLabel(string text, bool subtle = false) => new()
    {
        Text = text,
        AutoSize = true,
        Margin = new Padding(4, 6, 4, 4),
        Tag = subtle ? "subtle" : null,
    };

    public static Panel MakeCard() => new()
    {
        Tag = "card",
        Padding = new Padding(12),
        Margin = new Padding(6),
    };
}
