using System.Drawing;

namespace VirusTotalScanner;

/// <summary>
/// A group of action buttons folded behind a single header line ("▸ Araçlar · 8") until the user opens
/// it, so a tab holding twenty verbs shows three lines instead of twenty buttons at once. Which drawers
/// are open is remembered across restarts in <see cref="Settings.OpenDrawers"/>.
///
/// The header line is a full-width row: the fold button takes the left side and
/// <see cref="AddHeaderExtra"/> parks always-visible controls (a toggle, a live status label) on the
/// right, where the header would otherwise be blank space.
/// </summary>
internal sealed class DrawerPanel : FlowLayoutPanel
{
    const char KeySeparator = ';';

    // A TableLayoutPanel, not a plain Panel: the row has to grow to whatever the tallest thing in it
    // needs (a checkbox and a button are taller than the fold button), and a fixed-height Panel simply
    // clipped the drawers underneath it.
    readonly TableLayoutPanel _headerRow = new()
    {
        ColumnCount = 2,
        RowCount = 1,
        AutoSize = true,
        AutoSizeMode = AutoSizeMode.GrowAndShrink,
        Margin = new Padding(0),
        Padding = new Padding(0),
    };
    readonly Button _header;
    readonly FlowLayoutPanel _extras = new()
    {
        Anchor = AnchorStyles.Right,
        AutoSize = true,
        AutoSizeMode = AutoSizeMode.GrowAndShrink,
        WrapContents = false,
        FlowDirection = FlowDirection.LeftToRight,
        Margin = new Padding(0),
        Padding = new Padding(0),
        BackColor = Color.Transparent,
    };
    readonly FlowLayoutPanel _body = new()
    {
        AutoSize = true,
        AutoSizeMode = AutoSizeMode.GrowAndShrink,
        WrapContents = true,
        Margin = new Padding(0),
        Padding = new Padding(0, 0, 0, 4),
        Visible = false,
    };
    readonly string _key;
    readonly string _title;

    public DrawerPanel(string key, string title)
    {
        _key = key;
        _title = title;
        FlowDirection = FlowDirection.TopDown;
        WrapContents = false;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Margin = new Padding(0);

        _header = ThemeManager.MakeButton("", (_, _) => IsOpen = !IsOpen);
        _header.FlatAppearance.BorderSize = 0;
        _header.TextAlign = ContentAlignment.MiddleLeft;
        _header.Dock = DockStyle.Fill;
        _header.Margin = new Padding(0);
        // A stable tooltip key: the caption carries a fold arrow and a live action count, so it is not
        // something a lookup table can be written against.
        _header.AccessibleName = "tt.drawer." + key;

        _headerRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); // fold button takes the rest
        _headerRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));     // extras keep their own width
        _headerRow.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _headerRow.Controls.Add(_header, 0, 0);
        _headerRow.Controls.Add(_extras, 1, 0);

        Controls.Add(_headerRow);
        Controls.Add(_body);
    }

    /// <summary>Adds one action to the drawer. Call before <see cref="RestoreState"/> so the header count
    /// and the remembered open/closed state are applied to the finished drawer.</summary>
    public void Add(Control action) => _body.Controls.Add(action);

    /// <summary>Parks a control on the right-hand side of the header line, visible whether the drawer is
    /// open or closed. Added left-to-right in call order.</summary>
    public void AddHeaderExtra(Control c)
    {
        c.Margin = new Padding(4, 2, 2, 2);
        _extras.Controls.Add(c);
    }

    /// <summary>Applies the remembered open/closed state and paints the header. Separate from the
    /// constructor because the header text carries the action count, known only once all are added.</summary>
    public void RestoreState() => IsOpen = OpenKeys().Contains(_key);

    // Not public: a public property on a Control makes the WinForms designer-serialization analyzer
    // (WFO1000) demand serialization attributes, and nothing outside this class needs to read it.
    bool IsOpen
    {
        get => _body.Visible;
        set
        {
            _body.Visible = value;
            _header.Text = $"{(value ? "▾" : "▸")}  {_title}  ·  {_body.Controls.Count}";
            Remember(value);
        }
    }

    /// <summary>Bounds the wrapping body — and the header row — to the width the drawer actually has,
    /// so its buttons wrap into rows instead of growing one endless line.</summary>
    public void SetAvailableWidth(int width)
    {
        if (width <= 0) return;
        _body.MaximumSize = new Size(width, 0);
        // MinimumSize, not Width: this panel auto-sizes to its content, so a plain Width assignment is
        // thrown away and the header would hug the fold button instead of reaching the right edge.
        _headerRow.MinimumSize = new Size(width, 0);
    }

    static HashSet<string> OpenKeys() =>
        new(Settings.OpenDrawers.Value.Split(KeySeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            StringComparer.OrdinalIgnoreCase);

    void Remember(bool open)
    {
        var keys = OpenKeys();
        if (open ? !keys.Add(_key) : !keys.Remove(_key)) return; // already in the wanted state
        Settings.OpenDrawers.Value = string.Join(KeySeparator, keys);
        SettingsManager.SaveSettings();
    }
}
