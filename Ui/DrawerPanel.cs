using System.Drawing;

namespace VirusTotalScanner;

/// <summary>
/// A group of action buttons folded behind a single header line ("▸ Araçlar · 8") until the user opens
/// it, so a tab holding twenty verbs shows three lines instead of twenty buttons at once. Which drawers
/// are open is remembered across restarts in <see cref="Settings.OpenDrawers"/>.
/// </summary>
internal sealed class DrawerPanel : FlowLayoutPanel
{
    const char KeySeparator = ';';

    readonly Button _header;
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
        Controls.Add(_header);
        Controls.Add(_body);
    }

    /// <summary>Adds one action to the drawer. Call before <see cref="RestoreState"/> so the header count
    /// and the remembered open/closed state are applied to the finished drawer.</summary>
    public void Add(Control action) => _body.Controls.Add(action);

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

    /// <summary>Bounds the wrapping body to the width the drawer actually has, so its buttons wrap into
    /// rows instead of growing one endless line.</summary>
    public void SetAvailableWidth(int width)
    {
        if (width > 0) _body.MaximumSize = new Size(width, 0);
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
