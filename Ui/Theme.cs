using System.Drawing;

namespace VirusTotalScanner;

/// <summary>A colour palette for the UI (dark or light variant).</summary>
internal sealed class Palette
{
    public required Color Background { get; init; }
    public required Color Panel { get; init; }
    public required Color Surface { get; init; }
    public required Color Border { get; init; }
    public required Color Text { get; init; }
    public required Color SubtleText { get; init; }
    public required Color Accent { get; init; }
    public required Color AccentText { get; init; }
    public required Color Success { get; init; }
    public required Color Warning { get; init; }
    public required Color Danger { get; init; }
    public required Color GridHeader { get; init; }
    public required Color GridSelection { get; init; }
    public bool IsDark { get; init; }

    public static readonly Palette Dark = new()
    {
        IsDark = true,
        Background = Color.FromArgb(0x1E, 0x1E, 0x22),
        Panel = Color.FromArgb(0x26, 0x26, 0x2B),
        Surface = Color.FromArgb(0x2D, 0x2D, 0x33),
        Border = Color.FromArgb(0x3A, 0x3A, 0x42),
        Text = Color.FromArgb(0xE6, 0xE6, 0xEA),
        SubtleText = Color.FromArgb(0x9A, 0x9A, 0xA6),
        Accent = Color.FromArgb(0x4C, 0x8B, 0xF5),
        AccentText = Color.White,
        Success = Color.FromArgb(0x3F, 0xB9, 0x50),
        Warning = Color.FromArgb(0xE3, 0xB3, 0x41),
        Danger = Color.FromArgb(0xF8, 0x51, 0x49),
        GridHeader = Color.FromArgb(0x32, 0x32, 0x3A),
        GridSelection = Color.FromArgb(0x33, 0x44, 0x66),
    };

    public static readonly Palette Light = new()
    {
        IsDark = false,
        Background = Color.FromArgb(0xF4, 0xF5, 0xF8),
        Panel = Color.White,
        Surface = Color.White,
        Border = Color.FromArgb(0xD3, 0xD7, 0xDE),
        Text = Color.FromArgb(0x1B, 0x1F, 0x24),
        SubtleText = Color.FromArgb(0x5C, 0x63, 0x6E),
        Accent = Color.FromArgb(0x2F, 0x6F, 0xED),
        AccentText = Color.White,
        Success = Color.FromArgb(0x1A, 0x7F, 0x37),
        Warning = Color.FromArgb(0x9A, 0x6B, 0x00),
        Danger = Color.FromArgb(0xCF, 0x22, 0x2E),
        GridHeader = Color.FromArgb(0xEE, 0xF0, 0xF3),
        GridSelection = Color.FromArgb(0xD6, 0xE4, 0xFF),
    };
}

internal static class Theme
{
    public static Palette Current { get; private set; } = Palette.Dark;

    public static event Action? Changed;

    /// <summary>Resolves the palette from settings (explicit or follow-Windows) and applies it.</summary>
    public static void ApplyFromSettings()
    {
        bool dark = Settings.FollowWindowsTheme ? IsWindowsDark() :
            string.Equals(Settings.Theme.Value, "Dark", StringComparison.OrdinalIgnoreCase);
        Current = dark ? Palette.Dark : Palette.Light;
        try { Changed?.Invoke(); } catch (Exception ex) { Log("Theme Changed handler failed: " + ex.Message, LogLevel.Warning); }
    }

    public static void SetTheme(string name, bool follow)
    {
        Settings.FollowWindowsTheme.Value = follow;
        Settings.Theme.Value = name;
        SettingsManager.SaveSettings();
        ApplyFromSettings();
    }

    public static bool IsWindowsDark()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            object? v = k?.GetValue("AppsUseLightTheme");
            if (v is int i) return i == 0;
        }
        catch { }
        return true;
    }

    public static Color VerdictColor(string verdict)
    {
        if (verdict == Strings.VerdictSigned) return Current.Accent; // trusted-skip: neutral, NOT the green "clean"
        var cat = VerdictCategories.ByName(verdict);
        return cat?.Color ?? Current.SubtleText;
    }
}
