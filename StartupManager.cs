using Microsoft.Win32;

namespace VirusTotalScanner;

/// <summary>
/// "Start with Windows": adds/removes an HKCU Run entry (no admin) that launches the app at
/// login with --tray (hidden, only the tray icon shows). Re-syncs the stored path if the exe moves.
/// </summary>
internal static class StartupManager
{
    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string ValueName = "VirusTotalScanner";
    static string Command => $"\"{AppConstants.ThisExePath}\" --tray";

    public static bool IsEnabled()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(RunKey);
            return k?.GetValue(ValueName) as string is { Length: > 0 };
        }
        catch { return false; }
    }

    public static void SetEnabled(bool on)
    {
        try
        {
            using var k = Registry.CurrentUser.CreateSubKey(RunKey, writable: true)!;
            if (on) k.SetValue(ValueName, Command);
            else k.DeleteValue(ValueName, throwOnMissingValue: false);

            Settings.StartWithWindows.Value = on;
            SettingsManager.SaveSettings();
            Log("Start-with-Windows " + (on ? "enabled" : "disabled"), LogLevel.Info);
        }
        catch (Exception ex) { Log("Startup set failed: " + ex.Message, LogLevel.Error); }
    }

    /// <summary>If enabled, rewrite the Run entry to the current exe path (handles a moved exe).</summary>
    public static void Sync()
    {
        try
        {
            if (!Settings.StartWithWindows) return;
            using var k = Registry.CurrentUser.OpenSubKey(RunKey);
            string? current = k?.GetValue(ValueName) as string;
            if (!string.Equals(current, Command, StringComparison.OrdinalIgnoreCase))
                SetEnabled(true);
        }
        catch (Exception ex) { Log("Startup sync failed: " + ex.Message, LogLevel.Warning); }
    }
}
