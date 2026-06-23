using System.Diagnostics;
using Microsoft.Win32;

namespace VirusTotalScanner;

internal enum MenuState { Ok, Missing, Stale, Error }

/// <summary>
/// Installs/verifies/repairs/removes the Explorer right-click entries under
/// HKLM\Software\Classes (machine-wide, for all users). Writing HKLM needs admin, so
/// Install/Repair/Uninstall self-elevate via UAC (AdminHelper). On Windows 11 classic verbs
/// appear under "Daha fazla seçenek göster"; reaching the top-level menu would need a packaged
/// IExplorerCommand handler (deferred to keep the single-exe model).
///   *\shell\VTScan            -> scan a file (or each file of a multi-selection)
///   Directory\shell\VTScan    -> scan a folder recursively
///   Directory\Background\...   -> scan the current folder recursively
/// </summary>
internal static class ContextMenuInstaller
{
    const string ClassesRoot = @"SOFTWARE\Classes";
    static string FileVerbKey => $@"{ClassesRoot}\*\shell\{AppConstants.MenuVerb}";
    static string DirVerbKey => $@"{ClassesRoot}\Directory\shell\{AppConstants.MenuVerb}";
    static string BgVerbKey => $@"{ClassesRoot}\Directory\Background\shell\{AppConstants.MenuVerb}";

    static string Exe => AppConstants.ThisExePath;

    public static bool Install(bool excludeSafe, out string? error)
    {
        error = null;
        if (!AdminHelper.IsRunningAsAdmin())
        {
            if (!RunElevated("--install")) { error = "Yönetici izni verilmedi."; return false; }
            return Verify() == MenuState.Ok;
        }

        try
        {
            string appliesTo = excludeSafe ? BuildAppliesTo() : "";
            WriteVerb(FileVerbKey, $"\"{Exe}\" --scan \"%1\"", appliesTo);
            WriteVerb(DirVerbKey, $"\"{Exe}\" --scan --recurse \"%1\"", "");
            WriteVerb(BgVerbKey, $"\"{Exe}\" --scan --recurse \"%V\"", "");

            Settings.ContextMenuInstalled.Value = true;
            Settings.ContextMenuExcludeSafe.Value = excludeSafe;
            SettingsManager.SaveSettings();
            Log("Context menu installed (HKLM) for: " + Exe, LogLevel.Info);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            Log("Context menu install failed: " + ex, LogLevel.Error);
            return false;
        }
    }

    public static bool Repair(out string? error)
    {
        error = null;
        if (!AdminHelper.IsRunningAsAdmin())
        {
            if (!RunElevated("--repair")) { error = "Yönetici izni verilmedi."; return false; }
            return Verify() == MenuState.Ok;
        }
        return Install(Settings.ContextMenuExcludeSafe, out error);
    }

    public static bool Uninstall(out string? error)
    {
        error = null;
        if (!AdminHelper.IsRunningAsAdmin())
        {
            if (!RunElevated("--uninstall")) { error = "Yönetici izni verilmedi."; return false; }
            return Verify() == MenuState.Missing;
        }

        try
        {
            DeleteTree(FileVerbKey);
            DeleteTree(DirVerbKey);
            DeleteTree(BgVerbKey);
            Settings.ContextMenuInstalled.Value = false;
            SettingsManager.SaveSettings();
            Log("Context menu removed (HKLM).", LogLevel.Info);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            Log("Context menu uninstall failed: " + ex, LogLevel.Error);
            return false;
        }
    }

    public static MenuState Verify()
    {
        try
        {
            string? f = ReadCommand(FileVerbKey);
            string? d = ReadCommand(DirVerbKey);
            string? b = ReadCommand(BgVerbKey);

            if (f == null && d == null && b == null) return MenuState.Missing;
            if (f == null || d == null || b == null) return MenuState.Stale;

            string exe = Norm(Exe);
            bool allMatch = Norm(ExtractExe(f)) == exe && Norm(ExtractExe(d)) == exe && Norm(ExtractExe(b)) == exe;
            return allMatch ? MenuState.Ok : MenuState.Stale;
        }
        catch (Exception ex)
        {
            Log("Context menu verify failed: " + ex, LogLevel.Warning);
            return MenuState.Error;
        }
    }

    public static string Describe(MenuState s) => s switch
    {
        MenuState.Ok => "Kurulu ✓ (tüm kullanıcılar)",
        MenuState.Missing => "Kurulu değil",
        MenuState.Stale => "Eski yol — onarım gerekli",
        _ => "Durum okunamadı",
    };

    public static bool NeedsRepair() => Settings.ContextMenuInstalled && Verify() == MenuState.Stale;

    // ---- internals ----

    static bool RunElevated(string arg)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = AppConstants.ThisExePath,
                UseShellExecute = true,
                Verb = "runas",
                Arguments = arg,
            };
            var p = Process.Start(psi);
            if (p == null) return false;
            p.WaitForExit();
            return p.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception) { Log("Elevation cancelled by user.", LogLevel.Warning); return false; }
        catch (Exception ex) { Log("Elevation failed: " + ex.Message, LogLevel.Error); return false; }
    }

    static void WriteVerb(string keyPath, string command, string appliesTo)
    {
        using var shell = Registry.LocalMachine.CreateSubKey(keyPath, writable: true)
            ?? throw new InvalidOperationException("Cannot create registry key: " + keyPath);
        shell.SetValue("", AppConstants.MenuText);
        shell.SetValue("Icon", $"\"{Exe}\",0");
        shell.SetValue("Position", "Top");
        if (!string.IsNullOrEmpty(appliesTo)) shell.SetValue("AppliesTo", appliesTo);
        else shell.DeleteValue("AppliesTo", throwOnMissingValue: false);

        using var cmd = shell.CreateSubKey("command", writable: true)
            ?? throw new InvalidOperationException("Cannot create command key under: " + keyPath);
        cmd.SetValue("", command);
    }

    static string? ReadCommand(string verbKeyPath)
    {
        using var cmd = Registry.LocalMachine.OpenSubKey(verbKeyPath + @"\command");
        return cmd?.GetValue("") as string;
    }

    static void DeleteTree(string keyPath)
    {
        try { Registry.LocalMachine.DeleteSubKeyTree(keyPath, throwOnMissingSubKey: false); }
        catch (Exception ex) { Log("Registry delete failed (" + keyPath + "): " + ex.Message, LogLevel.Warning); }
    }

    static string ExtractExe(string command)
    {
        command = command.Trim();
        if (command.StartsWith('"'))
        {
            int end = command.IndexOf('"', 1);
            if (end > 1) return command[1..end];
        }
        int space = command.IndexOf(' ');
        return space > 0 ? command[..space] : command;
    }

    static string Norm(string path)
    {
        try { return Path.GetFullPath(path).TrimEnd('\\').ToLowerInvariant(); }
        catch { return (path ?? "").ToLowerInvariant(); }
    }

    static string BuildAppliesTo()
    {
        var exts = SelectionEnumerator.ParseExtensions(Settings.SafeExtensions);
        if (exts.Count == 0) return "";
        // Hide the verb for safe extensions (best-effort AQS); only applied when the user opts in.
        string ors = string.Join(" OR ", exts.Select(e => $"System.FileExtension:\"{e}\""));
        return $"NOT ({ors})";
    }
}
