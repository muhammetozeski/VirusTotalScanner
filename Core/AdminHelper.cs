using System.Diagnostics;
using System.Security.Principal;

namespace VirusTotalScanner;

/// <summary>
/// Windows privilege helpers. Adapted from C:\E\KodlamaProjeleri\CSharp\TPMPass\AdminHelper.cs.
/// The context menu uses HKCU and needs no admin; this is here only for optional flows.
/// </summary>
internal static class AdminHelper
{
    public static bool IsRunningAsAdmin()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>Relaunches elevated (UAC) and exits the current process.</summary>
    public static void RestartAsAdmin(string[]? args = null)
    {
        args ??= [];
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = AppConstants.ThisExePath,
                UseShellExecute = true,
                Verb = "runas",
                Arguments = string.Join(" ", args.Select(a => "\"" + a + "\"")),
            });
        }
        catch (Exception ex)
        {
            Log("Failed to restart as admin: " + ex.Message, LogLevel.Error);
        }
        Environment.Exit(0);
    }
}
