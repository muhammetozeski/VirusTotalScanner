using System.Diagnostics;

namespace VirusTotalScanner;

/// <summary>
/// "Scheduled sweep": registers a Windows Scheduled Task (via schtasks, no admin / LIMITED run
/// level) that periodically scans a chosen folder headlessly (--cli --recurse) and writes an HTML
/// report next to the exe. The user installs/removes it from settings.
/// </summary>
internal static class SweepScheduler
{
    const string TaskName = "VirusTotalScanner Sweep";

    public static string ReportPath => Path.Combine(ConfigPathResolver.DataFolder, "sweep-report.html");
    public static string ResultPath => Path.Combine(ConfigPathResolver.DataFolder, "sweep-result.json");

    public static bool IsInstalled()
    {
        try { return Run(["/Query", "/TN", TaskName], out _) == 0; }
        catch { return false; }
    }

    /// <summary><paramref name="schedule"/> is the schtasks /SC group, e.g. ["/SC","DAILY","/ST","03:00"].</summary>
    public static bool Install(string folder, string[] schedule, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) { error = "Geçerli bir klasör seçin."; return false; }
        try
        {
            // The whole run command is one argument; ArgumentList escapes the embedded quotes for us.
            string tr = $"\"{AppConstants.ThisExePath}\" --cli --recurse --quiet --report \"{ReportPath}\" --sweep-result \"{ResultPath}\" \"{folder}\"";
            var args = new List<string> { "/Create", "/TN", TaskName };
            args.AddRange(schedule);
            args.AddRange(["/TR", tr, "/F", "/RL", "LIMITED"]);

            int code = Run([.. args], out string output);
            if (code != 0) { error = string.IsNullOrWhiteSpace(output) ? $"schtasks çıkış kodu {code}" : output.Trim(); return false; }

            Settings.SweepFolder.Value = folder;
            SettingsManager.SaveSettings();
            Log("Scheduled sweep installed for: " + folder, LogLevel.Info);
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    public static bool Uninstall(out string? error)
    {
        error = null;
        try
        {
            int code = Run(["/Delete", "/TN", TaskName, "/F"], out string o);
            if (code != 0) { error = o.Trim(); return false; }
            Log("Scheduled sweep removed.", LogLevel.Info);
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    public static bool RunNow(out string? error)
    {
        error = null;
        try { int code = Run(["/Run", "/TN", TaskName], out string o); if (code != 0) { error = o.Trim(); return false; } return true; }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    static int Run(string[] args, out string output)
    {
        using var p = new Process();
        p.StartInfo.FileName = "schtasks.exe";
        foreach (var a in args) p.StartInfo.ArgumentList.Add(a);
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardError = true;
        p.StartInfo.CreateNoWindow = true;
        p.Start();
        output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(15000);
        return p.ExitCode;
    }
}
