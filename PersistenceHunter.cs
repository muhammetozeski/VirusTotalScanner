using System.Diagnostics;
using Microsoft.Win32;

namespace VirusTotalScanner;

/// <summary>
/// Read-only hunt for autostart hooks that reference a (usually flagged) file: Run/RunOnce keys
/// (HKCU + HKLM + WOW6432Node), the per-user and common Startup folders, and Scheduled Tasks. It
/// matches by full path or bare filename (plus any extra paths from the copy-finder), so a quarantine
/// that leaves a dangling autostart is visible. Listing only — local, zero quota.
/// </summary>
internal static class PersistenceHunter
{
    public sealed record Hook(string Location, string Name, string Command);

    public static List<Hook> Find(string filePath, IEnumerable<string>? alsoMatch = null)
    {
        var needles = new List<string> { filePath, Path.GetFileName(filePath) };
        if (alsoMatch != null) needles.AddRange(alsoMatch);
        needles = needles.Where(n => !string.IsNullOrEmpty(n))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var hooks = new List<Hook>();
        ScanRunKey(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run", needles, hooks);
        ScanRunKey(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce", needles, hooks);
        ScanRunKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run", needles, hooks);
        ScanRunKey(Registry.LocalMachine, @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (WOW64)", needles, hooks);
        ScanStartup(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Başlangıç (kullanıcı)", needles, hooks);
        ScanStartup(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Başlangıç (ortak)", needles, hooks);
        ScanTasks(needles, hooks);
        return hooks;
    }

    static bool Matches(string text, List<string> needles) =>
        !string.IsNullOrEmpty(text) && needles.Any(n => text.Contains(n, StringComparison.OrdinalIgnoreCase));

    static void ScanRunKey(RegistryKey root, string subPath, string label, List<string> needles, List<Hook> hooks)
    {
        try
        {
            using var k = root.OpenSubKey(subPath);
            if (k == null) return;
            foreach (var name in k.GetValueNames())
            {
                string cmd = k.GetValue(name)?.ToString() ?? "";
                if (Matches(cmd, needles)) hooks.Add(new Hook(label, name, cmd));
            }
        }
        catch (Exception ex) { Log($"Persistence scan failed ({label}): {ex.Message}", LogLevel.Warning); }
    }

    static void ScanStartup(string folder, string label, List<string> needles, List<Hook> hooks)
    {
        try
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
            foreach (var f in Directory.EnumerateFiles(folder))
            {
                // The target path is stored as text inside the .lnk; reading the bytes is enough to match.
                string blob;
                try { blob = File.ReadAllText(f); } catch { blob = Path.GetFileName(f); }
                if (Matches(Path.GetFileName(f), needles) || Matches(blob, needles))
                    hooks.Add(new Hook(label, Path.GetFileName(f), f));
            }
        }
        catch (Exception ex) { Log($"Persistence scan failed ({label}): {ex.Message}", LogLevel.Warning); }
    }

    static void ScanTasks(List<string> needles, List<Hook> hooks)
    {
        try
        {
            using var p = new Process();
            p.StartInfo.FileName = "schtasks.exe";
            foreach (var a in new[] { "/query", "/fo", "csv", "/v", "/nh" }) p.StartInfo.ArgumentList.Add(a);
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            string? line;
            while ((line = p.StandardOutput.ReadLine()) != null)
            {
                if (!Matches(line, needles)) continue;
                var fields = SplitCsv(line);
                string name = fields.Count > 1 ? fields[1] : "(görev)";
                string cmd = fields.Count > 8 ? fields[8] : line;
                hooks.Add(new Hook("Zamanlanmış görev", name, cmd));
            }
            p.WaitForExit(15000);
        }
        catch (Exception ex) { Log("Persistence scan failed (tasks): " + ex.Message, LogLevel.Warning); }
    }

    static List<string> SplitCsv(string line)
    {
        var fields = new List<string>();
        bool inQuotes = false;
        var cur = new System.Text.StringBuilder();
        foreach (char c in line)
        {
            if (c == '"') inQuotes = !inQuotes;
            else if (c == ',' && !inQuotes) { fields.Add(cur.ToString()); cur.Clear(); }
            else cur.Append(c);
        }
        fields.Add(cur.ToString());
        return fields;
    }
}
