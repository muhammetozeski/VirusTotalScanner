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
    public enum HookKind { RunKey, Startup, Task }
    public sealed record Hook(string Location, string Name, string Command, HookKind Kind = HookKind.RunKey, bool Hklm = false, string? RegSub = null);

    public static List<Hook> Find(string filePath, IEnumerable<string>? alsoMatch = null)
    {
        var needles = new List<string> { filePath, Path.GetFileName(filePath) };
        if (alsoMatch != null) needles.AddRange(alsoMatch);
        needles = needles.Where(n => !string.IsNullOrEmpty(n))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var hooks = new List<Hook>();
        ScanRunKey(Registry.CurrentUser, false, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run", needles, hooks);
        ScanRunKey(Registry.CurrentUser, false, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce", needles, hooks);
        ScanRunKey(Registry.LocalMachine, true, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run", needles, hooks);
        ScanRunKey(Registry.LocalMachine, true, @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (WOW64)", needles, hooks);
        ScanStartup(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Başlangıç (kullanıcı)", needles, hooks);
        ScanStartup(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Başlangıç (ortak)", needles, hooks);
        ScanTasks(needles, hooks);
        return hooks;
    }

    static bool Matches(string text, List<string> needles) =>
        !string.IsNullOrEmpty(text) && needles.Any(n => text.Contains(n, StringComparison.OrdinalIgnoreCase));

    static void ScanRunKey(RegistryKey root, bool hklm, string subPath, string label, List<string> needles, List<Hook> hooks)
    {
        try
        {
            using var k = root.OpenSubKey(subPath);
            if (k == null) return;
            foreach (var name in k.GetValueNames())
            {
                string cmd = k.GetValue(name)?.ToString() ?? "";
                if (Matches(cmd, needles)) hooks.Add(new Hook(label, name, cmd, HookKind.RunKey, hklm, subPath));
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
                    hooks.Add(new Hook(label, Path.GetFileName(f), f, HookKind.Startup));
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
                hooks.Add(new Hook("Zamanlanmış görev", name, cmd, HookKind.Task));
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

    /// <summary>Reversibly cut an autostart hook: a Run/RunOnce value is logged to a restore file in the
    /// quarantine folder then deleted; a Startup .lnk is moved into the vault; a scheduled task is deleted
    /// via schtasks. Returns false (with an error) if it couldn't — e.g. an HKLM value needs admin.</summary>
    public static bool Remove(Hook h, out string? error)
    {
        error = null;
        try
        {
            switch (h.Kind)
            {
                case HookKind.RunKey:
                {
                    var root = h.Hklm ? Registry.LocalMachine : Registry.CurrentUser;
                    BackupRunValue(h);
                    using var k = root.OpenSubKey(h.RegSub!, writable: true);
                    k?.DeleteValue(h.Name, throwOnMissingValue: false);
                    return true;
                }
                case HookKind.Startup:
                {
                    Directory.CreateDirectory(ConfigPathResolver.QuarantineFolder);
                    string dest = Path.Combine(ConfigPathResolver.QuarantineFolder, "startup-" + Path.GetFileName(h.Command));
                    File.Move(h.Command, dest, overwrite: true); // reversible: the .lnk now lives in the vault
                    return true;
                }
                case HookKind.Task:
                    return DeleteTask(h.Name, out error);
            }
            return false;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    static void BackupRunValue(Hook h)
    {
        try
        {
            Directory.CreateDirectory(ConfigPathResolver.QuarantineFolder);
            string path = Path.Combine(ConfigPathResolver.QuarantineFolder, "autostart-restore.log");
            string root = h.Hklm ? "HKLM" : "HKCU";
            File.AppendAllText(path, $"{DateTime.Now:o}\t{root}\\{h.RegSub}\t{h.Name}\t{h.Command}{Environment.NewLine}");
        }
        catch { /* backup is best-effort */ }
    }

    static bool DeleteTask(string name, out string? error)
    {
        error = null;
        try
        {
            using var p = new Process();
            p.StartInfo.FileName = "schtasks.exe";
            foreach (var a in new[] { "/delete", "/tn", name, "/f" }) p.StartInfo.ArgumentList.Add(a);
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            string err = p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            if (p.ExitCode != 0) { error = string.IsNullOrWhiteSpace(err) ? $"schtasks çıkış {p.ExitCode}" : err.Trim(); return false; }
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }
}
