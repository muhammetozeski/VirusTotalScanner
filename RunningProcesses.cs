using System.Diagnostics;

namespace VirusTotalScanner;

/// <summary>
/// "Am I infected right now?" triage: collects the on-disk image path of every running process so
/// they can be fed into the normal scan pipeline (trust pre-filter skips the Microsoft-signed
/// majority, the cache covers the rest, only genuine unknowns hit VirusTotal). Protected/system
/// processes whose path can't be read are counted as "unreadable", not failed.
/// </summary>
internal static class RunningProcesses
{
    public static (List<string> Paths, int Unreadable) ImagePaths(bool includeModules = false)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int unreadable = 0;

        foreach (var p in Process.GetProcesses())
        {
            try
            {
                string? file = p.MainModule?.FileName;
                if (!string.IsNullOrEmpty(file) && File.Exists(file)) paths.Add(file);
                else unreadable++;

                if (includeModules)
                {
                    foreach (ProcessModule m in p.Modules)
                    {
                        try { if (File.Exists(m.FileName)) paths.Add(m.FileName); }
                        catch { /* a single module being unreadable is not fatal */ }
                    }
                }
            }
            catch { unreadable++; } // access-denied on protected processes is expected
            finally { try { p.Dispose(); } catch { } }
        }

        return (paths.ToList(), unreadable);
    }
}
