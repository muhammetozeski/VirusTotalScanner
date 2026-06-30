namespace VirusTotalScanner;

/// <summary>
/// Expands a selection of files/folders into a deduplicated list of files. Folders are
/// recursed (all subfolders); inaccessible folders are skipped, not fatal.
/// </summary>
internal static class SelectionEnumerator
{
    public static List<string> Expand(IEnumerable<string> paths, ISet<string> safeExtensions, bool recurse,
        bool applySafeFilter, long maxSizeBytes = 0, List<string>? oversizeLedger = null)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in paths)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            string path = raw.Trim().Trim('"');

            try
            {
                if (File.Exists(path))
                {
                    AddFile(path);
                }
                else if (Directory.Exists(path))
                {
                    var opts = new EnumerationOptions
                    {
                        RecurseSubdirectories = recurse,
                        IgnoreInaccessible = true,
                        AttributesToSkip = FileAttributes.ReparsePoint, // don't follow junctions/symlinks
                    };
                    foreach (var file in Directory.EnumerateFiles(path, "*", opts))
                        AddFile(file);
                }
                else
                {
                    Log("Path not found, skipping: " + path, LogLevel.Warning);
                }
            }
            catch (Exception ex)
            {
                Log($"Enumeration error for '{path}': {ex.Message}", LogLevel.Warning);
            }
        }

        Log($"Selection expanded to {result.Count} file(s).", LogLevel.Info);
        return result;

        void AddFile(string file)
        {
            if (applySafeFilter && IsSafe(file, safeExtensions)) return;
            if (maxSizeBytes > 0)
            {
                try
                {
                    if (new FileInfo(file).Length > maxSizeBytes)
                    {
                        oversizeLedger?.Add(file);
                        Log($"Skipped (over size cap): {file}", LogLevel.Info);
                        return;
                    }
                }
                catch (Exception ex) { Log($"Size check failed for '{file}': {ex.Message}", LogLevel.Warning); }
            }
            string full;
            try { full = Path.GetFullPath(file); } catch { full = file; }
            if (seen.Add(full)) result.Add(full);
        }
    }

    public static bool IsSafe(string file, ISet<string> safeExtensions)
    {
        string ext = Path.GetExtension(file);
        return !string.IsNullOrEmpty(ext) && safeExtensions.Contains(ext);
    }

    /// <summary>Parses "a.txt;.png;.MP4" style settings into a normalized extension set.</summary>
    public static HashSet<string> ParseExtensions(string csv)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in csv.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string e = part.StartsWith('.') ? part : "." + part;
            set.Add(e);
        }
        return set;
    }
}
