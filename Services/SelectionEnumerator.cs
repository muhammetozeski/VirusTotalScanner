namespace VirusTotalScanner;

/// <summary>
/// Expands a selection of files/folders into a deduplicated list of files. Folders are
/// recursed (all subfolders); inaccessible folders are skipped, not fatal.
/// </summary>
internal static class SelectionEnumerator
{
    /// <summary>Expands the selection into files. <paramref name="missingPaths"/>, when given, collects the
    /// requested paths that are neither a file nor a folder — without it a deleted or unplugged target is
    /// indistinguishable from an empty one, and the caller reports "nothing found, all clean".</summary>
    public static List<string> Expand(IEnumerable<string> paths, ISet<string> safeExtensions, bool recurse,
        bool applySafeFilter, long maxSizeBytes = 0, List<string>? oversizeLedger = null,
        List<string>? missingPaths = null)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int prunedFolders = 0;
        int deniedFolders = 0;

        foreach (var raw in paths)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            string path = raw.Trim().Trim('"');

            try
            {
                if (File.Exists(path))
                {
                    AddFile(path, named: true);
                }
                else if (Directory.Exists(path))
                {
                    Walk(path, recurse, f => AddFile(f, named: false), ref prunedFolders, ref deniedFolders);
                }
                else
                {
                    missingPaths?.Add(path);
                    Log("Path not found, skipping: " + path, LogLevel.Warning);
                }
            }
            catch (Exception ex)
            {
                missingPaths?.Add(path);
                Log($"Enumeration error for '{path}': {ex.Message}", LogLevel.Warning);
            }
        }

        Log($"Selection expanded to {result.Count} file(s)"
            + (prunedFolders > 0 ? $"; {prunedFolders} suppressed folder subtree(s) never walked" : "")
            + (deniedFolders > 0 ? $"; {deniedFolders} folder(s) not readable by this account" : "")
            + ".", LogLevel.Info);
        return result;

        // The safe-extension filter thins out what a folder walk finds. A file the user named directly is
        // scanned whatever its extension: package_info.txt passed next to six folders was dropped without
        // a trace, neither scanned nor listed as skipped.
        void AddFile(string file, bool named)
        {
            if (!named && applySafeFilter && IsSafe(file, safeExtensions)) return;
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

    /// <summary>
    /// Manual directory walk instead of RecurseSubdirectories, so a suppressed folder can be PRUNED —
    /// the framework enumerator has no way to say "don't descend into this one". On a whole-disk sweep
    /// that is the difference between walking a suppressed tree and throwing every file away afterwards,
    /// and never touching the disk there at all.
    ///
    /// The explicitly selected folder is never pruned: picking a suppressed folder on purpose has to
    /// mean "scan it anyway". Only subfolders discovered during recursion are checked.
    /// </summary>
    static void Walk(string root, bool recurse, Action<string> onFile, ref int prunedFolders, ref int deniedFolders)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        int denied = 0;

        while (stack.Count > 0)
        {
            string dir = stack.Pop();

            try { foreach (var file in Directory.EnumerateFiles(dir)) onFile(file); }
            catch (UnauthorizedAccessException) { denied++; }
            catch (Exception ex) { Log($"Cannot list files in '{dir}': {ex.Message}", LogLevel.Warning); }

            // Only the root is ever pushed before this point, so a non-recursive walk ends right here.
            if (!recurse) continue;

            try
            {
                foreach (var sub in Directory.EnumerateDirectories(dir))
                {
                    try
                    {
                        // Junctions and symlinks would walk the same bytes twice (or loop forever).
                        if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue;
                        if (FolderSuppressionStore.ContainsFolder(sub))
                        {
                            prunedFolders++;
                            Log("Suppressed folder pruned from the walk: " + sub, LogLevel.Info);
                            continue;
                        }
                        stack.Push(sub);
                    }
                    catch (UnauthorizedAccessException) { denied++; }
                    catch (Exception ex) { Log($"Cannot inspect '{sub}': {ex.Message}", LogLevel.Warning); }
                }
            }
            catch (UnauthorizedAccessException) { denied++; }
            catch (Exception ex) { Log($"Cannot list subfolders of '{dir}': {ex.Message}", LogLevel.Warning); }
        }

        // A whole-disk walk hits hundreds of these (system folders, other users, the recycle bin) and
        // they are all expected. One count at the end says as much as hundreds of warnings did.
        deniedFolders += denied;
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
