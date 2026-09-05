namespace VirusTotalScanner;

/// <summary>
/// Crash-safe file writes for the app's durable JSON stores. Writes to a sibling <c>.tmp</c> file then
/// atomically swaps it onto the real path, so a crash / kill / power-loss mid-write can never leave a
/// truncated or empty store (which would otherwise silently lose the hash cache, history, or — worst —
/// the quarantine manifest that maps .VIRUS files back to their originals).
/// </summary>
internal static class AtomicFile
{
    /// <summary>Renames a file that failed to parse to a timestamped <c>.corrupt-…</c> sidecar so the
    /// data is preserved for manual recovery, instead of being silently overwritten with an empty store
    /// on the next save. Most important for the quarantine manifest, whose loss orphans .VIRUS files.</summary>
    public static void BackupCorrupt(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            string dest = $"{path}.corrupt-{DateTime.Now:yyyyMMdd-HHmmss}.bak";
            File.Move(path, dest);
            Log($"Preserved corrupt store as {dest}", LogLevel.Warning);
        }
        catch { }
    }

    /// <summary>One lock per destination path. Two threads saving the same store used to write the same
    /// sibling ".tmp" at the same time and one of them died with "the file is being used by another
    /// process" — during a sweep that is the quota counters failing to persist, over and over.</summary>
    static readonly System.Collections.Concurrent.ConcurrentDictionary<string, object> PathLocks =
        new(StringComparer.OrdinalIgnoreCase);

    public static void WriteAllText(string path, string content)
    {
        lock (PathLocks.GetOrAdd(Path.GetFullPath(path), _ => new object()))
            WriteLocked(path, content);
    }

    static void WriteLocked(string path, string content)
    {
        // Unique temp name: a second writer that slips past the lock (another process holding the same
        // config open) then collides on the swap, which is recoverable, instead of on the write itself.
        string tmp = $"{path}.{Environment.ProcessId:x}-{Environment.CurrentManagedThreadId:x}.tmp";
        File.WriteAllText(tmp, content);
        try
        {
            if (File.Exists(path))
                File.Replace(tmp, path, null); // atomic swap on NTFS
            else
                File.Move(tmp, path);
        }
        catch (Exception ex)
        {
            // File.Replace can fail across odd filesystems / antivirus locks — fall back to a plain
            // overwrite so we still persist (just without the atomicity guarantee this once). Logged
            // because a torn read of this very window is the prime suspect for the key-vault
            // decrypt failure seen in the field.
            Log($"Atomic replace failed for {path} ({ex.Message}); falling back to a plain copy.", LogLevel.Warning);
            try { File.Copy(tmp, path, overwrite: true); }
            finally { try { File.Delete(tmp); } catch (Exception del) { Log($"Temp file '{tmp}' left behind: {del.Message}", LogLevel.Warning); } }
        }
    }
}
