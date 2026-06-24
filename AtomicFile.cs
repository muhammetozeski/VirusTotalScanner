namespace VirusTotalScanner;

/// <summary>
/// Crash-safe file writes for the app's durable JSON stores. Writes to a sibling <c>.tmp</c> file then
/// atomically swaps it onto the real path, so a crash / kill / power-loss mid-write can never leave a
/// truncated or empty store (which would otherwise silently lose the hash cache, history, or — worst —
/// the quarantine manifest that maps .VIRUS files back to their originals).
/// </summary>
internal static class AtomicFile
{
    public static void WriteAllText(string path, string content)
    {
        string tmp = path + ".tmp";
        File.WriteAllText(tmp, content);
        try
        {
            if (File.Exists(path))
                File.Replace(tmp, path, null); // atomic swap on NTFS
            else
                File.Move(tmp, path);
        }
        catch
        {
            // File.Replace can fail across odd filesystems / antivirus locks — fall back to a plain
            // overwrite so we still persist (just without the atomicity guarantee this once).
            File.Copy(tmp, path, overwrite: true);
            try { File.Delete(tmp); } catch { }
        }
    }
}
