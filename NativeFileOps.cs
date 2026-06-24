using System.Runtime.InteropServices;

namespace VirusTotalScanner;

/// <summary>Native file operations for the cases the managed API can't handle — chiefly removing a file
/// that is still mapped/locked by neutralizing it at the next reboot.</summary>
internal static class NativeFileOps
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);

    const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    /// <summary>Schedule the file for deletion on the next reboot (works even while it is locked/mapped).
    /// Requires admin (it writes PendingFileRenameOperations); returns false if not permitted.</summary>
    public static bool ScheduleDeleteOnReboot(string path)
    {
        try { return MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT); }
        catch { return false; }
    }
}
