using System.Runtime.InteropServices;

namespace VirusTotalScanner;

/// <summary>Decides whether a non-urgent tray toast should be held back: during a user-set quiet window,
/// or while a fullscreen app (game / presentation / Direct3D) is foreground. Keeps protection running
/// while killing the interruptions that drive users to switch notifications off entirely.</summary>
internal static class NotificationGate
{
    enum QUNS { NOT_PRESENT = 1, BUSY = 2, RUNNING_D3D_FULL_SCREEN = 3, PRESENTATION_MODE = 4, ACCEPTS_NOTIFICATIONS = 5, QUIET_TIME = 6, APP = 7 }

    [DllImport("shell32.dll")]
    static extern int SHQueryUserNotificationState(out QUNS state);

    static bool FullscreenBusy()
    {
        try { if (SHQueryUserNotificationState(out var s) == 0) return s is QUNS.BUSY or QUNS.RUNNING_D3D_FULL_SCREEN or QUNS.PRESENTATION_MODE; }
        catch { /* not supported / failed — don't suppress */ }
        return false;
    }

    static bool InQuietHours()
    {
        int start = Settings.QuietHoursStart, end = Settings.QuietHoursEnd;
        if (start == end) return false; // start==end means the quiet window is disabled
        int h = DateTime.Now.Hour;
        return start < end ? (h >= start && h < end) : (h >= start || h < end); // the wrap-past-midnight case
    }

    /// <summary>True when a non-urgent toast should be held back (quiet hours or a fullscreen app).</summary>
    public static bool ShouldSuppress() =>
        InQuietHours() || (Settings.MuteInFullscreen && FullscreenBusy());
}
