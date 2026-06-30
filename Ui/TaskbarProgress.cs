using System.Runtime.InteropServices;

namespace VirusTotalScanner;

/// <summary>
/// Drives the Windows taskbar button during a scan via ITaskbarList3: a live green fill tracking
/// scanned/total, indeterminate "pulse" while waiting, and a red state when threats were found — so a
/// glance at the taskbar (scan minimized to tray) says "still working / clean / threats" without
/// reopening the window. All calls are best-effort: any COM failure is swallowed.
/// </summary>
internal static class TaskbarProgress
{
    enum State { NoProgress = 0, Indeterminate = 1, Normal = 2, Error = 4, Paused = 8 }

    [ComImport, Guid("ea1afb91-9e28-4b86-90e9-9e9f8a5eefaf"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface ITaskbarList3
    {
        // ITaskbarList
        void HrInit();
        void AddTab(IntPtr hwnd);
        void DeleteTab(IntPtr hwnd);
        void ActivateTab(IntPtr hwnd);
        void SetActiveAlt(IntPtr hwnd);
        // ITaskbarList2
        void MarkFullscreenWindow(IntPtr hwnd, [MarshalAs(UnmanagedType.Bool)] bool fFullscreen);
        // ITaskbarList3 (only the two we use; the rest of the vtable is not declared)
        void SetProgressValue(IntPtr hwnd, ulong completed, ulong total);
        void SetProgressState(IntPtr hwnd, State state);
    }

    [ComImport, Guid("56FDF344-FD6D-11d0-958A-006097C9A090"), ClassInterface(ClassInterfaceType.None)]
    class TaskbarInstance { }

    static ITaskbarList3? _bar;
    static IntPtr _hwnd;

    public static void Init(IntPtr hwnd)
    {
        _hwnd = hwnd;
        try { _bar = (ITaskbarList3)new TaskbarInstance(); _bar.HrInit(); }
        catch { _bar = null; }
    }

    public static void Set(int done, int total)
    {
        if (_bar == null || _hwnd == IntPtr.Zero) return;
        try
        {
            _bar.SetProgressState(_hwnd, State.Normal);
            _bar.SetProgressValue(_hwnd, (ulong)Math.Max(0, done), (ulong)Math.Max(1, total));
        }
        catch { }
    }

    public static void Indeterminate() { Try(State.Indeterminate); }
    public static void Threat() { Try(State.Error); }   // red bar = threats found
    public static void Clear() { Try(State.NoProgress); }

    static void Try(State s)
    {
        if (_bar == null || _hwnd == IntPtr.Zero) return;
        try { _bar.SetProgressState(_hwnd, s); } catch { }
    }
}
