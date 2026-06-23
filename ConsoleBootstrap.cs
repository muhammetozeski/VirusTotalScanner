using System.Runtime.InteropServices;

namespace VirusTotalScanner;

/// <summary>
/// Lets this WinExe behave like a console program when launched from a terminal. A GUI
/// (Windows-subsystem) process has no console of its own, so we attach to the parent's
/// console and reopen the standard streams. If there is no parent console (Explorer /
/// double-click), attaching fails and we stay in GUI mode.
/// </summary>
internal static partial class ConsoleBootstrap
{
    const uint ATTACH_PARENT_PROCESS = 0xFFFFFFFF;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AttachConsole(uint dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FreeConsole();

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetConsoleWindow();

    public static bool HasConsole { get; private set; }

    /// <summary>Attaches to the parent console (if any) and redirects stdio. Returns true if a real console was attached.</summary>
    public static bool TryAttachParentConsole()
    {
        // Already have a console window? (rare for WinExe)
        if (GetConsoleWindow() != IntPtr.Zero) { RedirectStdHandles(); HasConsole = true; return true; }

        if (AttachConsole(ATTACH_PARENT_PROCESS))
        {
            RedirectStdHandles();
            HasConsole = true;
            return true;
        }
        return false;
    }

    static void RedirectStdHandles()
    {
        try
        {
            var stdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
            Console.SetOut(stdout);
            var stderr = new StreamWriter(Console.OpenStandardError()) { AutoFlush = true };
            Console.SetError(stderr);
            Console.SetIn(new StreamReader(Console.OpenStandardInput()));
        }
        catch { /* best effort */ }
    }

    /// <summary>
    /// A GUI-subsystem process does not make the shell wait, so the prompt is already printed
    /// when our async output begins. Emit a leading newline so output starts on a clean line.
    /// </summary>
    public static void WritePromptNewlineFix()
    {
        try { Console.WriteLine(); } catch { }
    }
}
