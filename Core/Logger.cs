using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;

// Adapted from C:\E\isler\CulturelEnglish\MainProject\zTests\Logger.cs
// MAUI (FileSystem), CrashReporter and AppConstants.TestBuild dependencies removed.
// The log folder comes from LogsFolderProvider (set by LoggerHost); logging is OFF by
// default and toggled at runtime by the user via ActivateLogging.
// Lives in the GLOBAL namespace so "global using static Logger;" exposes Log() everywhere.
#pragma warning disable CA1050 // Declare types in namespaces
public static class Logger
#pragma warning restore CA1050
{
    static int _activateLogging = 0; // 0 = off, 1 = on (int for Interlocked)

    /// <summary>Master switch. Toggled at runtime by the user (persisted via Settings.EnableLogging).</summary>
    public static bool ActivateLogging
    {
        get => Interlocked.CompareExchange(ref _activateLogging, 0, 0) == 1;
        set => Interlocked.Exchange(ref _activateLogging, value ? 1 : 0);
    }

    /// <summary>When true (and logging active), lines are also appended to a log file.</summary>
    public static bool WriteToDisk { get; set; } = true;

    /// <summary>Set by LoggerHost; returns the folder log files are written to.</summary>
    public static Func<string>? LogsFolderProvider;

    /// <summary>Optional live sink (e.g. the in-app log viewer). Receives each formatted line.</summary>
    public static Action<string>? Sink;

    const bool PrintDebugModStyle = true;

    public static readonly string startTime = DateTime.Now.ToString("yyyy.MM.dd HH.mm.ss.ff");
    public const string LogFileNamePrefix = "Log";
    const int DeleteOlderThanLastXFile = 5;

    public static readonly ConcurrentQueue<string> AllLogs = new();
    public static readonly ConcurrentQueue<string?> AllLogsUserFriendly = new();

    /// <summary>Assembles every buffered log line into one string (for the "copy logs" button).</summary>
    public static string GetAllLogsText()
    {
        var sb = new System.Text.StringBuilder();
        foreach (var line in AllLogs) sb.Append(line);
        return sb.ToString();
    }

    /// <summary>Empties the in-memory log buffer so a fresh capture starts clean.</summary>
    public static void ClearAllLogs() { while (AllLogs.TryDequeue(out _)) { } }

    static readonly BlockingCollection<(string Message, ManualResetEventSlim? Sync)> _logQueue = [];
    static bool _oldFilesCleaned;

    static Logger()
    {
        // Always run the consumer thread; it blocks until something is enqueued, and Log()
        // only enqueues to disk when logging is active. A single failed write must never
        // kill this thread (that would silently stop all future disk logging).
        new Thread(() =>
        {
            foreach (var (Message, Sync) in _logQueue.GetConsumingEnumerable())
            {
                try
                {
                    string folder = ResolveLogsFolder();
                    if (!string.IsNullOrEmpty(folder))
                    {
                        Directory.CreateDirectory(folder);
                        if (!_oldFilesCleaned)
                        {
                            _oldFilesCleaned = true;
                            try { DeleteOldestFiles(folder, DeleteOlderThanLastXFile, LogFileNamePrefix); } catch { }
                        }
                        string file = Path.Combine(folder, LogFileNamePrefix + " " + startTime + ".txt");
                        File.AppendAllText(file, Message + "\n");
                    }
                }
                catch { /* skip this one line; keep the logging thread alive */ }
                finally { try { Sync?.Set(); } catch { } }
            }
        })
        { IsBackground = true, Name = "Logger.DiskWriter" }.Start();
    }

    static string ResolveLogsFolder()
    {
        try
        {
            string? f = LogsFolderProvider?.Invoke();
            if (!string.IsNullOrWhiteSpace(f)) return f!;
        }
        catch { }
        try { return Path.Combine(Path.GetTempPath(), "VirusTotalScannerLogs"); }
        catch { return string.Empty; }
    }

    public class LogLevel(string name, ConsoleColor consoleColor)
    {
        public static readonly LogLevel Info = new(nameof(Info), ConsoleColor.Blue);
        public static readonly LogLevel Debug = new(nameof(Debug), ConsoleColor.Green);
        public static readonly LogLevel Warning = new(nameof(Warning), ConsoleColor.Yellow);
        public static readonly LogLevel Error = new(nameof(Error), ConsoleColor.Red);

        public string Name { get; init; } = name;
        public ConsoleColor ConsoleColor { get; init; } = consoleColor;
    }

    /// <summary>
    /// Logs a message/object to the console (when one is attached), the in-memory buffer,
    /// the live sink and optionally disk. Captures caller file/function/line automatically.
    /// No-ops (returns the string form) when <see cref="ActivateLogging"/> is false.
    /// </summary>
    public static string? Log(object? MessageObject, LogLevel? logLevel = null, ConsoleColor? consoleColor = null,
        bool PrintToConsole = true, bool UseNewLine = true, bool WaitForLogging = false,
        [CallerMemberName] string callerFunction = "",
        [CallerFilePath] string callerFilePath = "",
        [CallerLineNumber] int callerLine = 0, bool Run = true)
    {
        logLevel ??= LogLevel.Debug;

        if (!Run || !ActivateLogging)
            return MessageObject?.ToString();

        string? returnValue = null;

        const string prefix = "> ";
        const string suffix = "\n-----------------------------\n\n";
        string CallerFile;
        try
        {
            CallerFile = Path.GetFileName(callerFilePath);
            if (string.IsNullOrWhiteSpace(CallerFile)) CallerFile = "null";
        }
        catch (Exception e) { CallerFile = "\"exception: " + e.Message + "\""; }

        string now = DateTime.Now.ToString("dd.MM.yyyy HH.mm.ss.ff");

        string Message = prefix + "[" + now + "] " +
            "[" + CallerFile + "/" + callerFunction + " Line: " + callerLine +
            " Thread Id: " + Environment.CurrentManagedThreadId + "]:\n[" + logLevel.Name + "] ";

        try
        {
            if (MessageObject is System.Collections.IEnumerable numerable and not string)
            {
                foreach (var item in numerable)
                {
                    try
                    {
                        string? itemString = item?.ToString();
                        returnValue = returnValue == null ? (itemString ?? "null") : returnValue + (itemString ?? "null");
                        returnValue += "\n";
                        Message += itemString ?? "item.ToString() returned null\n";
                    }
                    catch (Exception e)
                    {
                        returnValue += "error";
                        Message += "An error occured while converting a list item to string in Log(). Error:\n" + e + "\n";
                    }
                }
            }
            else
            {
                returnValue = MessageObject?.ToString();
                if (MessageObject is Exception)
                    returnValue = "An exception occured in the caller function: \n\n" + returnValue;
                Message += returnValue ?? "MessageObject.ToString() returned null";
            }
        }
        catch (Exception e)
        {
            Message += "An error occured while converting the given object to string in Log(). Error:\n" + e;
        }

        Message += suffix;

        if (PrintToConsole)
        {
            try
            {
                var defaultColor = SafeForegroundColor;
                if (consoleColor != null) SafeSetForeground(consoleColor.Value);
                else SafeSetForeground((logLevel.ConsoleColor));

                // Logs go to stderr so CLI stdout (results / --json) stays clean for piping.
                object? toPrint = PrintDebugModStyle ? Message : MessageObject;
                if (UseNewLine) Console.Error.WriteLine(toPrint);
                else Console.Error.Write(toPrint);

                SafeSetForeground(defaultColor);
            }
            catch { /* no console attached (GUI mode) */ }
        }

        AllLogs.Enqueue(Message);
        AllLogsUserFriendly.Enqueue(returnValue);
        try { Sink?.Invoke(Message); } catch { }

        if (WriteToDisk)
        {
            if (WaitForLogging)
            {
                using var syncEvent = new ManualResetEventSlim(false);
                _logQueue.Add((Message, syncEvent));
                syncEvent.Wait();
            }
            else
            {
                _logQueue.Add((Message, null));
            }
        }

        return returnValue;
    }

    static ConsoleColor SafeForegroundColor
    {
        get { try { return Console.ForegroundColor; } catch { return ConsoleColor.Gray; } }
    }
    static void SafeSetForeground(ConsoleColor c) { try { Console.ForegroundColor = c; } catch { } }

    static void DeleteOldestFiles(string folderPath, int filesToKeep, string prefix = "")
    {
        if (!Directory.Exists(folderPath)) return;

        var files = Directory.GetFiles(folderPath)
            .Select(p => new { Path = p, FileName = Path.GetFileNameWithoutExtension(p) })
            .ToList();

        var datedFiles = new List<(string Path, DateTime Date)>();
        foreach (var file in files)
        {
            string name = file.FileName;
            name = name.Contains(prefix) ? name.Remove(name.IndexOf(prefix), prefix.Length) : name;
            name = name.Trim();
            if (DateTime.TryParseExact(name, "yyyy.MM.dd HH.mm.ss.ff",
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out DateTime fileDate))
                datedFiles.Add((file.Path, fileDate));
        }

        var sorted = datedFiles.OrderBy(f => f.Date).ToList();
        int toDelete = sorted.Count - filesToKeep;
        for (int i = 0; i < toDelete; i++)
        {
            try { File.Delete(sorted[i].Path); } catch { }
        }
    }
}
