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

    /// <summary>How many lines the in-memory buffers keep. They exist for "copy the logs" and the live
    /// viewer, both of which only ever want the recent past — but they used to grow without any bound.
    /// A disk-wide scan logs millions of lines, and every one of them was held in RAM for the life of
    /// the process. The files on disk are still complete; only the memory copy is trimmed.</summary>
    const int MaxBufferedLines = 20000;

    static void Enqueue(string formatted, string? friendly)
    {
        AllLogs.Enqueue(formatted);
        AllLogsUserFriendly.Enqueue(friendly);
        while (AllLogs.Count > MaxBufferedLines && AllLogs.TryDequeue(out _)) { }
        while (AllLogsUserFriendly.Count > MaxBufferedLines && AllLogsUserFriendly.TryDequeue(out _)) { }
    }

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
    static int _sinceFlush;
    /// <summary>Upper bound on unflushed lines while the queue never goes quiet.</summary>
    const int FlushEveryLines = 200;

    static Logger()
    {
        // Always run the consumer thread; it blocks until something is enqueued, and Log()
        // only enqueues to disk when logging is active. A single failed write must never
        // kill this thread (that would silently stop all future disk logging).
        new Thread(() =>
        {
            // One open handle for the life of the process instead of an open/write/close per line.
            // A disk sweep logs a couple of thousand lines a second; at that rate AppendAllText spent
            // longer opening files than writing to them and the queue grew without ever draining.
            StreamWriter? writer = null;
            string? openPath = null;

            foreach (var (Message, Sync) in _logQueue.GetConsumingEnumerable())
            {
                try
                {
                    string folder = ResolveLogsFolder();
                    if (!string.IsNullOrEmpty(folder))
                    {
                        string file = Path.Combine(folder, LogFileNamePrefix + " " + startTime + ".txt");
                        if (writer == null || !string.Equals(openPath, file, StringComparison.OrdinalIgnoreCase))
                        {
                            try { writer?.Dispose(); } catch { }
                            Directory.CreateDirectory(folder);
                            if (!_oldFilesCleaned)
                            {
                                _oldFilesCleaned = true;
                                try { HelperFunctions.DeleteOldestFiles(folder, DeleteOlderThanLastXFile, LogFileNamePrefix); } catch { }
                            }
                            writer = new StreamWriter(new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.ReadWrite, 1 << 16));
                            openPath = file;
                        }
                        writer.Write(Message);
                        writer.Write('\n');

                        // Flushed when the queue goes quiet, when a caller is waiting on this line, or
                        // every so often under sustained load — so a crash never loses more than the
                        // last moment, and the log stays readable while a scan is running.
                        if (Sync != null || _logQueue.Count == 0 || ++_sinceFlush >= FlushEveryLines)
                        {
                            _sinceFlush = 0;
                            writer.Flush();
                        }
                    }
                }
                catch { /* skip this one line; keep the logging thread alive */ }
                finally { try { Sync?.Set(); } catch { } }
            }

            try { writer?.Flush(); writer?.Dispose(); } catch { }
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

        Enqueue(Message, returnValue);
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

}
