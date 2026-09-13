namespace VirusTotalScanner;

/// <summary>
/// Times a piece of work on the UI thread and logs it when it runs long. The UI lag watch says that the
/// window stopped answering and for how long, but not what it was doing; sampling the stack from outside
/// suspends the process long enough to cause the very stalls it is looking for. These lines name the work.
/// </summary>
internal static class UiSlice
{
    public const int SlowMs = 100;

    public static void Measure(string what, Action work)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        try { work(); }
        finally
        {
            if (clock.ElapsedMilliseconds >= SlowMs)
                Log($"UI work '{what}' took {clock.ElapsedMilliseconds} ms.", LogLevel.Warning);
        }
    }
}
