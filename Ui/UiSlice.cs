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
        var gcBefore = GC.GetTotalPauseDuration();
        try { work(); }
        finally
        {
            if (clock.ElapsedMilliseconds >= SlowMs)
                Log($"UI work '{what}' took {clock.ElapsedMilliseconds} ms ({GcPauseSince(gcBefore)} ms of it the runtime paused every thread for garbage collection).", LogLevel.Warning);
        }
    }

    /// <summary>Milliseconds the garbage collector had every thread stopped since <paramref name="before"/>. A
    /// stall that is mostly this is not caused by the work that happened to be running.</summary>
    public static long GcPauseSince(TimeSpan before) => (long)(GC.GetTotalPauseDuration() - before).TotalMilliseconds;
}
