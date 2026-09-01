namespace VirusTotalScanner;

internal enum StatusSeverity { Info, Warning, Danger }

/// <summary>One activity line from a background worker (watcher, catch-up, re-check, sweep…).</summary>
internal sealed record StatusEvent(DateTime WhenLocal, string Source, string Message, StatusSeverity Severity);

/// <summary>
/// The single funnel every background job reports through, so the status bar can always answer
/// "what is the app doing right now?" — before this, the watchers, catch-up, periodic re-checks and
/// sweep results all worked invisibly. Keeps a bounded ring of recent events for the click-to-open
/// history. Thread-safe; <see cref="Changed"/> fires on the reporting thread (subscribers marshal).
/// </summary>
internal static class UiStatusHub
{
    const int MaxEvents = 100;
    static readonly object Lock = new();
    static readonly List<StatusEvent> _events = [];

    public static event Action<StatusEvent>? Changed;

    public static StatusEvent? Latest { get { lock (Lock) { return _events.Count > 0 ? _events[^1] : null; } } }

    public static IReadOnlyList<StatusEvent> Recent() { lock (Lock) { return [.. _events]; } }

    public static void Report(string source, string message, StatusSeverity severity = StatusSeverity.Info)
    {
        var e = new StatusEvent(DateTime.Now, source, message, severity);
        lock (Lock)
        {
            _events.Add(e);
            if (_events.Count > MaxEvents) _events.RemoveRange(0, _events.Count - MaxEvents);
        }
        try { Changed?.Invoke(e); } catch (Exception ex) { Log("Status hub handler failed: " + ex.Message, LogLevel.Warning); }
    }
}
