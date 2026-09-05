using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace VirusTotalScanner;

/// <summary>
/// One consistent way to log that an operation STARTED and that it ENDED, with how long it took and
/// how it came out. Written because a hang is invisible when only the start of a step is logged: the
/// last line in the file says what began, and nothing says what it was still waiting for.
///
/// Use it around anything that can block, anything that talks to the network, and anything whose
/// failure would otherwise be silent:
/// <code>
/// using var op = OpLog.Begin("Tor circuit change", $"port={_controlPort}");
/// ...
/// op.Ok($"exit={ExitIp}");     // or op.Fail(reason)
/// </code>
/// Disposing without Ok/Fail logs "ended (no outcome recorded)", which is itself a finding.
/// </summary>
internal sealed class OpLog : IDisposable
{
    /// <summary>Numbers the operations of this process, so a start line and its end line can be tied
    /// together. Two dozen workers interleave their lines, and an end line on its own says only that
    /// SOMETHING finished — pairing it by thread does not work either, because an async step resumes on
    /// whatever thread is free. Unique within one log file, which is one process run.</summary>
    static int _sequence;

    readonly int _id;
    readonly string _name;
    readonly string _caller;
    readonly Stopwatch _sw = Stopwatch.StartNew();
    string? _outcome;
    Logger.LogLevel _level = LogLevel.Info;
    bool _disposed;

    /// <summary>This operation's number, the one written on both of its lines.</summary>
    public int Id => _id;

    OpLog(string name, string? detail, string caller)
    {
        _id = Interlocked.Increment(ref _sequence);
        _name = name;
        _caller = caller;
        Log($"▶ [#{_id}] {name} started" + (string.IsNullOrEmpty(detail) ? "" : " — " + detail), LogLevel.Info, callerFunction: caller);
    }

    /// <summary>Logs the start of an operation and returns the handle that logs its end.</summary>
    public static OpLog Begin(string name, string? detail = null, [CallerMemberName] string caller = "")
        => new(name, detail, caller);

    /// <summary>Records a successful end. <paramref name="detail"/> should carry the RESULT — the thing
    /// a later reader will want and cannot reconstruct.</summary>
    public void Ok(string? detail = null) { _outcome = "ok" + (string.IsNullOrEmpty(detail) ? "" : " — " + detail); _level = LogLevel.Info; }

    /// <summary>Records a failed end with the reason.</summary>
    public void Fail(string? reason = null) { _outcome = "FAILED" + (string.IsNullOrEmpty(reason) ? "" : " — " + reason); _level = LogLevel.Warning; }

    /// <summary>Records an end that is neither: cancelled, skipped, nothing to do.</summary>
    public void Note(string detail) { _outcome = detail; _level = LogLevel.Info; }

    /// <summary>A progress line inside a long operation, so a hang has a last-known position.</summary>
    public void Step(string detail) => Log($"· [#{_id}] {_name}: {detail} (+{_sw.ElapsedMilliseconds} ms)", LogLevel.Debug, callerFunction: _caller);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Log($"◀ [#{_id}] {_name} ended after {_sw.ElapsedMilliseconds} ms — {_outcome ?? "no outcome recorded"}", _level, callerFunction: _caller);
    }
}
