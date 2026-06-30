namespace VirusTotalScanner;

/// <summary>A simple pause/resume gate: callers await <see cref="WaitWhilePausedAsync"/>.</summary>
internal sealed class PauseTokenSource
{
    volatile TaskCompletionSource<bool>? _tcs;

    public bool IsPaused => _tcs != null;

    public void Pause() => _tcs ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

    public void Resume()
    {
        var t = _tcs;
        _tcs = null;
        t?.TrySetResult(true);
    }

    public async Task WaitWhilePausedAsync(CancellationToken ct)
    {
        var t = _tcs;
        if (t != null) await t.Task.WaitAsync(ct);
    }
}
