namespace VirusTotalScanner;

/// <summary>
/// Round-robin key selection with quota awareness. Each API request calls
/// <see cref="AcquireAsync"/> to consume one unit from the next key that has room. When
/// every key is exhausted it WAITS (counting down to the soonest reset) instead of failing,
/// and resumes automatically. 429s rotate to a different key; 401/403 disable a key.
/// </summary>
internal sealed class KeyRotator
{
    readonly KeyVault _vault;
    readonly object _lock = new();
    int _cursor;

    /// <summary>Raised when all keys are exhausted; argument is the soonest reset time (UTC).</summary>
    public event Action<DateTime>? OnAllExhausted;
    /// <summary>Raised when scanning resumes after a wait.</summary>
    public event Action? OnResumed;

    public KeyRotator(KeyVault vault) => _vault = vault;

    public bool HasUsableKeys => _vault.HasUsableKeys;
    public int UsableKeyCount => _vault.UsableKeyCount;

    /// <summary>
    /// Returns an API key with one quota unit consumed. Blocks (with countdown) until a key
    /// frees up if all are exhausted. Throws if no keys are configured at all.
    /// </summary>
    public async Task<string> AcquireAsync(CancellationToken ct = default)
    {
        bool waited = false;
        while (true)
        {
            ct.ThrowIfCancellationRequested();

            string? key = TryConsumeOne(out DateTime? soonest, out bool noKeys);
            if (noKeys)
                throw new InvalidOperationException(Strings.ErrNoKeysDefined);

            if (key != null)
            {
                if (waited) { Log("Keys reset; scanning resumed.", LogLevel.Info); try { OnResumed?.Invoke(); } catch (Exception ex) { Log("OnResumed handler failed: " + ex.Message, LogLevel.Warning); } }
                return key;
            }

            var now = DateTime.UtcNow;
            var target = soonest ?? now.AddSeconds(30);
            var wait = target - now;
            if (wait < TimeSpan.FromSeconds(1)) wait = TimeSpan.FromSeconds(1);
            if (wait > TimeSpan.FromSeconds(60)) wait = TimeSpan.FromSeconds(60); // re-check at least once a minute

            waited = true;
            try { OnAllExhausted?.Invoke(target); } catch (Exception ex) { Log("OnAllExhausted handler failed: " + ex.Message, LogLevel.Warning); }
            Log($"All keys exhausted. Waiting {wait.TotalSeconds:F0}s (soonest reset {target:HH:mm:ss} UTC).", LogLevel.Warning);
            await Task.Delay(wait, ct);
        }
    }

    string? TryConsumeOne(out DateTime? soonestReset, out bool noKeys)
    {
        soonestReset = null;
        noKeys = false;
        lock (_lock)
        {
            var keys = _vault.Keys.Where(k => !k.Disabled).ToList();
            if (keys.Count == 0) { noKeys = true; return null; }

            var now = DateTime.UtcNow;
            for (int i = 0; i < keys.Count; i++)
            {
                var entry = keys[(_cursor + i) % keys.Count];
                if (entry.TryConsume(now))
                {
                    _cursor = (_cursor + i + 1) % keys.Count;
                    _vault.MaybePersistCounters();
                    _vault.RaiseCountersUpdated();
                    return entry.Key;
                }
            }

            soonestReset = keys.Select(k => k.SoonestResetUtc(now)).DefaultIfEmpty(now.AddSeconds(30)).Min();
            return null;
        }
    }

    /// <summary>Marks a key's minute window full after a 429 so rotation skips it briefly.</summary>
    public void ReportRateLimited(string key, TimeSpan? retryAfter)
    {
        lock (_lock)
        {
            var e = _vault.Keys.FirstOrDefault(k => k.Key == key);
            if (e == null) return;
            var now = DateTime.UtcNow;
            e.Minute.WindowStartUtc = now;
            e.Minute.Used = e.Minute.Allowed;
            // A long Retry-After implies daily/monthly exhaustion — block that window too.
            if (retryAfter is { } ra && ra > TimeSpan.FromMinutes(5))
            {
                e.Daily.Roll(now);
                e.Daily.Used = e.Daily.Allowed;
            }
            Log($"Key {e.Masked} rate-limited (429). Rotating.", LogLevel.Warning);
        }
        _vault.RaiseCountersUpdated();
    }

    /// <summary>Disables a key after an auth failure.</summary>
    public void ReportAuthError(string key)
    {
        lock (_lock)
        {
            var e = _vault.Keys.FirstOrDefault(k => k.Key == key);
            if (e == null) return;
            e.Disabled = true;
            e.LastError = "Auth failed (401/403)";
            Log($"Key {e.Masked} disabled: auth failed.", LogLevel.Error);
        }
        _vault.Save();
    }

    /// <summary>Reconciles daily/monthly counters from the authoritative server quota.</summary>
    public void ReconcileFromServer(string key, VtQuotas quotas)
    {
        lock (_lock)
        {
            var e = _vault.Keys.FirstOrDefault(k => k.Key == key);
            if (e == null) return;
            if (quotas.Daily.Allowed > 0) { e.Daily.Allowed = quotas.Daily.Allowed; e.Daily.Used = quotas.Daily.Used; }
            if (quotas.Monthly.Allowed > 0) { e.Monthly.Allowed = quotas.Monthly.Allowed; e.Monthly.Used = quotas.Monthly.Used; }
        }
        _vault.RaiseCountersUpdated();
    }
}
