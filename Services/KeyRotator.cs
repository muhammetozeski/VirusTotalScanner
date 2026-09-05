using System.Collections.Concurrent;

namespace VirusTotalScanner;

/// <summary>
/// Round-robin key selection with quota awareness. Each API request calls
/// <see cref="AcquireAsync"/> to consume one unit from the next key that has room. When
/// every key is exhausted it WAITS (counting down to the soonest reset) instead of failing,
/// and resumes automatically. 429s rotate to a different key; 401/403 disable a key.
///
/// The local counters are only a model of what VirusTotal thinks. When a key answers 429
/// several times in a row even though its minute window was just reset, the model is wrong and
/// the key's DAILY allowance is really gone — VirusTotal sends no Retry-After to say so. That case
/// is detected here and the key is parked until the next UTC day, instead of being retried every
/// minute forever (which is what made a big scan sit still for hours, hammering VT with 429s).
/// </summary>
internal sealed class KeyRotator
{
    /// <summary>Consecutive 429s (with no success in between) after which a key is treated as
    /// daily-exhausted server-side.</summary>
    const int ConsecutiveRateLimitsMeansDaily = 3;

    readonly KeyVault _vault;
    readonly object _lock = new();
    readonly ConcurrentDictionary<string, int> _consecutive429 = new(StringComparer.Ordinal);
    int _cursor;

    /// <summary>Raised when all keys are exhausted; argument is the soonest reset time (UTC).</summary>
    public event Action<DateTime>? OnAllExhausted;
    /// <summary>Raised when scanning resumes after a wait.</summary>
    public event Action? OnResumed;
    /// <summary>Raised when a key is parked because its daily allowance is gone (argument: masked key).</summary>
    public event Action<string>? OnKeyDailyExhausted;

    public KeyRotator(KeyVault vault) => _vault = vault;

    public bool HasUsableKeys => _vault.HasUsableKeys;
    public int UsableKeyCount => _vault.UsableKeyCount;

    /// <summary>True when at least one key could serve a request RIGHT NOW (no waiting). Lets a caller
    /// fall back to the keyless path instead of blocking on a quota that resets hours from now.</summary>
    public bool HasImmediateRoom
    {
        get
        {
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                return _vault.Keys.Any(k => !k.Disabled && !k.IsExhausted(now));
            }
        }
    }

    /// <summary>When the next key frees up, or null when there are no keys at all.</summary>
    public DateTime? SoonestResetUtc
    {
        get
        {
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                var keys = _vault.Keys.Where(k => !k.Disabled).ToList();
                if (keys.Count == 0) return null;
                return keys.Select(k => k.SoonestResetUtc(now)).Min();
            }
        }
    }

    /// <summary>
    /// Returns an API key with one quota unit consumed. Blocks (with countdown) until a key
    /// frees up if all are exhausted. Throws if no keys are configured at all.
    /// </summary>
    public async Task<string> AcquireAsync(CancellationToken ct = default)
    {
        string? key = await AcquireAsync(Timeout.InfiniteTimeSpan, ct);
        return key ?? throw new InvalidOperationException(Strings.ErrNoKeysDefined);
    }

    /// <summary>As <see cref="AcquireAsync(CancellationToken)"/>, but gives up and returns null once
    /// <paramref name="maxWait"/> has passed with every key still exhausted.</summary>
    public async Task<string?> AcquireAsync(TimeSpan maxWait, CancellationToken ct = default)
    {
        bool waited = false;
        var deadline = maxWait == Timeout.InfiniteTimeSpan ? DateTime.MaxValue : DateTime.UtcNow + maxWait;
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
            if (now >= deadline) return null;

            var target = soonest ?? now.AddSeconds(30);
            var wait = target - now;
            if (wait < TimeSpan.FromSeconds(1)) wait = TimeSpan.FromSeconds(1);
            if (wait > TimeSpan.FromSeconds(60)) wait = TimeSpan.FromSeconds(60); // re-check at least once a minute
            if (deadline != DateTime.MaxValue && now + wait > deadline) wait = deadline - now;
            if (wait < TimeSpan.Zero) return null;

            if (!waited)
            {
                // Only announce once per wait, not on every re-check: the old code logged and raised the
                // "all exhausted" event on every loop, which flooded the UI thread during a long block.
                try { OnAllExhausted?.Invoke(target); } catch (Exception ex) { Log("OnAllExhausted handler failed: " + ex.Message, LogLevel.Warning); }
                Log($"All keys exhausted. Waiting for the soonest reset at {target:HH:mm:ss} UTC.", LogLevel.Warning);
            }
            waited = true;
            await Task.Delay(wait, ct);
        }
    }

    string? TryConsumeOne(out DateTime? soonestReset, out bool noKeys)
    {
        soonestReset = null;
        noKeys = false;
        bool consumed = false;
        string? result = null;
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
                    result = entry.Key;
                    consumed = true;
                    break;
                }
            }

            if (!consumed)
                soonestReset = keys.Select(k => k.SoonestResetUtc(now)).DefaultIfEmpty(now.AddSeconds(30)).Min();
        }

        // Outside the lock: persisting writes the config file, and the UI event fans out to the grid.
        if (consumed) { _vault.MaybePersistCounters(); _vault.RaiseCountersUpdated(); }
        return result;
    }

    /// <summary>A request on this key came back OK — the local model matches the server again.</summary>
    public void ReportSuccess(string key) => _consecutive429.TryRemove(key, out _);

    /// <summary>Marks a key's minute window full after a 429 so rotation skips it briefly. Repeated
    /// 429s with no success in between mean the DAILY allowance is really gone, so the key is parked
    /// until the next UTC day rather than retried every minute.</summary>
    public void ReportRateLimited(string key, TimeSpan? retryAfter)
    {
        int strikes = _consecutive429.AddOrUpdate(key, 1, (_, n) => n + 1);
        bool dailyGone;
        string masked;
        lock (_lock)
        {
            var e = _vault.Keys.FirstOrDefault(k => k.Key == key);
            if (e == null) return;
            masked = e.Masked;
            var now = DateTime.UtcNow;
            e.Minute.WindowStartUtc = now;
            e.Minute.Used = e.Minute.Allowed;

            // A long Retry-After says outright that this is daily/monthly exhaustion. VirusTotal
            // usually sends no Retry-After at all, so the strike count stands in for it.
            dailyGone = (retryAfter is { } ra && ra > TimeSpan.FromMinutes(5)) || strikes >= ConsecutiveRateLimitsMeansDaily;
            if (dailyGone)
            {
                e.Daily.Roll(now);
                e.Daily.Used = e.Daily.Allowed;
            }
        }

        if (dailyGone)
        {
            _consecutive429.TryRemove(key, out _);
            Log($"Key {masked}: {strikes} rate-limits in a row — treating its daily allowance as spent; parked until the next UTC day.", LogLevel.Warning);
            try { OnKeyDailyExhausted?.Invoke(masked); } catch (Exception ex) { Log("OnKeyDailyExhausted handler failed: " + ex.Message, LogLevel.Warning); }
        }
        else
        {
            Log($"Key {masked} rate-limited (429). Rotating.", LogLevel.Warning);
        }
        _vault.RaiseCountersUpdated();
    }

    /// <summary>
    /// Handles a 401/403. Disabling a key is permanent until the user edits it, so it only happens
    /// when VirusTotal itself says the credential is bad. A bare 403 is not that: an edge in front of
    /// VirusTotal answers 403 too, and fourteen working keys were once disabled in one morning
    /// because API traffic briefly went out through a Tor exit. An ambiguous 403 parks the key for a
    /// minute instead, exactly like a rate limit.
    /// </summary>
    public void ReportAuthError(string key, VtAuthException? ex = null)
    {
        bool credential = ex?.IsCredentialRejection ?? true;
        string masked;
        lock (_lock)
        {
            var e = _vault.Keys.FirstOrDefault(k => k.Key == key);
            if (e == null) return;
            masked = e.Masked;
            if (credential)
            {
                e.Disabled = true;
                e.LastError = $"Auth failed ({(int?)ex?.StatusCode ?? 401})";
            }
            else
            {
                e.Minute.WindowStartUtc = DateTime.UtcNow;
                e.Minute.Used = e.Minute.Allowed;
                e.LastError = "Blocked by an edge (403), not by VirusTotal";
            }
        }

        if (credential)
        {
            Log($"Key {masked} disabled: VirusTotal rejected the credential.", LogLevel.Error);
            _vault.Save();
        }
        else
        {
            Log($"Key {masked} got a 403 that does not name a credential problem — something in front of "
                + "VirusTotal refused it. Parked for a minute instead of disabled. Body: "
                + (string.IsNullOrEmpty(ex?.Body) ? "(empty)" : ex!.Body!.Length > 200 ? ex.Body[..200] + "…" : ex.Body), LogLevel.Warning);
            _vault.RaiseCountersUpdated();
        }
    }

    /// <summary>Clears the disabled flag on every key. For the case above: once the real cause is
    /// understood, the keys themselves were never the problem.</summary>
    public int ReEnableAll()
    {
        int n = 0;
        lock (_lock)
        {
            foreach (var e in _vault.Keys.Where(k => k.Disabled))
            {
                e.Disabled = false;
                e.LastError = null;
                n++;
            }
        }
        if (n > 0) { Log($"{n} key(s) re-enabled.", LogLevel.Info); _vault.Save(); }
        return n;
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
