using System.Collections.Concurrent;

namespace VirusTotalScanner;

/// <summary>One concrete network egress route a browser session can bind to without affecting other cells.</summary>
internal readonly record struct NetworkRoute(bool IsTor, int CircuitIndex, string? ProxyUrl, string Label)
{
    public static readonly NetworkRoute Direct = new(false, -1, null, "Direkt");
    public string Key => IsTor ? $"tor:{CircuitIndex}" : "direct";
}

/// <summary>
/// Manages direct and multi-circuit Tor egress routes independently per query cell.
///
/// Unlike the old global Tor on/off switch (where one cell toggling Tor broke every other in-flight
/// lookup), Tor runs as a background multi-port SOCKS5 daemon with <see cref="TorService.CircuitPortCount"/>
/// isolated SocksPorts. One cell can query directly (proxy=null) while another queries through Tor
/// circuit #2 and a third rotates to Tor circuit #5 — zero cross-cell interference.
/// </summary>
internal static class RoutePool
{
    sealed class RouteHealth
    {
        public int ConsecutiveBlocks;
        public int ConsecutiveFailures;
        public DateTime CooldownUntilUtc = DateTime.MinValue;
        public DateTime LastSuccessUtc = DateTime.MinValue;
    }

    static readonly ConcurrentDictionary<string, RouteHealth> Health = new(StringComparer.Ordinal);
    static int _circuitCursor;
    static long _lastTorAutoStartFailTicks;

    public static NetworkRoute Direct => NetworkRoute.Direct;

    public static bool CanUseTor => TorService.IsActive || TorService.IsBinaryAvailable;

    /// <summary>Picks the best starting route for a new query cell: honors user's Tor preference when
    /// healthy, or selects the least-cooled route if the preferred one was just rate-limited.</summary>
    public static NetworkRoute PickInitialRoute()
    {
        var now = DateTime.UtcNow;
        bool wantTor = Settings.UseTor && TorService.IsActive;
        if (wantTor)
        {
            if (TryPickHealthyTor(now, excludeCircuit: -1) is { } tor) return tor;
            if (!IsCooling(Direct.Key, now)) return Direct;
            return BuildTorRoute(NextCircuitIndex());
        }

        if (!IsCooling(Direct.Key, now)) return Direct;
        if (TorService.IsActive && TryPickHealthyTor(now, excludeCircuit: -1) is { } healthyTor)
            return healthyTor;
        return Direct;
    }

    /// <summary>Returns a Tor route on an isolated circuit port, starting Tor on-demand for this session
    /// (never mutating persisted Settings.UseTor) if needed. Returns null if Tor is unavailable.</summary>
    public static async Task<NetworkRoute?> AcquireTorRouteAsync(int excludeCircuit, bool requestNewnym, CancellationToken ct)
    {
        if (!TorService.IsActive)
        {
            // Don't hammer a broken/missing Tor install every second.
            long lastFail = Interlocked.Read(ref _lastTorAutoStartFailTicks);
            if (lastFail > 0 && DateTime.UtcNow.Ticks - lastFail < TimeSpan.FromMinutes(2).Ticks)
                return null;
            if (!TorService.IsBinaryAvailable) return null;

            bool started = await TorService.EnableAsync(ct);
            if (!started)
            {
                Interlocked.Exchange(ref _lastTorAutoStartFailTicks, DateTime.UtcNow.Ticks);
                return null;
            }
            Interlocked.Exchange(ref _lastTorAutoStartFailTicks, 0);
            UiStatusHub.Report(Strings.StatusSourceTor, TorService.StatusLine(), StatusSeverity.Info);
        }

        if (requestNewnym)
        {
            bool rotated = await TorService.NewCircuitAsync(ct);
            if (rotated) ClearTorCooldowns();
        }

        var now = DateTime.UtcNow;
        if (TryPickHealthyTor(now, excludeCircuit) is { } picked) return picked;

        int next = NextCircuitIndex();
        if (next == excludeCircuit && TorService.CircuitPortCount > 1)
            next = (next + 1) % TorService.CircuitPortCount;
        return BuildTorRoute(next);
    }

    public static void ReportSuccess(NetworkRoute route)
    {
        var h = Health.GetOrAdd(route.Key, _ => new RouteHealth());
        lock (h)
        {
            h.ConsecutiveBlocks = 0;
            h.ConsecutiveFailures = 0;
            h.CooldownUntilUtc = DateTime.MinValue;
            h.LastSuccessUtc = DateTime.UtcNow;
        }
    }

    /// <summary>Records an IP-level block (429/403/unanswered captcha) ONLY on this specific route so other
    /// routes stay open.</summary>
    public static void ReportBlocked(NetworkRoute route)
    {
        var h = Health.GetOrAdd(route.Key, _ => new RouteHealth());
        lock (h)
        {
            h.ConsecutiveBlocks++;
            // Brief, capped per-route cool-off (20s -> 40s -> 90s max); cells can still explicitly cross back later.
            int secs = Math.Min(90, 20 * (1 << Math.Min(2, h.ConsecutiveBlocks - 1)));
            h.CooldownUntilUtc = DateTime.UtcNow.AddSeconds(secs);
        }
    }

    public static void ReportTransportFailure(NetworkRoute route)
    {
        var h = Health.GetOrAdd(route.Key, _ => new RouteHealth());
        lock (h)
        {
            h.ConsecutiveFailures++;
            int secs = Math.Min(60, 10 * h.ConsecutiveFailures);
            h.CooldownUntilUtc = DateTime.UtcNow.AddSeconds(secs);
        }
    }

    public static void ResetAllHealth()
    {
        Health.Clear();
        Interlocked.Exchange(ref _lastTorAutoStartFailTicks, 0);
    }

    static bool IsCooling(string key, DateTime now)
    {
        if (!Health.TryGetValue(key, out var h)) return false;
        lock (h) return h.CooldownUntilUtc > now;
    }

    static NetworkRoute? TryPickHealthyTor(DateTime now, int excludeCircuit)
    {
        int count = TorService.CircuitPortCount;
        int start = NextCircuitIndex();
        for (int i = 0; i < count; i++)
        {
            int idx = (start + i) % count;
            if (idx == excludeCircuit && count > 1) continue;
            var candidate = BuildTorRoute(idx);
            if (candidate.ProxyUrl != null && !IsCooling(candidate.Key, now))
                return candidate;
        }
        return null;
    }

    static NetworkRoute BuildTorRoute(int idx)
    {
        int norm = ((idx % TorService.CircuitPortCount) + TorService.CircuitPortCount) % TorService.CircuitPortCount;
        string? proxy = TorService.GetCircuitProxy(norm);
        return proxy == null ? Direct : new NetworkRoute(true, norm, proxy, $"Tor #{norm + 1}");
    }

    static int NextCircuitIndex() =>
        Math.Abs(Interlocked.Increment(ref _circuitCursor)) % Math.Max(1, TorService.CircuitPortCount);

    static void ClearTorCooldowns()
    {
        foreach (var kv in Health)
        {
            if (!kv.Key.StartsWith("tor:", StringComparison.Ordinal)) continue;
            lock (kv.Value) { kv.Value.ConsecutiveBlocks = 0; kv.Value.CooldownUntilUtc = DateTime.MinValue; }
        }
    }
}
