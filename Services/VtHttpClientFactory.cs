using System.Net;

namespace VirusTotalScanner;

/// <summary>
/// Shared HttpClient. The API key is NOT a default header — it is added per request so the client
/// can round-robin between keys. Timeout is generous (large uploads); real cancellation comes from
/// the per-request CancellationToken.
///
/// The client is rebuilt whenever <see cref="TorService"/> is switched on or off, because the proxy
/// belongs to the handler and a handler cannot be re-pointed once it has been used. The previous
/// client is deliberately NOT disposed on the spot: requests already in flight would be aborted
/// mid-upload. It is parked and disposed once it has been idle long enough to be safe.
/// </summary>
internal static class VtHttpClientFactory
{
    static readonly object _lock = new();
    static HttpClient? _client;
    static string? _clientProxy;                    // the proxy the live client was built with
    static readonly List<(HttpClient Client, DateTime RetireUtc)> _retired = [];

    public static HttpClient Client
    {
        get
        {
            lock (_lock)
            {
                // The API is authenticated by key and is not limited by source address, so routing it
                // through Tor buys nothing and costs latency plus the risk of an exit VirusTotal's edge
                // refuses. Only the keyless browser needs a different address; this is opt-in.
                string? want = Settings.TorRouteApi ? TorService.ProxyUrl : null;
                if (_client != null && _clientProxy == want) { SweepRetired(); return _client; }
                Rebuild(want);
                return _client!;
            }
        }
    }

    /// <summary>Drops the current client so the next call rebuilds it (called when Tor toggles).</summary>
    public static void Invalidate()
    {
        lock (_lock)
        {
            if (_client == null) return;
            Retire(_client);
            _client = null;
            _clientProxy = null;
        }
        Log("VirusTotal HTTP client invalidated (proxy change).", LogLevel.Info);
    }

    static void Rebuild(string? proxyUrl)
    {
        if (_client != null) Retire(_client);
        try
        {
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.All,
            };
            if (!string.IsNullOrEmpty(proxyUrl))
            {
                handler.Proxy = new WebProxy(proxyUrl);
                handler.UseProxy = true;
            }
            var c = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(15) };
            c.DefaultRequestHeaders.UserAgent.ParseAdd($"{AppConstants.AppFolderName}/{AppConstants.Version}");
            _client = c;
            _clientProxy = proxyUrl;
            Log("VirusTotal HTTP client built " + (proxyUrl == null ? "without a proxy." : "through " + proxyUrl), LogLevel.Info);
        }
        catch (Exception ex)
        {
            // Never leave the app without a client: fall back to a plain direct one.
            Log("Proxied HTTP client build failed, falling back to direct: " + ex, LogLevel.Error);
            try
            {
                var c = new HttpClient { Timeout = TimeSpan.FromMinutes(15) };
                c.DefaultRequestHeaders.UserAgent.ParseAdd($"{AppConstants.AppFolderName}/{AppConstants.Version}");
                _client = c;
                _clientProxy = null;
            }
            catch (Exception inner)
            {
                Log("Direct HTTP client build ALSO failed: " + inner, LogLevel.Error);
                throw;
            }
        }
    }

    static void Retire(HttpClient old)
    {
        // 20 minutes covers the 15-minute request timeout plus slack, so nothing in flight is cut.
        _retired.Add((old, DateTime.UtcNow.AddMinutes(20)));
        SweepRetired();
    }

    static void SweepRetired()
    {
        for (int i = _retired.Count - 1; i >= 0; i--)
        {
            if (_retired[i].RetireUtc > DateTime.UtcNow) continue;
            try { _retired[i].Client.Dispose(); }
            catch (Exception ex) { Log("Retired HTTP client dispose failed: " + ex.Message, LogLevel.Warning); }
            finally { _retired.RemoveAt(i); }
        }
    }
}
