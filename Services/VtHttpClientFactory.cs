namespace VirusTotalScanner;

/// <summary>
/// Single shared HttpClient. The API key is NOT a default header — it is added per request
/// so the client can round-robin between keys. Timeout is generous (large uploads); real
/// cancellation comes from the per-request CancellationToken.
/// </summary>
internal static class VtHttpClientFactory
{
    static readonly Lazy<HttpClient> _client = new(() =>
    {
        var c = new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(15),
        };
        c.DefaultRequestHeaders.UserAgent.ParseAdd($"{AppConstants.AppFolderName}/{AppConstants.Version}");
        return c;
    });

    public static HttpClient Client => _client.Value;
}
