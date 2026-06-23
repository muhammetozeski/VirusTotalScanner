using System.Net;

namespace VirusTotalScanner;

/// <summary>Base for VirusTotal API failures.</summary>
internal class VtApiException : Exception
{
    public HttpStatusCode? StatusCode { get; }
    public string? Body { get; }

    public VtApiException(string message, HttpStatusCode? status = null, string? body = null) : base(message)
    {
        StatusCode = status;
        Body = body;
    }
}

/// <summary>HTTP 429 — rate (4/min) or quota (daily/monthly) exhausted for this key.</summary>
internal sealed class VtRateLimitException : VtApiException
{
    public TimeSpan? RetryAfter { get; }

    public VtRateLimitException(TimeSpan? retryAfter, string? body = null)
        : base("VirusTotal rate/quota limit reached (HTTP 429).", HttpStatusCode.TooManyRequests, body)
    {
        RetryAfter = retryAfter;
    }
}

/// <summary>HTTP 401/403 — the API key is wrong, disabled or lacks permission.</summary>
internal sealed class VtAuthException : VtApiException
{
    public VtAuthException(HttpStatusCode status, string? body = null)
        : base("VirusTotal authentication failed (HTTP " + (int)status + "). Check the API key.", status, body) { }
}
