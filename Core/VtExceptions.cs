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

/// <summary>HTTP 401/403 — the API key is wrong, disabled or lacks permission… or something in front
/// of VirusTotal refused the connection.</summary>
internal sealed class VtAuthException : VtApiException
{
    public VtAuthException(HttpStatusCode status, string? body = null)
        : base("VirusTotal authentication failed (HTTP " + (int)status + "). Check the API key.", status, body) { }

    /// <summary>
    /// True only when VirusTotal itself says the CREDENTIAL is bad. A 403 is not proof of that: an
    /// edge (Cloudflare, a proxy, a blocked exit address) answers 403 too, with HTML or nothing at
    /// all. Fourteen working keys were once permanently disabled in one morning because API traffic
    /// briefly went out through a Tor exit and every 403 was read as "bad key".
    /// </summary>
    public bool IsCredentialRejection
    {
        get
        {
            if (StatusCode == HttpStatusCode.Unauthorized) return true;         // 401 is unambiguous
            if (StatusCode != HttpStatusCode.Forbidden) return false;
            string b = Body ?? "";
            // VirusTotal answers a real permission problem with its own JSON error code.
            return b.Contains("WrongCredentialsError", StringComparison.OrdinalIgnoreCase)
                || b.Contains("UserNotActiveError", StringComparison.OrdinalIgnoreCase)
                || b.Contains("ForbiddenError", StringComparison.OrdinalIgnoreCase)
                || b.Contains("NotAvailableYet", StringComparison.OrdinalIgnoreCase);
        }
    }
}
