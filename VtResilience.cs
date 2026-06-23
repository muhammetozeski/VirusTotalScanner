using Polly;
using Polly.Retry;

namespace VirusTotalScanner;

/// <summary>
/// Polly pipeline for VirusTotal GET requests: retries transient transport failures and
/// 5xx with exponential backoff + jitter. HTTP 429 is deliberately NOT handled here — it is
/// surfaced as <see cref="VtRateLimitException"/> so the key rotator can switch keys/wait.
/// Uploads do not use this pipeline (retrying a stream upload is not safe/cheap).
/// </summary>
internal static class VtResilience
{
    public static readonly ResiliencePipeline<HttpResponseMessage> Pipeline = Build();

    static ResiliencePipeline<HttpResponseMessage> Build()
    {
        return new ResiliencePipelineBuilder<HttpResponseMessage>()
            .AddRetry(new RetryStrategyOptions<HttpResponseMessage>
            {
                ShouldHandle = new PredicateBuilder<HttpResponseMessage>()
                    .Handle<HttpRequestException>()
                    .Handle<IOException>()
                    .HandleResult(r => (int)r.StatusCode >= 500),
                MaxRetryAttempts = 3,
                BackoffType = DelayBackoffType.Exponential,
                UseJitter = true,
                Delay = TimeSpan.FromSeconds(2),
                OnRetry = args =>
                {
                    Log($"VT request retry #{args.AttemptNumber} after {args.RetryDelay.TotalSeconds:F1}s " +
                        $"(reason: {args.Outcome.Exception?.Message ?? args.Outcome.Result?.StatusCode.ToString()})",
                        LogLevel.Warning);
                    return default;
                },
            })
            .Build();
    }
}
