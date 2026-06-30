using System.Text.Json.Serialization;

namespace VirusTotalScanner;

internal enum WindowKind { Minute, Daily, Monthly }

/// <summary>
/// One usage window for an API key. Minute is a sliding 60s window; Daily/Monthly are
/// aligned to UTC calendar boundaries (matching VirusTotal's reset behaviour). Counters
/// persist (serialized) so daily/monthly survive app restarts.
/// </summary>
internal sealed class QuotaWindow
{
    public WindowKind Kind { get; set; }
    public long Allowed { get; set; }
    public long Used { get; set; }
    public DateTime WindowStartUtc { get; set; }

    public QuotaWindow() { }

    public QuotaWindow(WindowKind kind, long allowed)
    {
        Kind = kind;
        Allowed = allowed;
    }

    /// <summary>Resets the counter if the current window has elapsed.</summary>
    public void Roll(DateTime nowUtc)
    {
        switch (Kind)
        {
            case WindowKind.Minute:
                if (WindowStartUtc != default && nowUtc - WindowStartUtc >= TimeSpan.FromMinutes(1))
                {
                    Used = 0;
                    WindowStartUtc = default;
                }
                break;
            case WindowKind.Daily:
                var day = DateTime.SpecifyKind(nowUtc.Date, DateTimeKind.Utc);
                if (WindowStartUtc != day) { WindowStartUtc = day; Used = 0; }
                break;
            case WindowKind.Monthly:
                var month = new DateTime(nowUtc.Year, nowUtc.Month, 1, 0, 0, 0, DateTimeKind.Utc);
                if (WindowStartUtc != month) { WindowStartUtc = month; Used = 0; }
                break;
        }
    }

    [JsonIgnore] public bool HasRoom => Used < Allowed;
    [JsonIgnore] public long Remaining => Math.Max(0, Allowed - Used);

    public void Consume(DateTime nowUtc)
    {
        if (Kind == WindowKind.Minute && Used == 0) WindowStartUtc = nowUtc;
        Used++;
    }

    /// <summary>When this window's counter next resets.</summary>
    [JsonIgnore]
    public DateTime ResetUtc => Kind switch
    {
        WindowKind.Minute => (WindowStartUtc == default ? DateTime.UtcNow : WindowStartUtc).AddMinutes(1),
        WindowKind.Daily => WindowStartUtc.AddDays(1),
        WindowKind.Monthly => WindowStartUtc.AddMonths(1),
        _ => DateTime.UtcNow,
    };
}
