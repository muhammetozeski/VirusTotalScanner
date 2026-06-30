using System.Text.Json.Serialization;

namespace VirusTotalScanner;

/// <summary>
/// One VirusTotal API key plus its local quota counters. The whole list is JSON-serialized
/// then DPAPI-encrypted into the single config setting (EncryptedKeyVault), so the key text
/// is never stored in clear.
/// </summary>
internal sealed class ApiKeyEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Label { get; set; } = "";
    public string Key { get; set; } = "";

    /// <summary>Disabled after an auth failure (401/403) so rotation skips it.</summary>
    public bool Disabled { get; set; }
    public string? LastError { get; set; }

    public QuotaWindow Minute { get; set; } = new(WindowKind.Minute, AppConstants.RatePerMinute);
    public QuotaWindow Daily { get; set; } = new(WindowKind.Daily, AppConstants.QuotaPerDay);
    public QuotaWindow Monthly { get; set; } = new(WindowKind.Monthly, AppConstants.QuotaPerMonth);

    public static ApiKeyEntry Create(string label, string key) => new()
    {
        Label = string.IsNullOrWhiteSpace(label) ? "Key" : label.Trim(),
        Key = key.Trim(),
    };

    /// <summary>Masked form for display, e.g. "c288…a2b9".</summary>
    [JsonIgnore]
    public string Masked
    {
        get
        {
            var k = Key ?? "";
            if (k.Length <= 10) return new string('•', Math.Max(4, k.Length));
            return k[..4] + "…" + k[^4..];
        }
    }

    /// <summary>True if any window is full (the key can't be used right now).</summary>
    public bool IsExhausted(DateTime nowUtc)
    {
        Minute.Roll(nowUtc); Daily.Roll(nowUtc); Monthly.Roll(nowUtc);
        return !(Minute.HasRoom && Daily.HasRoom && Monthly.HasRoom);
    }

    /// <summary>Consumes one request unit from all three windows if all have room.</summary>
    public bool TryConsume(DateTime nowUtc)
    {
        Minute.Roll(nowUtc); Daily.Roll(nowUtc); Monthly.Roll(nowUtc);
        if (!(Minute.HasRoom && Daily.HasRoom && Monthly.HasRoom)) return false;
        Minute.Consume(nowUtc); Daily.Consume(nowUtc); Monthly.Consume(nowUtc);
        return true;
    }

    /// <summary>Earliest time a full window resets (when the key may be usable again).</summary>
    public DateTime SoonestResetUtc(DateTime nowUtc)
    {
        Minute.Roll(nowUtc); Daily.Roll(nowUtc); Monthly.Roll(nowUtc);
        var full = new List<DateTime>();
        if (!Minute.HasRoom) full.Add(Minute.ResetUtc);
        if (!Daily.HasRoom) full.Add(Daily.ResetUtc);
        if (!Monthly.HasRoom) full.Add(Monthly.ResetUtc);
        return full.Count == 0 ? nowUtc : full.Min();
    }
}
