using System.Text.Json.Serialization;

namespace VirusTotalScanner;

// ---------------------------------------------------------------------------
// JSON DTOs (wire format) for VirusTotal API v3
// ---------------------------------------------------------------------------

internal sealed class VtResponse<T>
{
    [JsonPropertyName("data")] public T? Data { get; set; }
}

internal sealed class VtFileData
{
    [JsonPropertyName("attributes")] public VtFileAttributes? Attributes { get; set; }
}

internal sealed class VtFileAttributes
{
    [JsonPropertyName("last_analysis_stats")] public VtStatsDto? Stats { get; set; }
    [JsonPropertyName("last_analysis_results")] public Dictionary<string, VtEngineDto>? Results { get; set; }
    [JsonPropertyName("meaningful_name")] public string? MeaningfulName { get; set; }
    [JsonPropertyName("type_description")] public string? TypeDescription { get; set; }
    [JsonPropertyName("type_tag")] public string? TypeTag { get; set; }
    [JsonPropertyName("md5")] public string? Md5 { get; set; }
    [JsonPropertyName("sha1")] public string? Sha1 { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("size")] public long Size { get; set; }
    [JsonPropertyName("reputation")] public int Reputation { get; set; }
    [JsonPropertyName("times_submitted")] public int TimesSubmitted { get; set; }
}

internal sealed class VtStatsDto
{
    [JsonPropertyName("malicious")] public int Malicious { get; set; }
    [JsonPropertyName("suspicious")] public int Suspicious { get; set; }
    [JsonPropertyName("harmless")] public int Harmless { get; set; }
    [JsonPropertyName("undetected")] public int Undetected { get; set; }
    [JsonPropertyName("timeout")] public int Timeout { get; set; }
    [JsonPropertyName("type-unsupported")] public int TypeUnsupported { get; set; }
    [JsonPropertyName("failure")] public int Failure { get; set; }
}

internal sealed class VtEngineDto
{
    [JsonPropertyName("engine_name")] public string? EngineName { get; set; }
    [JsonPropertyName("engine_version")] public string? EngineVersion { get; set; }
    [JsonPropertyName("category")] public string? Category { get; set; }
    [JsonPropertyName("result")] public string? Result { get; set; }
    [JsonPropertyName("method")] public string? Method { get; set; }
    [JsonPropertyName("engine_update")] public string? EngineUpdate { get; set; }
}

internal sealed class VtUploadData
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("type")] public string? Type { get; set; }
}

internal sealed class VtAnalysisData
{
    [JsonPropertyName("attributes")] public VtAnalysisAttributes? Attributes { get; set; }
}

internal sealed class VtAnalysisAttributes
{
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("stats")] public VtStatsDto? Stats { get; set; }
}

internal sealed class VtUserData
{
    [JsonPropertyName("attributes")] public VtUserAttributes? Attributes { get; set; }
}

internal sealed class VtUserAttributes
{
    [JsonPropertyName("quotas")] public VtQuotasDto? Quotas { get; set; }
}

internal sealed class VtQuotasDto
{
    [JsonPropertyName("api_requests_hourly")] public VtQuotaSlotDto? Hourly { get; set; }
    [JsonPropertyName("api_requests_daily")] public VtQuotaSlotDto? Daily { get; set; }
    [JsonPropertyName("api_requests_monthly")] public VtQuotaSlotDto? Monthly { get; set; }
}

internal sealed class VtQuotaSlotDto
{
    [JsonPropertyName("used")] public long Used { get; set; }
    [JsonPropertyName("allowed")] public long Allowed { get; set; }
}

// ---------------------------------------------------------------------------
// Domain models (what the rest of the app consumes)
// ---------------------------------------------------------------------------

/// <summary>A clean, UI-friendly view of a VirusTotal file report.</summary>
internal sealed class VtFileReport
{
    public string? Md5 { get; set; }
    public string? Sha1 { get; set; }
    public string? Sha256 { get; set; }
    public string? MeaningfulName { get; set; }
    public string? TypeDescription { get; set; }
    public long Size { get; set; }
    public int Reputation { get; set; }

    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Harmless { get; set; }
    public int Undetected { get; set; }
    public int Timeout { get; set; }

    public List<VtEngineResult> Engines { get; set; } = [];

    [JsonIgnore] public IEnumerable<VtEngineResult> Detections => Engines.Where(e => e.IsDetection);
    [JsonIgnore] public int DetectionCount => Malicious + Suspicious;
    [JsonIgnore] public int TotalEngines => Malicious + Suspicious + Harmless + Undetected + Timeout;
    [JsonIgnore] public bool IsMalicious => Malicious > 0 || Suspicious > 0;
    [JsonIgnore] public string ReportUrl => AppConstants.VtGuiFile + (Sha256 ?? Md5 ?? Sha1 ?? string.Empty);

    [JsonIgnore]
    public string Verdict =>
        Malicious > 0 ? "ZARARLI" :
        Suspicious > 0 ? "ŞÜPHELİ" :
        TotalEngines > 0 ? "TEMİZ" : "BİLİNMİYOR";
}

internal sealed class VtEngineResult
{
    public string EngineName { get; set; } = "";
    public string? EngineVersion { get; set; }
    public string? Category { get; set; }
    public string? Result { get; set; }
    public string? Method { get; set; }
    [JsonIgnore] public bool IsDetection => Category is "malicious" or "suspicious";
}

internal sealed class VtAnalysisInfo
{
    public string Status { get; set; } = "";
    public bool IsCompleted => string.Equals(Status, "completed", StringComparison.OrdinalIgnoreCase);
}

internal sealed class VtQuotas
{
    public VtQuotaSlot Hourly { get; set; } = new();
    public VtQuotaSlot Daily { get; set; } = new();
    public VtQuotaSlot Monthly { get; set; } = new();
}

internal sealed class VtQuotaSlot
{
    public long Used { get; set; }
    public long Allowed { get; set; }
}

internal sealed class UploadProgress
{
    public long BytesSent { get; set; }
    public long TotalBytes { get; set; }
    public long BytesPerSecond { get; set; }
    public double Percent => TotalBytes > 0 ? (double)BytesSent / TotalBytes * 100 : 0;
}
