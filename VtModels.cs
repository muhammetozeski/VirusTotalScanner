using System.Text.Json.Serialization;

namespace VirusTotalScanner;

// ---------------------------------------------------------------------------
// JSON DTOs (wire format) for VirusTotal API v3
// ---------------------------------------------------------------------------

internal sealed class VtResponse<T>
{
    [JsonPropertyName("data")] public T? Data { get; set; }
}

internal sealed class VtCommentData
{
    [JsonPropertyName("attributes")] public VtCommentAttributes? Attributes { get; set; }
}

internal sealed class VtCommentAttributes
{
    [JsonPropertyName("date")] public long Date { get; set; }
    [JsonPropertyName("text")] public string? Text { get; set; }
    [JsonPropertyName("tags")] public List<string>? Tags { get; set; }
}

/// <summary>A community comment on a file (date + text + tags), from the keyless GUI comments fetch.</summary>
internal sealed class VtComment
{
    public DateTime? Date { get; set; }
    public string? Text { get; set; }
    public List<string> Tags { get; set; } = [];
}

// ---- sandbox behaviour summary (/ui/files/<hash>/behaviour_summary) ----

internal sealed class VtBehaviourReportData
{
    [JsonPropertyName("attributes")] public VtBehaviourDto? Attributes { get; set; }
}

internal sealed class VtBehaviourDto
{
    [JsonPropertyName("dns_lookups")] public List<VtDnsDto>? DnsLookups { get; set; }
    [JsonPropertyName("ip_traffic")] public List<VtIpDto>? IpTraffic { get; set; }
    [JsonPropertyName("files_written")] public List<string>? FilesWritten { get; set; }
    [JsonPropertyName("files_dropped")] public List<VtDroppedDto>? FilesDropped { get; set; }
    [JsonPropertyName("registry_keys_set")] public List<VtRegistryDto>? RegistryKeysSet { get; set; }
    [JsonPropertyName("processes_created")] public List<string>? ProcessesCreated { get; set; }
    [JsonPropertyName("mitre_attack_techniques")] public List<VtMitreDto>? Mitre { get; set; }
}

internal sealed class VtDnsDto { [JsonPropertyName("hostname")] public string? Hostname { get; set; } }
internal sealed class VtIpDto { [JsonPropertyName("destination_ip")] public string? DestinationIp { get; set; } }
internal sealed class VtDroppedDto { [JsonPropertyName("path")] public string? Path { get; set; } }
internal sealed class VtRegistryDto { [JsonPropertyName("key")] public string? Key { get; set; } }
internal sealed class VtMitreDto
{
    [JsonPropertyName("id")] public string? Id { get; set; }
    [JsonPropertyName("signature_description")] public string? Description { get; set; }
}

/// <summary>"What this file does when run" — flattened sandbox behaviour for display.</summary>
internal sealed class VtBehaviour
{
    public List<string> Network { get; set; } = [];
    public List<string> FilesWritten { get; set; } = [];
    public List<string> Registry { get; set; } = [];
    public List<string> Processes { get; set; } = [];
    public List<string> Mitre { get; set; } = [];
    public bool Any => Network.Count + FilesWritten.Count + Registry.Count + Processes.Count + Mitre.Count > 0;
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
    [JsonPropertyName("first_submission_date")] public long FirstSubmissionDate { get; set; }
    [JsonPropertyName("last_submission_date")] public long LastSubmissionDate { get; set; }
    [JsonPropertyName("total_votes")] public VtVotesDto? TotalVotes { get; set; }
    [JsonPropertyName("tags")] public List<string>? Tags { get; set; }
    [JsonPropertyName("popular_threat_classification")] public VtThreatClassDto? ThreatClassification { get; set; }
    [JsonPropertyName("sigma_analysis_results")] public List<VtSigmaDto>? SigmaResults { get; set; }
    [JsonPropertyName("crowdsourced_ids_results")] public List<VtIdsDto>? IdsResults { get; set; }
    [JsonPropertyName("crowdsourced_yara_results")] public List<VtYaraDto>? YaraResults { get; set; }
}

internal sealed class VtSigmaDto
{
    [JsonPropertyName("rule_title")] public string? RuleTitle { get; set; }
    [JsonPropertyName("rule_level")] public string? RuleLevel { get; set; }
}

internal sealed class VtIdsDto
{
    [JsonPropertyName("rule_msg")] public string? RuleMsg { get; set; }
    [JsonPropertyName("alert_severity")] public string? Severity { get; set; }
}

internal sealed class VtYaraDto
{
    [JsonPropertyName("rule_name")] public string? RuleName { get; set; }
    [JsonPropertyName("author")] public string? Author { get; set; }
}

internal sealed class VtThreatClassDto
{
    [JsonPropertyName("suggested_threat_label")] public string? SuggestedLabel { get; set; }
}

internal sealed class VtVotesDto
{
    [JsonPropertyName("harmless")] public int Harmless { get; set; }
    [JsonPropertyName("malicious")] public int Malicious { get; set; }
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
    public int TimesSubmitted { get; set; }
    public DateTime? FirstSeenUtc { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public int VotesHarmless { get; set; }
    public int VotesMalicious { get; set; }

    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Harmless { get; set; }
    public int Undetected { get; set; }
    public int Timeout { get; set; }

    public List<VtEngineResult> Engines { get; set; } = [];

    /// <summary>Major-engine names that flagged this file; stored so it survives in the summary cache.</summary>
    public List<string> MajorFlaggers { get; set; } = [];

    /// <summary>Most-common normalized malware family across engines (e.g. "Swrort"), and how many
    /// engines agree. Stored so it survives in the summary cache.</summary>
    public string? Family { get; set; }
    public int FamilyCount { get; set; }

    /// <summary>VT capability/behavior tags (e.g. "checks-network-adapters", "long-sleeps") and the
    /// crowd-suggested threat label. Both come straight from the file report (no extra request).</summary>
    public List<string> Tags { get; set; } = [];
    public string? ThreatLabel { get; set; }

    /// <summary>How many detections are signature-based (engine method == "blacklist") vs heuristic/ML.
    /// Stored so it survives in the summary cache. A heuristic-only detection set is a strong FP tell.</summary>
    public int SignatureHits { get; set; }

    /// <summary>Detections coming from engines whose signature DB is older than the configured
    /// threshold — a weak/possibly-stale signal worth re-checking. Stored in the summary cache.</summary>
    public int StaleDetections { get; set; }

    [JsonIgnore]
    public string? StaleText => StaleDetections == 0 || DetectionCount == 0 ? null
        : string.Format(Strings.StaleTextFormat, StaleDetections, DetectionCount);

    /// <summary>Crowdsourced rule hits (Sigma / IDS / YARA) that name WHY a file is flagged, formatted
    /// for display. Already in the report JSON; stored so it survives in the summary cache.</summary>
    public List<string> CommunityRules { get; set; } = [];

    [JsonIgnore]
    public string? CommunityRulesText => CommunityRules.Count == 0 ? null
        : string.Format(Strings.CommunityRulesPrefixFormat, CommunityRules.Count) + string.Join("  •  ", CommunityRules.Take(5))
          + (CommunityRules.Count > 5 ? string.Format(Strings.MoreParenFormat, CommunityRules.Count - 5) : "");

    [JsonIgnore] public int HeuristicOnlyHits => Math.Max(0, DetectionCount - SignatureHits);
    [JsonIgnore] public bool HeuristicOnly => DetectionCount > 0 && SignatureHits == 0;

    /// <summary>"Real match vs a guess" — the detection-confidence line for the detail pane / CLI.</summary>
    [JsonIgnore]
    public string? ConfidenceText =>
        DetectionCount == 0 ? null
        : HeuristicOnly ? Strings.ConfidenceHeuristic
        : string.Format(Strings.ConfidenceSigFormat, SignatureHits, HeuristicOnlyHits);

    [JsonIgnore]
    public string? CapabilitySummary => BehaviorTags.Summarize(Tags, ThreatLabel);

    [JsonIgnore]
    public string? FamilyLabel => string.IsNullOrEmpty(Family) ? null
        : string.Format(Strings.FamilyLabelFormat, Family) + (FamilyCount > 1 ? string.Format(Strings.FamilyMotorFormat, FamilyCount) : "");

    [JsonIgnore] public IEnumerable<VtEngineResult> Detections => Engines.Where(e => e.IsDetection);
    [JsonIgnore] public int DetectionCount => Malicious + Suspicious;
    [JsonIgnore] public int TotalEngines => Malicious + Suspicious + Harmless + Undetected + Timeout;
    [JsonIgnore] public int MajorDetectionCount => MajorFlaggers.Count;
    [JsonIgnore] public int MinorDetectionCount => Math.Max(0, DetectionCount - MajorDetectionCount);
    /// <summary>True when there are detections but no major/high-reputation engine flagged it
    /// (the classic false-positive shape).</summary>
    [JsonIgnore] public bool MajorClean => TotalEngines > 0 && DetectionCount > 0 && MajorDetectionCount == 0;
    /// <summary>A "threat" per the user's verdict categories (e.g. 1 detection may count as clean).</summary>
    [JsonIgnore] public bool IsMalicious => TotalEngines > 0 && VerdictCategories.IsThreat(DetectionCount);
    [JsonIgnore] public string ReportUrl => AppConstants.VtGuiFile + (Sha256 ?? Md5 ?? Sha1 ?? string.Empty);

    [JsonIgnore]
    public string Verdict => TotalEngines > 0 ? VerdictCategories.Classify(DetectionCount).Name : Strings.VerdictUnknown;

    /// <summary>Age + prevalence line: a 0/70 on a file the world first saw minutes ago is very
    /// different from a 0/70 on a years-old, widely-seen file.</summary>
    [JsonIgnore]
    public string? FirstSeenText
    {
        get
        {
            if (FirstSeenUtc is not { } first) return null;
            var age = DateTime.UtcNow - first;
            string ageStr = age.TotalDays >= 365 ? string.Format(Strings.AgeYearsFormat, (int)(age.TotalDays / 365))
                : age.TotalDays >= 1 ? string.Format(Strings.AgeDaysFormat, (int)age.TotalDays)
                : age.TotalHours >= 1 ? string.Format(Strings.AgeHoursFormat, (int)age.TotalHours)
                : string.Format(Strings.AgeMinutesFormat, (int)age.TotalMinutes);
            string prev = TimesSubmitted > 0 ? string.Format(Strings.SubmissionsFormat, TimesSubmitted) : "";
            string rare = age.TotalDays < 2 ? Strings.VeryNew : "";
            return string.Format(Strings.FirstSeenFormat, first.ToString("yyyy-MM-dd"), ageStr, prev, rare);
        }
    }

    /// <summary>Community vote tally, shown when the user enables it. A strong harmless lean is
    /// a useful false-positive signal (e.g. a game exe the community marked clean).</summary>
    [JsonIgnore]
    public string? VotesText => (VotesHarmless > 0 || VotesMalicious > 0)
        ? string.Format(Strings.VotesTextFormat, VotesHarmless, VotesMalicious)
        : null;

    /// <summary>"Who flagged it" — splits detections into major vs minor engines so a few
    /// obscure-engine hits read as a likely false positive.</summary>
    [JsonIgnore]
    public string? ConsensusText
    {
        get
        {
            if (TotalEngines == 0) return null;
            if (DetectionCount == 0) return Strings.ConsensusNoneFlagged;
            string majors = MajorFlaggers.Count > 0 ? "  →  " + string.Join(", ", MajorFlaggers.Take(6)) : "";
            string hint = MajorClean ? Strings.ConsensusMajorCleanHint : "";
            return string.Format(Strings.ConsensusFormat, MajorDetectionCount, MinorDetectionCount, majors, hint);
        }
    }
}

internal sealed class VtEngineResult
{
    public string EngineName { get; set; } = "";
    public string? EngineVersion { get; set; }
    public string? Category { get; set; }
    public string? Result { get; set; }
    public string? Method { get; set; }
    public string? EngineUpdate { get; set; } // yyyymmdd, the engine's signature-DB date

    [JsonIgnore] public bool IsDetection => Category is "malicious" or "suspicious";

    [JsonIgnore]
    public DateTime? UpdatedUtc =>
        DateTime.TryParseExact(EngineUpdate, "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var d)
            ? d : null;
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
