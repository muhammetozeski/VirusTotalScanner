using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalScanner;

internal sealed class HashCacheEntry
{
    public string Md5 { get; set; } = "";
    public string? Sha256 { get; set; }
    public DateTime CachedUtc { get; set; }

    /// <summary>Last on-disk path this hash was seen at (for the folder-neighbors view).</summary>
    public string? LastPath { get; set; }

    // Explicitly recorded so cache.json is self-documenting (the user's ask): VT link + threat count.
    public string? ReportUrl { get; set; }
    public int Detections { get; set; }
    public int TotalEngines { get; set; }

    public VtFileReport? Report { get; set; }

    [JsonIgnore] public bool IsMalicious => Report?.IsMalicious ?? false;
}

/// <summary>
/// Local md5 -> report cache so repeat scans of known files don't spend VirusTotal quota.
/// Persisted to %AppData%\VirusTotalScanner\hashcache.json. Never caches unknown (404) files.
/// </summary>
internal sealed class HashCache
{
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    readonly ConcurrentDictionary<string, HashCacheEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    readonly object _saveLock = new();
    DateTime _lastSaveUtc = DateTime.MinValue;
    bool _dirty;

    public void Load()
    {
        try
        {
            string path = ConfigPathResolver.HashCachePath;
            if (!File.Exists(path)) return;
            var list = JsonSerializer.Deserialize<List<HashCacheEntry>>(File.ReadAllText(path), JsonOpts);
            if (list != null)
                foreach (var e in list)
                    if (!string.IsNullOrEmpty(e.Md5)) _entries[e.Md5] = e;
            Log($"Hash cache loaded: {_entries.Count} entr(ies).", LogLevel.Info);
        }
        catch (Exception ex) { Log("Hash cache load failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Returns a cached report if present and fresh enough (within ttlDays).</summary>
    public VtFileReport? TryGet(string md5, int ttlDays)
    {
        if (!_entries.TryGetValue(md5, out var e) || e.Report == null) return null;
        if (ttlDays > 0 && DateTime.UtcNow - e.CachedUtc > TimeSpan.FromDays(ttlDays)) return null;
        return e.Report;
    }

    /// <summary>As <see cref="TryGet(string,int)"/> but with a separate, longer retention for malicious
    /// verdicts: a clean result can go stale (a file later flagged) so it expires sooner, but a
    /// known-malicious verdict almost never reverses and shouldn't burn quota re-confirming itself.</summary>
    public VtFileReport? TryGet(string md5, int cleanDays, int threatDays)
    {
        if (!_entries.TryGetValue(md5, out var e) || e.Report == null) return null;
        int ttl = e.Report.IsMalicious ? threatDays : cleanDays;
        if (ttl > 0 && DateTime.UtcNow - e.CachedUtc > TimeSpan.FromDays(ttl)) return null;
        return e.Report;
    }

    public void Put(string md5, VtFileReport report, string? sourcePath = null)
    {
        // Preserve a previously-recorded path when this Put has none (e.g. a hash-only re-check).
        if (sourcePath == null && _entries.TryGetValue(md5, out var prev)) sourcePath = prev.LastPath;

        // Store only the summary (no per-engine list) to keep cache.json small; the engine
        // table is re-fetched if the user re-scans.
        var compact = new VtFileReport
        {
            Md5 = report.Md5,
            Sha1 = report.Sha1,
            Sha256 = report.Sha256,
            MeaningfulName = report.MeaningfulName,
            TypeDescription = report.TypeDescription,
            Size = report.Size,
            Reputation = report.Reputation,
            TimesSubmitted = report.TimesSubmitted,
            FirstSeenUtc = report.FirstSeenUtc,
            LastSeenUtc = report.LastSeenUtc,
            VotesHarmless = report.VotesHarmless,
            VotesMalicious = report.VotesMalicious,
            Malicious = report.Malicious,
            Suspicious = report.Suspicious,
            Harmless = report.Harmless,
            Undetected = report.Undetected,
            Timeout = report.Timeout,
            MajorFlaggers = report.MajorFlaggers,
            Family = report.Family,
            FamilyCount = report.FamilyCount,
            Tags = report.Tags,
            ThreatLabel = report.ThreatLabel,
            SignatureHits = report.SignatureHits,
            StaleDetections = report.StaleDetections,
            CommunityRules = report.CommunityRules,
        };
        _entries[md5] = new HashCacheEntry
        {
            Md5 = md5,
            Sha256 = report.Sha256,
            CachedUtc = DateTime.UtcNow,
            LastPath = sourcePath,
            ReportUrl = report.ReportUrl,
            Detections = report.DetectionCount,
            TotalEngines = report.TotalEngines,
            Report = compact,
        };
        _dirty = true;
        MaybeSave();
    }

    public int Count => _entries.Count;

    /// <summary>A point-in-time copy of all cache entries (for the verdict re-check sweep).</summary>
    public IReadOnlyList<HashCacheEntry> Snapshot() => _entries.Values.ToList();

    public void Clear()
    {
        _entries.Clear();
        _dirty = true;
        Flush();
    }

    public void MaybeSave()
    {
        if (!_dirty) return;
        if (DateTime.UtcNow - _lastSaveUtc < TimeSpan.FromSeconds(5)) return;
        Flush();
    }

    public void Flush()
    {
        if (!_dirty) return;
        lock (_saveLock)
        {
            try
            {
                Directory.CreateDirectory(ConfigPathResolver.ConfigFolder);
                File.WriteAllText(ConfigPathResolver.HashCachePath, JsonSerializer.Serialize(_entries.Values.ToList(), JsonOpts));
                _lastSaveUtc = DateTime.UtcNow;
                _dirty = false;
            }
            catch (Exception ex) { Log("Hash cache save failed: " + ex.Message, LogLevel.Warning); }
        }
    }
}
