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

    /// <summary>When THIS machine first cached this hash — set once on creation and preserved across
    /// re-caches (unlike <see cref="CachedUtc"/>, which tracks last-seen). The local arrival anchor.</summary>
    public DateTime LocalFirstSeenUtc { get; set; }

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
    DateTime _lastSaveUtc = DateTime.MinValue; // only touched under _saveLock
    volatile bool _dirty;                       // set true by worker threads; cleared under _saveLock

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
        catch (Exception ex) { Log("Hash cache load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(ConfigPathResolver.HashCachePath); }
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
        // Preserve a previously-recorded path (e.g. a hash-only re-check) and the local first-seen anchor
        // when this Put updates an existing entry — CachedUtc still advances to now as the last-seen time.
        DateTime localFirstSeen = DateTime.UtcNow;
        if (_entries.TryGetValue(md5, out var prev))
        {
            sourcePath ??= prev.LastPath;
            if (prev.LocalFirstSeenUtc > DateTime.MinValue) localFirstSeen = prev.LocalFirstSeenUtc;
        }

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
            LocalFirstSeenUtc = localFirstSeen,
            LastPath = sourcePath,
            ReportUrl = report.ReportUrl,
            Detections = report.DetectionCount,
            TotalEngines = report.TotalEngines,
            Report = compact,
        };
        _dirty = true;
        MaybeSave();
    }

    /// <summary>When this machine first cached the given md5 (preserved across re-caches), or null if the
    /// hash isn't cached or predates the field.</summary>
    public DateTime? LocalFirstSeen(string? md5)
    {
        if (!string.IsNullOrEmpty(md5) && _entries.TryGetValue(md5, out var e) && e.LocalFirstSeenUtc > DateTime.MinValue)
            return e.LocalFirstSeenUtc;
        return null;
    }

    public int Count => _entries.Count;

    /// <summary>A point-in-time copy of all cache entries (for the verdict re-check sweep).</summary>
    public IReadOnlyList<HashCacheEntry> Snapshot() => _entries.Values.ToList();

    /// <summary>The distinct file sizes recorded in the cache. A cheap pre-filter for cache-peek callers:
    /// a file whose byte length matches none of these can never be a cache hit, so it needn't be hashed.</summary>
    public HashSet<long> CachedSizes()
    {
        var set = new HashSet<long>();
        foreach (var e in _entries.Values)
            if (e.Report is { Size: > 0 }) set.Add(e.Report.Size);
        return set;
    }

    public void Clear()
    {
        _entries.Clear();
        _dirty = true;
        Flush();
    }

    public void MaybeSave()
    {
        if (!_dirty) return; // fast-path hint; the real throttle decision is made under the lock
        lock (_saveLock)
        {
            if (!_dirty || DateTime.UtcNow - _lastSaveUtc < TimeSpan.FromSeconds(5)) return;
            WriteUnderLock();
        }
    }

    public void Flush()
    {
        lock (_saveLock)
        {
            if (!_dirty) return;
            WriteUnderLock();
        }
    }

    /// <summary>Serializes the cache to disk. Caller must hold <see cref="_saveLock"/> so the
    /// throttle/dirty read-modify-write stays atomic across concurrent scan-worker Puts.</summary>
    void WriteUnderLock()
    {
        try
        {
            Directory.CreateDirectory(ConfigPathResolver.ConfigFolder);
            AtomicFile.WriteAllText(ConfigPathResolver.HashCachePath, JsonSerializer.Serialize(_entries.Values.ToList(), JsonOpts));
            _lastSaveUtc = DateTime.UtcNow;
            _dirty = false;
        }
        catch (Exception ex) { Log("Hash cache save failed: " + ex.Message, LogLevel.Warning); }
    }
}
