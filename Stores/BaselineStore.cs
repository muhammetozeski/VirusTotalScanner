using System.Text.Json;

namespace VirusTotalScanner;

internal sealed class BaselineRecord
{
    public string Path { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long Size { get; set; }
    public string? Signer { get; set; }
    public long MtimeTicks { get; set; }
    public DateTime CapturedUtc { get; set; }
}

internal enum DriftKind { Unchanged, ChangedStillUntrusted, ChangedLostTrust, Missing }

internal sealed record DriftResult(string Path, DriftKind Kind, string Detail)
{
    public bool IsAlarm => Kind == DriftKind.ChangedLostTrust;
}

/// <summary>
/// Path-keyed integrity baseline (path -> {sha256, size, signer, mtime}), the inverse of the
/// content-keyed cache. "Pin to integrity watch" records the expected bytes at a path; "verify"
/// re-hashes those paths locally and reports drift. The loud alarm fires only when a previously
/// trusted/signed path is now changed AND lost its signer continuity — a swapped or trojanized
/// binary — while a normal signed update is a quiet note. Local-only, no quota.
/// </summary>
internal static class BaselineStore
{
    static readonly Dictionary<string, BaselineRecord> _records = new(StringComparer.OrdinalIgnoreCase);
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };
    // The periodic tray re-check verifies in the background while the user can pin/remove from the
    // UI thread — every _records access must hold this (the other stores already follow the pattern).
    static readonly object Lock = new();
    static bool _loaded;

    static string FilePath => System.IO.Path.Combine(ConfigPathResolver.ConfigFolder, "baseline.json");

    static void LoadUnderLock()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            if (!File.Exists(FilePath)) return;
            var list = JsonSerializer.Deserialize<List<BaselineRecord>>(File.ReadAllText(FilePath), JsonOpts);
            if (list != null)
                foreach (var r in list)
                    if (!string.IsNullOrEmpty(r.Path)) _records[r.Path] = r;
            Log($"Baseline loaded: {_records.Count} watched path(s).", LogLevel.Info);
        }
        catch (Exception ex) { Log("Baseline load failed: " + ex.Message, LogLevel.Warning); AtomicFile.BackupCorrupt(FilePath); }
    }

    static void SaveUnderLock()
    {
        try
        {
            Directory.CreateDirectory(ConfigPathResolver.ConfigFolder);
            AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(_records.Values.ToList(), JsonOpts));
        }
        catch (Exception ex) { Log("Baseline save failed: " + ex.Message, LogLevel.Warning); }
    }

    public static int Count { get { lock (Lock) { LoadUnderLock(); return _records.Count; } } }
    public static bool Contains(string path) { lock (Lock) { LoadUnderLock(); return _records.ContainsKey(path); } }

    /// <summary>Pins (or refreshes) a file's expected state. Computes hash + signer now.</summary>
    public static async Task<bool> PinAsync(string path, CancellationToken ct = default)
    {
        try
        {
            if (!File.Exists(path)) return false;
            var (_, sha) = await HashService.ComputeAsync(path, ct);
            var fi = new FileInfo(path);
            var trust = TrustService.Evaluate(path);
            lock (Lock)
            {
                LoadUnderLock();
                _records[path] = new BaselineRecord
                {
                    Path = path,
                    Sha256 = sha,
                    Size = fi.Length,
                    Signer = trust.Trusted ? trust.Publisher : null,
                    MtimeTicks = fi.LastWriteTimeUtc.Ticks,
                    CapturedUtc = DateTime.UtcNow,
                };
                SaveUnderLock();
            }
            Log("Pinned to integrity watch: " + path, LogLevel.Info);
            return true;
        }
        catch (Exception ex) { Log("Baseline pin failed: " + ex.Message, LogLevel.Warning); return false; }
    }

    public static void Remove(string path) { lock (Lock) { LoadUnderLock(); if (_records.Remove(path)) SaveUnderLock(); } }

    /// <summary>Re-hashes every watched path and reports drift; updates stored hash on benign change.</summary>
    public static async Task<List<DriftResult>> VerifyAsync(Action<int, int>? onProgress, CancellationToken ct)
    {
        var results = new List<DriftResult>();
        List<BaselineRecord> all;
        lock (Lock) { LoadUnderLock(); all = _records.Values.ToList(); }
        int i = 0;
        foreach (var r in all)
        {
            ct.ThrowIfCancellationRequested();
            onProgress?.Invoke(++i, all.Count);

            if (!File.Exists(r.Path)) { results.Add(new DriftResult(r.Path, DriftKind.Missing, Strings.BaselineDriftMissing)); continue; }

            var (_, sha) = await HashService.ComputeAsync(r.Path, ct);
            if (string.Equals(sha, r.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                results.Add(new DriftResult(r.Path, DriftKind.Unchanged, Strings.BaselineDriftUnchanged));
                continue;
            }

            var trust = TrustService.Evaluate(r.Path);
            bool wasSigned = !string.IsNullOrEmpty(r.Signer);
            bool sameSigner = trust.Trusted && string.Equals(trust.Publisher, r.Signer, StringComparison.OrdinalIgnoreCase);

            if (wasSigned && !sameSigner)
                results.Add(new DriftResult(r.Path, DriftKind.ChangedLostTrust,
                    string.Format(Strings.BaselineDriftLostTrustFormat, r.Signer, trust.Trusted ? trust.Publisher : Strings.BaselineSignerInvalid)));
            else
            {
                results.Add(new DriftResult(r.Path, DriftKind.ChangedStillUntrusted,
                    wasSigned ? Strings.BaselineDriftSamePublisher : Strings.BaselineDriftWasUnsigned));
                // Benign drift: refresh the stored hash/size so the next verify is quiet.
                lock (Lock)
                {
                    r.Sha256 = sha;
                    try { r.Size = new FileInfo(r.Path).Length; } catch { /* keep old size */ }
                }
            }
        }
        lock (Lock) SaveUnderLock();
        return results;
    }
}
