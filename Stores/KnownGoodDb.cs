namespace VirusTotalScanner;

/// <summary>
/// Optional user-supplied known-good hash list (one md5/sha1/sha256 per line). A hit means
/// the user vouches the file is clean → VT is skipped. Never bundled; the user points at it.
/// </summary>
internal static class KnownGoodDb
{
    static readonly HashSet<string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    static string? _loadedPath;

    public static int Count => _hashes.Count;

    public static void Reload()
    {
        string path = Settings.KnownGoodHashDbPath.Value;
        lock (_hashes)
        {
            if (string.Equals(path, _loadedPath, StringComparison.OrdinalIgnoreCase)) return;
            _hashes.Clear();
            _loadedPath = path;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
            try
            {
                foreach (var raw in File.ReadLines(path))
                {
                    var line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith('#')) continue;
                    // accept "hash" or "hash<space>anything"
                    var token = line.Split([' ', '\t', ','], 2)[0].Trim();
                    if (token.Length is 32 or 40 or 64) _hashes.Add(token);
                }
                Log($"Known-good DB loaded: {_hashes.Count} hashes from {path}", LogLevel.Info);
            }
            catch (Exception ex) { Log("Known-good DB load failed: " + ex.Message, LogLevel.Warning); }
        }
    }

    public static bool Contains(string? md5, string? sha256)
    {
        if (_hashes.Count == 0) return false;
        lock (_hashes)
            return (md5 != null && _hashes.Contains(md5)) || (sha256 != null && _hashes.Contains(sha256));
    }
}
