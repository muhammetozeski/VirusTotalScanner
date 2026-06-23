using System.Security.Cryptography;
using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>
/// Holds the API keys + their quota counters, persisted as Base64(DPAPI(JSON)) inside the
/// single config setting <see cref="Settings.EncryptedKeyVault"/>. No separate key file.
/// </summary>
internal sealed class KeyVault
{
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    readonly List<ApiKeyEntry> _keys = [];
    readonly object _lock = new();
    DateTime _lastCounterPersistUtc = DateTime.MinValue;

    /// <summary>Raised on structural changes (add/remove/edit/disable).</summary>
    public event Action? Changed;
    /// <summary>Raised when quota counters change (live UI refresh, no disk write).</summary>
    public event Action? CountersUpdated;

    public IReadOnlyList<ApiKeyEntry> Keys { get { lock (_lock) return _keys.ToList(); } }
    public bool HasUsableKeys { get { lock (_lock) return _keys.Any(k => !k.Disabled); } }
    public int UsableKeyCount { get { lock (_lock) return _keys.Count(k => !k.Disabled); } }

    public void Load()
    {
        string enc = Settings.EncryptedKeyVault.Value;
        lock (_lock)
        {
            _keys.Clear();
            if (string.IsNullOrWhiteSpace(enc)) return;
            try
            {
                string json = CryptoService.UnprotectFromBase64(enc);
                var list = JsonSerializer.Deserialize<List<ApiKeyEntry>>(json, JsonOpts);
                if (list != null) _keys.AddRange(list);
                Log($"Key vault loaded: {_keys.Count} key(s)", LogLevel.Info);
            }
            catch (CryptographicException)
            {
                Log("Key vault could not be decrypted (config likely copied from another user/PC). Starting empty.", LogLevel.Warning);
            }
            catch (Exception ex)
            {
                Log("Key vault load failed: " + ex, LogLevel.Error);
            }
        }
    }

    public ApiKeyEntry Add(string label, string key)
    {
        var entry = ApiKeyEntry.Create(label, key);
        lock (_lock) _keys.Add(entry);
        Log($"API key added: {entry.Label} ({entry.Masked})", LogLevel.Info);
        Save();
        return entry;
    }

    public void Remove(string id)
    {
        lock (_lock) _keys.RemoveAll(k => k.Id == id);
        Log("API key removed: " + id, LogLevel.Info);
        Save();
    }

    public void UpdateMeta(string id, string label, string key)
    {
        lock (_lock)
        {
            var e = _keys.FirstOrDefault(k => k.Id == id);
            if (e == null) return;
            e.Label = label;
            e.Key = key;
            e.Disabled = false;
            e.LastError = null;
        }
        Save();
    }

    /// <summary>Reorders keys (drag-reorder in the UI). ids = new order.</summary>
    public void Reorder(IReadOnlyList<string> ids)
    {
        lock (_lock)
        {
            _keys.Sort((a, b) =>
            {
                int ia = ids.ToList().IndexOf(a.Id);
                int ib = ids.ToList().IndexOf(b.Id);
                return (ia < 0 ? int.MaxValue : ia).CompareTo(ib < 0 ? int.MaxValue : ib);
            });
        }
        Save();
    }

    /// <summary>Serialize + encrypt + write config, then raise Changed.</summary>
    public void Save()
    {
        PersistToConfig();
        try { Changed?.Invoke(); } catch { }
    }

    /// <summary>Throttled counter persistence (called frequently during scans).</summary>
    public void MaybePersistCounters()
    {
        if (DateTime.UtcNow - _lastCounterPersistUtc < TimeSpan.FromSeconds(5)) return;
        PersistToConfig();
    }

    /// <summary>Force-write counters (e.g. on shutdown).</summary>
    public void Flush() => PersistToConfig();

    public void RaiseCountersUpdated() { try { CountersUpdated?.Invoke(); } catch { } }

    void PersistToConfig()
    {
        string json;
        lock (_lock) json = JsonSerializer.Serialize(_keys, JsonOpts);
        try
        {
            Settings.EncryptedKeyVault.Value = CryptoService.ProtectToBase64(json);
            SettingsManager.SaveSettings();
            _lastCounterPersistUtc = DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            Log("Key vault save failed: " + ex, LogLevel.Error);
        }
    }
}
