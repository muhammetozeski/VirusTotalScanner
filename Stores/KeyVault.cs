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
    bool _undecryptable; // the stored blob failed to decrypt this session — guards it from being overwritten

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
            catch (CryptographicException ex)
            {
                _undecryptable = true;
                string backup = BackupUndecryptableBlob(enc);
                Log("Key vault could not be decrypted (different Windows account, or a torn config write). "
                    + (backup.Length > 0 ? $"Encrypted blob backed up to: {backup}. " : "Backing the blob up ALSO failed. ")
                    + "Starting empty; the stored blob will not be overwritten until a key is added. " + ex.Message, LogLevel.Error);
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
        try { Changed?.Invoke(); } catch (Exception ex) { Log("Vault Changed handler failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Throttled counter persistence (called frequently during scans).</summary>
    public void MaybePersistCounters()
    {
        if (DateTime.UtcNow - _lastCounterPersistUtc < TimeSpan.FromSeconds(5)) return;
        PersistToConfig();
    }

    /// <summary>Force-write counters (e.g. on shutdown).</summary>
    public void Flush() => PersistToConfig();

    public void RaiseCountersUpdated() { try { CountersUpdated?.Invoke(); } catch (Exception ex) { Log("CountersUpdated handler failed: " + ex.Message, LogLevel.Warning); } }

    /// <summary>Preserves the still-encrypted blob to a sidecar file so the keys stay recoverable
    /// (e.g. back on the right Windows account) instead of being lost to the next save. Tries the
    /// data folder first, then %TEMP%; returns the written path, or "" when both fail.</summary>
    static string BackupUndecryptableBlob(string encryptedBlob)
    {
        string name = $"keyvault-backup-{DateTime.Now:yyyyMMdd-HHmmss}.txt";
        foreach (string folder in new[] { ConfigPathResolver.DataFolder, Path.GetTempPath() })
        {
            try
            {
                string path = Path.Combine(folder, name);
                File.WriteAllText(path, encryptedBlob);
                return path;
            }
            catch (Exception ex) { Log($"Key vault blob backup to '{folder}' failed: {ex.Message}", LogLevel.Warning); }
        }
        return "";
    }

    void PersistToConfig()
    {
        string json;
        bool empty;
        lock (_lock) { json = JsonSerializer.Serialize(_keys, JsonOpts); empty = _keys.Count == 0; }
        if (_undecryptable && empty)
        {
            // The stored blob is unreadable only HERE (wrong account / torn read) and memory holds
            // nothing: writing now would empty the user's real vault for good. Keep the stored blob —
            // the previous behavior did exactly this overwrite and destroyed saved keys.
            Log("Key vault save skipped to protect the stored (undecryptable) blob from being emptied.", LogLevel.Warning);
            return;
        }
        _undecryptable = false; // a real vault is being written; the old blob lives on in the backup file
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
