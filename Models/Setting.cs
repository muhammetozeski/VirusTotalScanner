namespace VirusTotalScanner;

/// <summary>Read-only view of a setting (value as object, plus its keys).</summary>
internal interface ISetting
{
    string Key { get; }
    string KeyHumanReadable { get; }
    object Value { get; }
    object DefaultValue { get; }
    bool IsDefault { get; }
    void ResetToDefault();
}

/// <summary>Setup contract used exclusively by <see cref="SettingsManager"/>.</summary>
internal interface ISettingSetup
{
    string Key { get; }
    void InitializeKey(string key);
    void LoadFromStr(string value);
    string Serialize();
}

/// <summary>
/// A strongly-typed configuration setting. Adapted from
/// The key is assigned by <see cref="SettingsManager"/> from the
/// field name via reflection.
/// </summary>
internal class Setting<T>(T defaultValue) : ISetting, ISettingSetup
{
    string _key = string.Empty;

    public string Key
    {
        get => _key;
        private set
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                _key = value;
                KeyHumanReadable = SplitCamelCase(value);
            }
        }
    }

    public string KeyHumanReadable { get; private set; } = string.Empty;

    public T Value = defaultValue;
    public readonly T DefaultValue = defaultValue;

    object ISetting.Value => Value!;
    object ISetting.DefaultValue => DefaultValue!;
    bool ISetting.IsDefault => EqualityComparer<T>.Default.Equals(Value, DefaultValue);
    void ISetting.ResetToDefault() => Value = DefaultValue;

    void ISettingSetup.InitializeKey(string key)
    {
        if (!string.IsNullOrEmpty(Key))
            throw new InvalidOperationException($"Key already initialized to '{Key}'. Cannot re-assign to '{key}'.");
        Key = key;
    }

    void ISettingSetup.LoadFromStr(string value)
    {
        try
        {
            Value = (T)Convert.ChangeType(value, typeof(T));
        }
        catch
        {
            Log($"Config: invalid {typeof(T).Name} for '{Key}': '{value}'. Using default.", LogLevel.Warning);
        }
    }

    string ISettingSetup.Serialize() => Value?.ToString() ?? string.Empty;

    public static implicit operator T(Setting<T> setting) => setting.Value;
}
