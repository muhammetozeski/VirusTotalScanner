using System.Drawing;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VirusTotalScanner;

/// <summary>One user-defined verdict band: detections &gt;= MinDetections maps to this category.</summary>
internal sealed class VerdictCategory
{
    public int MinDetections { get; set; }
    public string Name { get; set; } = "";
    public string ColorHex { get; set; } = "#888888";

    [JsonIgnore]
    public Color Color
    {
        get { try { return ColorTranslator.FromHtml(ColorHex); } catch { return Color.Gray; } }
    }
}

/// <summary>
/// User-configurable mapping from detection count to a named, colored verdict. Default:
/// 0-1 detections = TEMİZ (green), 2 = ŞÜPHELİ (orange), 3+ = VİRÜS (red). The user can add
/// bands (distinct thresholds), rename them and change colors. Persisted in the config.
/// </summary>
internal static class VerdictCategories
{
    static readonly JsonSerializerOptions JsonOpts = new();
    static List<VerdictCategory> _cats = Defaults();

    public static List<VerdictCategory> Defaults() =>
    [
        new() { MinDetections = 0, Name = Strings.VerdictCatCleanName, ColorHex = "#3FB950" },
        new() { MinDetections = 2, Name = Strings.VerdictCatSuspiciousName, ColorHex = "#E3B341" },
        new() { MinDetections = 3, Name = Strings.VerdictCatVirusName, ColorHex = "#F85149" },
    ];

    public static IReadOnlyList<VerdictCategory> All => _cats;

    public static void Load()
    {
        try
        {
            string json = Settings.VerdictCategoriesJson.Value;
            if (string.IsNullOrWhiteSpace(json)) { _cats = Defaults(); return; }
            var list = JsonSerializer.Deserialize<List<VerdictCategory>>(json, JsonOpts);
            _cats = (list != null && list.Count > 0) ? Normalize(list) : Defaults();
        }
        catch (Exception ex) { Log("Verdict categories load failed: " + ex.Message, LogLevel.Warning); _cats = Defaults(); }
    }

    public static void Save(IEnumerable<VerdictCategory> cats)
    {
        _cats = Normalize(cats.ToList());
        try
        {
            Settings.VerdictCategoriesJson.Value = JsonSerializer.Serialize(_cats, JsonOpts);
            SettingsManager.SaveSettings();
        }
        catch (Exception ex) { Log("Verdict categories save failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Dedupe thresholds (distinct counts required) and sort ascending.</summary>
    static List<VerdictCategory> Normalize(List<VerdictCategory> list)
    {
        var byThreshold = new Dictionary<int, VerdictCategory>();
        foreach (var c in list) byThreshold[Math.Max(0, c.MinDetections)] = c;
        var result = byThreshold.Values.OrderBy(c => c.MinDetections).ToList();
        if (result.Count == 0 || result[0].MinDetections != 0)
            result.Insert(0, new VerdictCategory { MinDetections = 0, Name = Strings.VerdictCatCleanName, ColorHex = "#3FB950" });
        return result;
    }

    public static VerdictCategory Classify(int detections)
    {
        var match = _cats[0];
        foreach (var c in _cats)
            if (detections >= c.MinDetections) match = c;
        return match;
    }

    /// <summary>A threat = anything above the lowest (clean) band.</summary>
    public static bool IsThreat(int detections) => _cats.Count > 1 && detections >= _cats[1].MinDetections;

    public static VerdictCategory? ByName(string name) =>
        _cats.FirstOrDefault(c => string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase));
}
