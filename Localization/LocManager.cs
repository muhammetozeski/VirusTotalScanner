using System.Reflection;
using System.Text;
using System.Xml.Linq;

namespace VirusTotalScanner;

/// <summary>
/// Drives localization for <see cref="Strings"/>. Stores editable XML language packs under
/// <c>UserData\Language\</c>: writes <c>lang.tr.xml</c> from compiled Turkish defaults and extracts
/// the embedded <c>lang.en.xml</c> resource so the exe stays single-file with zero root clutter.
/// </summary>
internal static class LocManager
{
    const string EmbeddedEnglishResourceName = "VirusTotalScanner.lang.en.xml";

    public static (string Code, string Name)[] Available
    {
        get
        {
            if (!Directory.Exists(ConfigPathResolver.LanguageFolder))
                return [("tr", "Türkçe")];
            return Directory.GetFiles(ConfigPathResolver.LanguageFolder, "lang.*.xml")
                .Select(f =>
                {
                    string code = Path.GetFileName(f).Split('.')[1];
                    string name = code.ToUpperInvariant();
                    try
                    {
                        var doc = XDocument.Load(f);
                        var langName = doc.Root?.Element("LanguageName")?.Value;
                        if (!string.IsNullOrWhiteSpace(langName)) name = langName;
                    }
                    catch { }
                    return (code, name);
                })
                .ToArray();
        }
    }

    static FieldInfo[] StringFields() => typeof(Strings)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(string))
        .ToArray();

    static string PathFor(string lang) => Path.Combine(ConfigPathResolver.LanguageFolder, $"lang.{lang}.xml");

    public static void Init()
    {
        try
        {
            Directory.CreateDirectory(ConfigPathResolver.LanguageFolder);

            // Always keep an editable Turkish baseline file under UserData\Language\.
            string trPath = PathFor("tr");
            if (!File.Exists(trPath)) WriteXml(trPath, "Türkçe");

            // Extract embedded English language pack if missing so English works out of the box from one EXE.
            string enPath = PathFor("en");
            if (!File.Exists(enPath)) TryExtractEmbeddedEnglish(enPath);

            string lang = (Settings.Language.Value ?? "tr").Trim().ToLowerInvariant();
            if (lang is "" or "tr") return;

            string path = PathFor(lang);
            if (File.Exists(path)) ReadInto(path);
            else if (lang == "en" && TryReadEmbeddedEnglish()) return;
            else Log($"Language file not found: {path}; keeping Turkish defaults.", LogLevel.Warning);
        }
        catch (Exception ex) { Log("Localization init failed: " + ex.Message, LogLevel.Warning); }
    }

    static void TryExtractEmbeddedEnglish(string destPath)
    {
        try
        {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(EmbeddedEnglishResourceName);
            if (stream == null) return;
            using var fs = File.Create(destPath);
            stream.CopyTo(fs);
            Log($"Extracted embedded English language pack to {destPath}.", LogLevel.Info);
        }
        catch (Exception ex) { Log("Embedded English language extract failed: " + ex.Message, LogLevel.Warning); }
    }

    static bool TryReadEmbeddedEnglish()
    {
        try
        {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(EmbeddedEnglishResourceName);
            if (stream == null) return false;
            var doc = XDocument.Load(stream);
            ApplyDocument(doc, EmbeddedEnglishResourceName);
            return true;
        }
        catch (Exception ex)
        {
            Log("Embedded English language load failed: " + ex.Message, LogLevel.Warning);
            return false;
        }
    }

    /// <summary>Reflection-writes the current field values to an XML file (used for default language file: lang.tr.xml).</summary>
    static void WriteXml(string path, string languageName)
    {
        try
        {
            var doc = new XDocument(new XElement("strings",
                new XElement("LanguageName", languageName),
                StringFields().Select(f => new XElement("s",
                    new XAttribute("name", f.Name),
                    Escape((string?)f.GetValue(null) ?? "")))));
            File.WriteAllText(path, doc.ToString(), new UTF8Encoding(false));
            Log($"Wrote language baseline: {path}", LogLevel.Info);
        }
        catch (Exception ex) { Log("Language baseline write failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Reflection-loads values from an XML file over the matching <see cref="Strings"/> fields.</summary>
    static void ReadInto(string path) => ApplyDocument(XDocument.Load(path), Path.GetFileName(path));

    static void ApplyDocument(XDocument doc, string sourceLabel)
    {
        var map = StringFields().ToDictionary(f => f.Name, StringComparer.Ordinal);
        int n = 0;
        foreach (var s in doc.Root?.Elements("s") ?? [])
        {
            string? name = s.Attribute("name")?.Value;
            if (name != null && map.TryGetValue(name, out var f)) { f.SetValue(null, Unescape(s.Value)); n++; }
        }
        Log($"Loaded {n} localized string(s) from {sourceLabel}.", LogLevel.Info);
    }

    // Multi-line strings are stored single-line with a literal \n so the XML stays clean/indentable.
    static string Escape(string s) => s.Replace("\r\n", "\n").Replace("\n", "\\n");
    static string Unescape(string s) => s.Replace("\\n", "\n");
}
