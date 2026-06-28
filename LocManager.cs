using System.Reflection;
using System.Text;
using System.Xml.Linq;

namespace VirusTotalScanner;

/// <summary>
/// Drives localization for <see cref="Strings"/>. On startup it ensures <c>lang.tr.xml</c> exists
/// (writing the Turkish defaults so the user can edit them), and — when another language is chosen
/// — loads <c>lang.&lt;code&gt;.xml</c> over the fields via reflection. English ships as
/// <c>lang.en.xml</c> next to the exe.
/// </summary>
internal static class LocManager
{

    public static (string Code, string Name)[] Available
    {
        get
        {
            if (!Directory.Exists(ConfigPathResolver.ConfigFolder))
                return [("tr", "Türkçe")];
            return Directory.GetFiles(ConfigPathResolver.ConfigFolder, "lang.*.xml")
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

    static string PathFor(string lang) => Path.Combine(ConfigPathResolver.ConfigFolder, $"lang.{lang}.xml");

    public static void Init()
    {
        try
        {
            // Always keep an editable Turkish baseline file next to the exe (write once if missing).
            string trPath = PathFor("tr");
            if (!File.Exists(trPath)) WriteXml(trPath, "Türkçe");

            string lang = (Settings.Language.Value ?? "tr").Trim().ToLowerInvariant();
            if (lang is "" or "tr") return;

            string path = PathFor(lang);
            if (File.Exists(path)) ReadInto(path);
            else Log($"Language file not found: {path}; keeping Turkish defaults.", LogLevel.Warning);
        }
        catch (Exception ex) { Log("Localization init failed: " + ex.Message, LogLevel.Warning); }
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
    static void ReadInto(string path)
    {
        var doc = XDocument.Load(path);
        var map = StringFields().ToDictionary(f => f.Name, StringComparer.Ordinal);
        int n = 0;
        foreach (var s in doc.Root?.Elements("s") ?? [])
        {
            string? name = s.Attribute("name")?.Value;
            if (name != null && map.TryGetValue(name, out var f)) { f.SetValue(null, Unescape(s.Value)); n++; }
        }
        Log($"Loaded {n} localized string(s) from {Path.GetFileName(path)}.", LogLevel.Info);
    }

    // Multi-line strings are stored single-line with a literal \n so the XML stays clean/indentable.
    static string Escape(string s) => s.Replace("\r\n", "\n").Replace("\n", "\\n");
    static string Unescape(string s) => s.Replace("\\n", "\n");
}
