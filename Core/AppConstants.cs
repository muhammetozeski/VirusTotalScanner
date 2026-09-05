namespace VirusTotalScanner;

/// <summary>
/// Global constants and configuration defaults used throughout the application.
/// </summary>
internal static class AppConstants
{
    public const string AppTitle = "VirusTotal Scanner";
    public const string AppFolderName = "VirusTotalScanner";

    /// <summary>Read from the assembly rather than typed out again here: the hand-written copy had
    /// drifted to 1.0.0 while the csproj said 1.1.0, so the About box and the User-Agent were lying.</summary>
    public static readonly string Version =
        System.Reflection.Assembly.GetExecutingAssembly().GetName().Version is { } v
            ? $"{v.Major}.{v.Minor}.{v.Build}"
            : "0.0.0";

    /// <summary>Full path to the running executable. Not null for file-based exes.</summary>
    public static readonly string ThisExePath = Environment.ProcessPath ?? Application.ExecutablePath;

    /// <summary>Folder the executable lives in.</summary>
    public static readonly string ThisExeFolder = Path.GetDirectoryName(ThisExePath) ?? AppContext.BaseDirectory;

    // ---- Config file ----
    public const string ConfigFileName = "VirusTotalScanner.config";
    public const string CommentPrefix = "#";
    public const string KeyValueSeparator = "=";

    // ---- VirusTotal API v3 ----
    public const string VtApiBase = "https://www.virustotal.com/api/v3";
    public const string VtGuiFile = "https://www.virustotal.com/gui/file/";
    /// <summary>The plain VirusTotal shell, used to warm a freshly built browser profile up so the
    /// first real lookup is not also paying to download the whole single-page app.</summary>
    public const string VtGuiHome = "https://www.virustotal.com/gui/home/upload";

    /// <summary>Files at or below this size upload directly to /files; larger need an upload_url.</summary>
    public const long DirectUploadLimitBytes = 32L * 1024 * 1024;

    // ---- Free-tier quota, per key ----
    public const int RatePerMinute = 4;
    public const int QuotaPerDay = 500;
    public const int QuotaPerMonth = 15500;

    // ---- Context menu ----
    public const string MenuVerb = "VTScan";
    public const string MenuText = "VirusTotal ile tara";
}
