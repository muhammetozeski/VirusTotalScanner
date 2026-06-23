using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace VirusTotalScanner;

internal enum ScanStatus
{
    Queued,
    Hashing,
    LookingUp,
    Uploading,
    Polling,
    Completed,
    Failed,
    Skipped,
    TrustedSkipped, // valid trusted signature or known-good list — VT skipped, NOT "clean"
    Cancelled,
}

/// <summary>One file in the scan queue. Bindable to a DataGridView via BindingList.</summary>
internal sealed class ScanItem : INotifyPropertyChanged
{
    public ScanItem(string filePath)
    {
        FilePath = filePath;
        try { SizeBytes = new FileInfo(filePath).Length; } catch { SizeBytes = -1; }
    }

    public string FilePath { get; }
    public string FileName => Path.GetFileName(FilePath);
    public long SizeBytes { get; }
    public string SizeText => SizeBytes < 0 ? "?" : FormatBytes(SizeBytes);

    string? _md5;
    public string? Md5 { get => _md5; set => Set(ref _md5, value); }

    string? _sha256;
    public string? Sha256 { get => _sha256; set => Set(ref _sha256, value); }

    ScanStatus _status = ScanStatus.Queued;
    public ScanStatus Status
    {
        get => _status;
        set { if (Set(ref _status, value)) OnPropertyChanged(nameof(StatusText)); }
    }

    int _progress;
    public int Progress { get => _progress; set => Set(ref _progress, value); }

    string? _detail;
    /// <summary>Free-text detail (e.g. upload speed, poll status).</summary>
    public string? Detail { get => _detail; set { if (Set(ref _detail, value)) OnPropertyChanged(nameof(StatusText)); } }

    VtFileReport? _report;
    public VtFileReport? Report { get => _report; set { if (Set(ref _report, value)) { OnPropertyChanged(nameof(StatusText)); OnPropertyChanged(nameof(Verdict)); } } }

    public bool FromCache { get; set; }

    /// <summary>Signer/publisher when the file was trust-skipped.</summary>
    public string? Publisher { get; set; }

    /// <summary>Why VT was skipped (e.g. "İmzalı · Microsoft", "Bilinen temiz (yerel liste)").</summary>
    public string? SkipReason { get; set; }

    string? _error;
    public string? Error { get => _error; set => Set(ref _error, value); }

    public string Verdict => Report?.Verdict ?? (Status == ScanStatus.TrustedSkipped ? "İMZALI" : "");

    public string StatusText => _status switch
    {
        ScanStatus.Queued => "Sırada",
        ScanStatus.Hashing => "Hash hesaplanıyor…",
        ScanStatus.LookingUp => "VirusTotal sorgulanıyor…",
        ScanStatus.Uploading => Detail ?? "Yükleniyor…",
        ScanStatus.Polling => Detail ?? "Analiz bekleniyor…",
        ScanStatus.Completed => Report == null ? "Tamamlandı" :
            $"{Report.Verdict} ({Report.DetectionCount}/{Report.TotalEngines})" + (FromCache ? " • önbellek" : ""),
        ScanStatus.Failed => "Hata: " + (Error ?? "bilinmiyor"),
        ScanStatus.Skipped => "Atlandı (" + (SkipReason ?? "güvenli tür") + ")",
        ScanStatus.TrustedSkipped => (SkipReason ?? "İmzalı") + " (VT atlandı)",
        ScanStatus.Cancelled => "İptal edildi",
        _ => _status.ToString(),
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }

    void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>Aggregate progress across the whole scan batch.</summary>
internal sealed class OverallProgress
{
    public int Total { get; set; }
    public int Done { get; set; }
    public int Malicious { get; set; }
    public int Suspicious { get; set; }
    public int Clean { get; set; }
    public int Failed { get; set; }
    public int Skipped { get; set; }
    public int SignedSkipped { get; set; }
    public double Percent => Total > 0 ? (double)Done / Total * 100 : 0;
}

internal sealed class ScanOptions
{
    public bool Recurse { get; set; } = true;
    public bool ApplySafeFilter { get; set; }
    public int MaxConcurrency { get; set; } = 2;
    public int MaxUploads { get; set; } = 2;
    /// <summary>Skip files larger than this before hashing (0 = no cap). VT's own ceiling is ~650 MB.</summary>
    public long MaxFileSizeBytes { get; set; }
    /// <summary>Expand ZIP-family archives and scan their members instead of the archive file.</summary>
    public bool ExpandArchives { get; set; }
    public bool UseCache { get; set; } = true;
    public int CacheDays { get; set; } = 7;

    /// <summary>Skip VT for trusted-signed / known-good files (the keyless quota saver).</summary>
    public bool SkipTrusted { get; set; } = true;
    /// <summary>When true, force every file through VT even if trusted (re-scan ignoring trust).</summary>
    public bool BypassTrust { get; set; }

    public static ScanOptions FromSettings(bool recurse) => new()
    {
        Recurse = recurse,
        ApplySafeFilter = Settings.SkipSafeExtensionsOnScan,
        MaxConcurrency = Math.Max(1, Settings.MaxConcurrentScans.Value),
        MaxUploads = Math.Max(1, Settings.MaxConcurrentUploads.Value),
        MaxFileSizeBytes = Math.Max(0, (long)Settings.MaxFileSizeMB.Value) * 1024 * 1024,
        UseCache = Settings.UseLocalHashCache,
        CacheDays = Math.Max(0, Settings.HashCacheDays.Value),
        SkipTrusted = Settings.TrustSkipSigned,
    };
}
