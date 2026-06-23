using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace VirusTotalScanner;

internal sealed class TrustResult
{
    public bool Trusted { get; init; }
    public string? Publisher { get; init; }
    public string Reason { get; init; } = "";
    public bool IsMicrosoft { get; init; }

    public static readonly TrustResult NotSigned = new() { Trusted = false, Reason = "imzasız" };
}

/// <summary>
/// Local, keyless, zero-quota code-signature trust check. Verifies BOTH embedded signatures
/// and catalog signatures (the way Get-AuthenticodeSignature does) with whole-chain
/// revocation against cached CRLs. "Trusted" means vouched-for provenance, NOT safety —
/// the scanner shows "İmzalı (taranmadı)", never "Temiz".
/// </summary>
internal static class TrustService
{
    static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    const uint WTD_UI_NONE = 2;
    const uint WTD_REVOKE_WHOLECHAIN = 1;
    const uint WTD_CHOICE_FILE = 1;
    const uint WTD_CHOICE_CATALOG = 2;
    const uint WTD_STATEACTION_VERIFY = 1;
    const uint WTD_STATEACTION_CLOSE = 2;
    const uint WTD_REVOCATION_CHECK_CHAIN = 0x40;
    const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    const uint TRUST_E_NOSIGNATURE = 0x800B0100;

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", SetLastError = false)]
    static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", SetLastError = false)]
    static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner, [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, uint idxCounterSigner);

    [DllImport("wintrust.dll", SetLastError = false)]
    static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, [MarshalAs(UnmanagedType.LPWStr)] string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = false)]
    static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion; // pFile or pCatalog
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    public static TrustResult Evaluate(string path)
    {
        try
        {
            var embedded = VerifyEmbedded(path);
            if (embedded.hr == 0) return Trusted(embedded.signer);
            if ((uint)embedded.hr != TRUST_E_NOSIGNATURE) return new TrustResult { Trusted = false, Reason = ReasonFor(embedded.hr) };

            // No embedded signature -> try catalog signature (covers most OS files).
            var cat = VerifyCatalog(path);
            if (cat.hr == 0) return Trusted(cat.signer);
            return new TrustResult { Trusted = false, Reason = ReasonFor(cat.hr) };
        }
        catch (Exception ex)
        {
            Log("Trust evaluate failed for " + path + ": " + ex.Message, LogLevel.Warning);
            return TrustResult.NotSigned;
        }
    }

    static TrustResult Trusted((string? cn, bool ms) signer) => new()
    {
        Trusted = true,
        Publisher = signer.cn,
        IsMicrosoft = signer.ms,
        Reason = "İmzalı" + (signer.cn != null ? " · " + signer.cn : ""),
    };

    static (int hr, (string? cn, bool ms) signer) VerifyEmbedded(string path)
    {
        IntPtr pFile = IntPtr.Zero, pData = IntPtr.Zero, filePathPtr = IntPtr.Zero;
        try
        {
            filePathPtr = Marshal.StringToHGlobalUni(path);
            var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = filePathPtr };
            pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, pFile, false);

            var data = NewData(WTD_CHOICE_FILE, pFile);
            pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            int hr = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);
            var signer = hr == 0 ? ExtractSigner(Marshal.PtrToStructure<WINTRUST_DATA>(pData).hWVTStateData) : (null, false);
            CloseState(pData);
            return (hr, signer);
        }
        finally
        {
            if (pFile != IntPtr.Zero) Marshal.FreeHGlobal(pFile);
            if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
            if (filePathPtr != IntPtr.Zero) Marshal.FreeHGlobal(filePathPtr);
        }
    }

    static (int hr, (string? cn, bool ms) signer) VerifyCatalog(string path)
    {
        IntPtr hCatAdmin = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0) &&
                !CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0))
                return (unchecked((int)TRUST_E_NOSIGNATURE), (null, false));

            using var fs = File.OpenRead(path);
            IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();

            uint cbHash = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, null, 0) || cbHash == 0)
            {
                cbHash = 0;
                if (!CryptCATAdminCalcHashFromFileHandle(hFile, ref cbHash, null, 0) || cbHash == 0)
                    return (unchecked((int)TRUST_E_NOSIGNATURE), (null, false));
                var h1 = new byte[cbHash];
                if (!CryptCATAdminCalcHashFromFileHandle(hFile, ref cbHash, h1, 0)) return (unchecked((int)TRUST_E_NOSIGNATURE), (null, false));
                return VerifyAgainstCatalog(hCatAdmin, h1, cbHash, path);
            }
            var hash = new byte[cbHash];
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, hash, 0))
                return (unchecked((int)TRUST_E_NOSIGNATURE), (null, false));
            return VerifyAgainstCatalog(hCatAdmin, hash, cbHash, path);
        }
        finally
        {
            if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    static (int hr, (string? cn, bool ms) signer) VerifyAgainstCatalog(IntPtr hCatAdmin, byte[] hash, uint cbHash, string path)
    {
        IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, cbHash, 0, IntPtr.Zero);
        if (hCatInfo == IntPtr.Zero) return (unchecked((int)TRUST_E_NOSIGNATURE), (null, false));

        IntPtr pData = IntPtr.Zero, pCat = IntPtr.Zero, memberTagPtr = IntPtr.Zero, hashPtr = IntPtr.Zero;
        try
        {
            var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0)) return (unchecked((int)TRUST_E_NOSIGNATURE), (null, false));

            string memberTag = Convert.ToHexString(hash, 0, (int)cbHash);
            hashPtr = Marshal.AllocHGlobal((int)cbHash);
            Marshal.Copy(hash, 0, hashPtr, (int)cbHash);

            var wci = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = ci.wszCatalogFile,
                pcwszMemberTag = memberTag,
                pcwszMemberFilePath = path,
                pbCalculatedFileHash = hashPtr,
                cbCalculatedFileHash = cbHash,
                hCatAdmin = hCatAdmin,
            };
            pCat = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(wci, pCat, false);

            var data = NewData(WTD_CHOICE_CATALOG, pCat);
            pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            int hr = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);
            var signer = hr == 0 ? ExtractSigner(Marshal.PtrToStructure<WINTRUST_DATA>(pData).hWVTStateData) : (null, false);
            CloseState(pData);
            return (hr, signer);
        }
        finally
        {
            if (pCat != IntPtr.Zero) Marshal.FreeHGlobal(pCat);
            if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
            if (hashPtr != IntPtr.Zero) Marshal.FreeHGlobal(hashPtr);
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        }
    }

    static WINTRUST_DATA NewData(uint unionChoice, IntPtr pUnion) => new()
    {
        cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
        dwUIChoice = WTD_UI_NONE,
        fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice = unionChoice,
        pUnion = pUnion,
        dwStateAction = WTD_STATEACTION_VERIFY,
        dwProvFlags = WTD_REVOCATION_CHECK_CHAIN | WTD_CACHE_ONLY_URL_RETRIEVAL,
    };

    static void CloseState(IntPtr pData)
    {
        try
        {
            var close = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            close.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(close, pData, false);
            WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);
        }
        catch { }
    }

    static (string? publisher, bool isMicrosoft) ExtractSigner(IntPtr stateData)
    {
        try
        {
            if (stateData == IntPtr.Zero) return (null, false);
            IntPtr prov = WTHelperProvDataFromStateData(stateData);
            if (prov == IntPtr.Zero) return (null, false);
            IntPtr sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
            if (sgnr == IntPtr.Zero) return (null, false);
            IntPtr provCert = WTHelperGetProvCertFromChain(sgnr, 0);
            if (provCert == IntPtr.Zero) return (null, false);

            int offset = IntPtr.Size == 8 ? 8 : 4; // CRYPT_PROVIDER_CERT: DWORD cbStruct; PCCERT_CONTEXT pCert;
            IntPtr pCertContext = Marshal.ReadIntPtr(provCert, offset);
            if (pCertContext == IntPtr.Zero) return (null, false);

            using var cert = new X509Certificate2(pCertContext);
            string cn = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            bool isMs = (cert.Subject + " " + cert.Issuer).Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
            return (string.IsNullOrWhiteSpace(cn) ? null : cn, isMs);
        }
        catch { return (null, false); }
    }

    static string ReasonFor(int hr) => (uint)hr switch
    {
        0x800B0100 => "imzasız",
        0x800B0101 => "sertifika süresi dolmuş",
        0x800B010C => "sertifika iptal edilmiş",
        0x800B0111 => "güvenilmeyen yayıncı",
        0x800B010A => "güven zinciri kurulamadı",
        0x800B0004 => "imza geçersiz",
        _ => $"güvenilmiyor (0x{(uint)hr:X8})",
    };

    public static bool ShouldSkip(TrustResult t, bool microsoftOnly, string allowListCsv)
    {
        if (!t.Trusted) return false;
        if (!microsoftOnly) return true;
        if (t.IsMicrosoft) return true;
        if (!string.IsNullOrWhiteSpace(allowListCsv) && t.Publisher != null)
            foreach (var cn in allowListCsv.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                if (t.Publisher.Contains(cn, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
