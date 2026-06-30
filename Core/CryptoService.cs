using System.Security.Cryptography;
using System.Text;

namespace VirusTotalScanner;

/// <summary>
/// DPAPI wrapper, adapted from C:\E\KodlamaProjeleri\CSharp\TPMPass\CryptoService.cs.
/// File I/O removed: this encrypts a string to Base64 (and back) so the API-key vault can
/// live inside the single config file. Bound to the current Windows user
/// (<see cref="DataProtectionScope.CurrentUser"/>) plus an app-level entropy value.
/// </summary>
internal static class CryptoService
{
    // App-level secondary entropy, combined with the per-user DPAPI key.
    static readonly byte[] Entropy = Encoding.UTF8.GetBytes("VirusTotalScanner.v1.entropy.b27f9a41");

    /// <summary>Encrypts <paramref name="plainText"/> and returns Base64 ciphertext.</summary>
    public static string ProtectToBase64(string plainText)
    {
        byte[] plain = Encoding.UTF8.GetBytes(plainText);
        try
        {
            byte[] cipher = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(cipher);
        }
        finally { Array.Clear(plain); }
    }

    /// <summary>
    /// Decrypts Base64 ciphertext produced by <see cref="ProtectToBase64"/>.
    /// Throws <see cref="CryptographicException"/> if the data was encrypted by another
    /// user/machine (e.g. the config was copied elsewhere).
    /// </summary>
    public static string UnprotectFromBase64(string base64)
    {
        byte[] cipher = Convert.FromBase64String(base64);
        byte[] plain = ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.CurrentUser);
        try { return Encoding.UTF8.GetString(plain); }
        finally { Array.Clear(plain); }
    }
}
