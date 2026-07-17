using System.Security.Cryptography;

namespace Dawa.Signal;

/// <summary>
/// Low-level AES-CBC helpers used by SignalKeyStore for message encryption/decryption.
/// The Double Ratchet logic lives in SignalKeyStore; this class is a pure static utility.
/// </summary>
public static class MessageCipher
{
    /// <summary>AES-CBC encrypt with PKCS7 padding.</summary>
    public static byte[] AesCbcEncrypt(byte[] key, byte[] iv, byte[] plaintext)
    {
        using var aes = Aes.Create();
        aes.Key     = key;
        aes.IV      = iv;
        aes.Mode    = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    /// <summary>AES-CBC decrypt with PKCS7 padding.</summary>
    public static byte[] AesCbcDecrypt(byte[] key, byte[] iv, byte[] ciphertext)
    {
        using var aes = Aes.Create();
        aes.Key     = key;
        aes.IV      = iv;
        aes.Mode    = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        return dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }
}
