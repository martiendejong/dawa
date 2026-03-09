using System.Security.Cryptography;

namespace Dawa.Crypto;

/// <summary>AES-256-GCM authenticated encryption helper.</summary>
public static class AesGcmHelper
{
    private const int TagSize = 16;
    private const int NonceSize = 12;

    /// <summary>
    /// Encrypts plaintext with AES-256-GCM.
    /// Returns: nonce(12) + ciphertext + tag(16) — unless you supply an explicit nonce.
    /// </summary>
    public static byte[] Encrypt(byte[] key, byte[] plaintext, byte[]? associatedData = null, byte[]? nonce = null)
    {
        nonce ??= RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        var result = new byte[NonceSize + ciphertext.Length + TagSize];
        nonce.CopyTo(result, 0);
        ciphertext.CopyTo(result, NonceSize);
        tag.CopyTo(result, NonceSize + ciphertext.Length);
        return result;
    }

    /// <summary>
    /// Encrypts with an explicit counter-based nonce (Noise protocol transport).
    /// Returns ciphertext + tag(16).
    /// </summary>
    public static byte[] EncryptWithCounter(byte[] key, ulong counter, byte[] plaintext, byte[]? associatedData = null)
    {
        var nonce = CounterToNonce(counter);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        var result = new byte[ciphertext.Length + TagSize];
        ciphertext.CopyTo(result, 0);
        tag.CopyTo(result, ciphertext.Length);
        return result;
    }

    /// <summary>
    /// Decrypts ciphertext+tag (no nonce prefix) with counter-based nonce.
    /// </summary>
    public static byte[] DecryptWithCounter(byte[] key, ulong counter, byte[] ciphertextWithTag, byte[]? associatedData = null)
    {
        if (ciphertextWithTag.Length < TagSize)
            throw new CryptographicException("Ciphertext too short.");

        var nonce = CounterToNonce(counter);
        var cipherLen = ciphertextWithTag.Length - TagSize;
        var ciphertext = ciphertextWithTag[..cipherLen];
        var tag = ciphertextWithTag[cipherLen..];
        var plaintext = new byte[cipherLen];

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    /// <summary>
    /// Decrypts with an explicit nonce supplied in the first 12 bytes of the buffer.
    /// </summary>
    public static byte[] DecryptWithNoncePrefix(byte[] key, byte[] nonceAndCiphertextAndTag, byte[]? associatedData = null)
    {
        var nonce = nonceAndCiphertextAndTag[..NonceSize];
        var cipherLen = nonceAndCiphertextAndTag.Length - NonceSize - TagSize;
        var ciphertext = nonceAndCiphertextAndTag[NonceSize..(NonceSize + cipherLen)];
        var tag = nonceAndCiphertextAndTag[(NonceSize + cipherLen)..];
        var plaintext = new byte[cipherLen];

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    /// <summary>
    /// Encrypt using raw nonce byte array.
    /// Returns ciphertext + tag(16).
    /// </summary>
    public static byte[] EncryptRaw(byte[] key, byte[] nonce, byte[] plaintext, byte[]? associatedData = null)
    {
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        var result = new byte[ciphertext.Length + TagSize];
        ciphertext.CopyTo(result, 0);
        tag.CopyTo(result, ciphertext.Length);
        return result;
    }

    /// <summary>
    /// Decrypt using raw nonce byte array. Input is ciphertext+tag.
    /// </summary>
    public static byte[] DecryptRaw(byte[] key, byte[] nonce, byte[] ciphertextAndTag, byte[]? associatedData = null)
    {
        if (ciphertextAndTag.Length < TagSize)
            throw new CryptographicException("Ciphertext too short.");
        var cipherLen = ciphertextAndTag.Length - TagSize;
        var plaintext = new byte[cipherLen];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertextAndTag[..cipherLen], ciphertextAndTag[cipherLen..], plaintext, associatedData);
        return plaintext;
    }

    private static byte[] CounterToNonce(ulong counter)
    {
        // 12-byte nonce: 4 zero bytes + 8-byte big-endian counter
        var nonce = new byte[NonceSize];
        var counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);
        counterBytes.CopyTo(nonce, 4);
        return nonce;
    }
}
