using System.Security.Cryptography;
using Dawa.Crypto;

namespace Dawa.Signal;

/// <summary>
/// Encrypts and decrypts WhatsApp messages using the Signal Double Ratchet algorithm.
/// </summary>
public sealed class MessageCipher
{
    private readonly SignalKeyStore _keyStore;

    public MessageCipher(SignalKeyStore keyStore)
    {
        _keyStore = keyStore;
    }

    /// <summary>
    /// Encrypts a plaintext message for a recipient. Returns encrypted bytes + a pre-key message header.
    /// </summary>
    public (byte[] ciphertext, bool isPreKey) Encrypt(string recipientJid, byte[] plaintext)
    {
        var session = _keyStore.GetSession(recipientJid);
        if (session == null)
            throw new InvalidOperationException($"No Signal session for {recipientJid}. Must pair first.");

        var (messageKey, nextChainKey) = _keyStore.DeriveMessageKeys(session.SendChainKey);
        session.SendChainKey = nextChainKey;

        // Derive AES and HMAC keys from the message key via HKDF
        var keyMaterial = DawaHKDF.DeriveKey(messageKey, new byte[32], null, 80);
        var cipherKey = keyMaterial[..32];
        var macKey = keyMaterial[32..64];
        var iv = keyMaterial[64..80];

        // Encrypt with AES-CBC (Signal uses AES-CBC, not GCM)
        var ciphertext = AesCbcEncrypt(cipherKey, iv, plaintext);

        // MAC over version(1) + iv(16) + ciphertext
        var macInput = new byte[1 + 16 + ciphertext.Length];
        macInput[0] = 3; // Signal version
        iv.CopyTo(macInput, 1);
        ciphertext.CopyTo(macInput, 17);
        var mac = HMACSHA256.HashData(macKey, macInput)[..8];

        var result = new byte[1 + 16 + ciphertext.Length + 8];
        result[0] = 3;
        iv.CopyTo(result, 1);
        ciphertext.CopyTo(result, 17);
        mac.CopyTo(result, 17 + ciphertext.Length);

        session.SendCounter++;
        return (result, false);
    }

    /// <summary>
    /// Decrypts a received Signal message.
    /// </summary>
    public byte[] Decrypt(string senderJid, byte[] encryptedMessage, bool isPreKey)
    {
        var session = _keyStore.GetSession(senderJid);
        if (session == null)
            throw new InvalidOperationException($"No Signal session for {senderJid}.");

        var (messageKey, nextChainKey) = _keyStore.DeriveMessageKeys(session.ReceiveChainKey);
        session.ReceiveChainKey = nextChainKey;

        var keyMaterial = DawaHKDF.DeriveKey(messageKey, new byte[32], null, 80);
        var cipherKey = keyMaterial[..32];
        var macKey = keyMaterial[32..64];
        var iv = keyMaterial[64..80];

        // Strip version(1) + iv(16) + mac(8)
        if (encryptedMessage.Length < 25) throw new CryptographicException("Message too short.");
        var ciphertext = encryptedMessage[17..(encryptedMessage.Length - 8)];

        return AesCbcDecrypt(cipherKey, iv, ciphertext);
    }

    private static byte[] AesCbcEncrypt(byte[] key, byte[] iv, byte[] plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    private static byte[] AesCbcDecrypt(byte[] key, byte[] iv, byte[] ciphertext)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        return dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }
}
