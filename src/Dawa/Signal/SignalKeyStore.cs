using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dawa.Auth;
using Dawa.Crypto;

namespace Dawa.Signal;

/// <summary>
/// Stores and manages Signal Protocol keys: sessions, pre-keys, signed pre-keys.
/// Persists to the session directory alongside the auth credentials.
/// </summary>
public sealed class SignalKeyStore
{
    private readonly string _directory;
    private readonly Dictionary<string, SignalSession> _sessions = new();

    private static readonly JsonSerializerOptions _jsonOpts = new() { WriteIndented = true };

    public SignalKeyStore(string directory)
    {
        _directory = directory;
        Directory.CreateDirectory(directory);
    }

    // ─── Session management ───────────────────────────────────────────────────

    public SignalSession? GetSession(string jid)
        => _sessions.TryGetValue(jid, out var s) ? s : null;

    public void PutSession(string jid, SignalSession session)
        => _sessions[jid] = session;

    public bool HasSession(string jid) => _sessions.ContainsKey(jid);

    // ─── Pre-key operations ───────────────────────────────────────────────────

    public async Task<PreKey?> GetPreKeyAsync(uint id, AuthState auth)
    {
        return auth.PreKeys.FirstOrDefault(k => k.Id == id);
    }

    public void RemovePreKey(uint id, AuthState auth)
    {
        auth.PreKeys.RemoveAll(k => k.Id == id);
    }

    // ─── Key derivation helpers ───────────────────────────────────────────────

    /// <summary>
    /// Derives a new session from a pre-key bundle (X3DH key agreement).
    /// </summary>
    public SignalSession DeriveSession(
        string recipientJid,
        byte[] ourIdentityPriv,
        byte[] theirIdentityPub,
        byte[] theirSignedPreKeyPub,
        byte[] theirPreKeyPub,
        byte[] ourEphemeralPriv,
        byte[] ourEphemeralPub)
    {
        // X3DH: DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B),
        //        DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B)
        var dh1 = Curve25519Helper.DH(ourIdentityPriv, theirSignedPreKeyPub);
        var dh2 = Curve25519Helper.DH(ourEphemeralPriv, theirIdentityPub);
        var dh3 = Curve25519Helper.DH(ourEphemeralPriv, theirSignedPreKeyPub);
        var dh4 = Curve25519Helper.DH(ourEphemeralPriv, theirPreKeyPub);

        var masterSecret = dh1.Concat(dh2).Concat(dh3).Concat(dh4).ToArray();
        var zeroSalt = new byte[32];
        var (rootKey, chainKey) = DawaHKDF.DeriveKeys(masterSecret, zeroSalt);

        return new SignalSession
        {
            RemoteJid = recipientJid,
            RootKey = rootKey,
            SendChainKey = chainKey,
            ReceiveChainKey = Array.Empty<byte>(),
            SendCounter = 0,
            ReceiveCounter = 0,
            TheirCurrentRatchetPublic = theirSignedPreKeyPub,
            OurRatchetPrivate = ourEphemeralPriv,
            OurRatchetPublic = ourEphemeralPub,
        };
    }

    // ─── Message key derivation (Double Ratchet) ──────────────────────────────

    public (byte[] messageKey, byte[] nextChainKey) DeriveMessageKeys(byte[] chainKey)
    {
        var messageKey = HMACSHA256.HashData(chainKey, new byte[] { 0x01 });
        var nextChainKey = HMACSHA256.HashData(chainKey, new byte[] { 0x02 });
        return (messageKey, nextChainKey);
    }
}

/// <summary>A Signal protocol session for a single recipient.</summary>
public sealed class SignalSession
{
    public string RemoteJid { get; set; } = "";
    public byte[] RootKey { get; set; } = [];
    public byte[] SendChainKey { get; set; } = [];
    public byte[] ReceiveChainKey { get; set; } = [];
    public uint SendCounter { get; set; }
    public uint ReceiveCounter { get; set; }
    public byte[] TheirCurrentRatchetPublic { get; set; } = [];
    public byte[] OurRatchetPrivate { get; set; } = [];
    public byte[] OurRatchetPublic { get; set; } = [];
}
