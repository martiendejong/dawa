using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Dawa.Crypto;
using System.Text.Json;

namespace Dawa.Auth;

/// <summary>
/// Persisted authentication credentials for a WhatsApp session.
/// Equivalent to Baileys' AuthState/Creds object.
/// </summary>
public sealed class AuthState
{
    [JsonPropertyName("noiseKeyPrivate")]
    public byte[] NoiseKeyPrivate { get; set; } = [];

    [JsonPropertyName("noiseKeyPublic")]
    public byte[] NoiseKeyPublic { get; set; } = [];

    [JsonPropertyName("signedIdentityKeyPrivate")]
    public byte[] SignedIdentityKeyPrivate { get; set; } = [];

    [JsonPropertyName("signedIdentityKeyPublic")]
    public byte[] SignedIdentityKeyPublic { get; set; } = [];

    [JsonPropertyName("registrationId")]
    public uint RegistrationId { get; set; }

    [JsonPropertyName("advSecretKey")]
    public byte[] AdvSecretKey { get; set; } = [];

    [JsonPropertyName("signedPreKeyPrivate")]
    public byte[] SignedPreKeyPrivate { get; set; } = [];

    [JsonPropertyName("signedPreKeyPublic")]
    public byte[] SignedPreKeyPublic { get; set; } = [];

    [JsonPropertyName("signedPreKeySignature")]
    public byte[] SignedPreKeySignature { get; set; } = [];

    [JsonPropertyName("signedPreKeyId")]
    public uint SignedPreKeyId { get; set; }

    [JsonPropertyName("preKeys")]
    public List<PreKey> PreKeys { get; set; } = [];

    [JsonPropertyName("me")]
    public MeInfo? Me { get; set; }

    [JsonPropertyName("platform")]
    public string Platform { get; set; } = "WEB";

    [JsonPropertyName("lastAccountSyncTimestamp")]
    public long LastAccountSyncTimestamp { get; set; }

    /// <summary>True if this is a fresh (unauthenticated) state.</summary>
    [JsonIgnore]
    public bool IsFresh => Me == null;

    /// <summary>Generates a brand-new auth state (before any pairing).</summary>
    public static AuthState CreateNew()
    {
        var (noisePriv, noisePub) = Curve25519Helper.GenerateKeyPair();
        var (idPriv, idPub) = Curve25519Helper.GenerateKeyPair();
        var (spkPriv, spkPub) = Curve25519Helper.GenerateKeyPair();
        var regId = (uint)(RandomNumberGenerator.GetInt32(1, 16380));
        var advSecret = RandomNumberGenerator.GetBytes(32);

        // Sign pre-key (simplified — real impl uses Ed25519 over ECDH key)
        var sig = SignPreKey(idPriv, spkPub);

        var state = new AuthState
        {
            NoiseKeyPrivate = noisePriv,
            NoiseKeyPublic = noisePub,
            SignedIdentityKeyPrivate = idPriv,
            SignedIdentityKeyPublic = idPub,
            RegistrationId = regId,
            AdvSecretKey = advSecret,
            SignedPreKeyPrivate = spkPriv,
            SignedPreKeyPublic = spkPub,
            SignedPreKeySignature = sig,
            SignedPreKeyId = 1,
        };

        // Generate 100 one-time pre-keys
        for (uint i = 0; i < 100; i++)
        {
            var (priv, pub) = Curve25519Helper.GenerateKeyPair();
            state.PreKeys.Add(new PreKey { Id = i + 1, Private = priv, Public = pub });
        }

        return state;
    }

    private static byte[] SignPreKey(byte[] identityPriv, byte[] preKeyPub)
    {
        // XEdDSA: uses the Curve25519 identity private key directly as an Ed25519 scalar.
        // This matches Baileys / Signal's curve25519-js curve25519_sign() behaviour.
        // Returns a 64-byte signature (R ‖ s).
        return XEdDSA.Sign(identityPriv, preKeyPub);
    }
}

public sealed class PreKey
{
    [JsonPropertyName("id")]
    public uint Id { get; set; }

    [JsonPropertyName("private")]
    public byte[] Private { get; set; } = [];

    [JsonPropertyName("public")]
    public byte[] Public { get; set; } = [];
}

public sealed class MeInfo
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("verifiedName")]
    public string? VerifiedName { get; set; }
}
