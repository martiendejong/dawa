using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Dawa.Auth;
using Dawa.Crypto;
using Dawa.Noise;
using Dawa.Proto;
using Xunit;

namespace Dawa.Tests;

/// <summary>
/// Regression tests for the 5 handshake-blocking crypto/registration fixes
/// (869ceb2e8 / 2uw / 2jp / 2t7 / 3w5). Each fix was verified against the actual
/// WhiskeySockets/Baileys source; these tests lock that behaviour in offline so
/// it can't silently regress the way it already did once (a prior "swap" commit
/// plus a misleading code comment had MixKey inverted).
///
/// The definitive gate remains a live WhatsApp handshake reaching the
/// authenticated state without AuthenticationTagMismatch — see samples/Dawa.Console.
/// </summary>
public class HandshakeCryptoTests
{
    // ── 869ceb2uw: AES-GCM transport nonce layout (spec-lock) ───────────────────
    // Baileys noise-handler.ts: new DataView(iv).setUint32(8, counter)
    //   => 8 zero bytes, then a big-endian uint32 counter in the LAST 4 bytes.
    //
    // HONESTY NOTE: the pre-fix code wrote an 8-byte big-endian counter at offset 4.
    // For every counter < 2^32 (i.e. every value a real Noise transport session ever
    // reaches — the counter resets to 0 on each MixKey) that produced the SAME 12
    // bytes as the Baileys form, so the change was a robustness/clarity cleanup, not
    // the fix for the AuthTagMismatch. This test is a spec-lock: it proves Dawa's
    // nonce matches Baileys AND rejects a genuinely-wrong offset (e.g. offset 0), so
    // a future regression that actually breaks the layout is caught.
    [Fact]
    public void CounterNonce_MatchesBaileysGenerateIV_AndRejectsWrongOffset()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("dawa transport frame");
        var aad = System.Text.Encoding.UTF8.GetBytes("noise-hash");
        const ulong counter = 7;

        // Dawa encrypts (ciphertext + tag, no nonce prefix).
        var dawaCt = AesGcmHelper.EncryptWithCounter(key, counter, plaintext, aad);
        var ct = dawaCt[..^16];
        var tag = dawaCt[^16..];

        // Baileys nonce (uint32 @ offset 8) decrypts Dawa's output.
        var baileysNonce = new byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(baileysNonce.AsSpan(8), (uint)counter);
        var decrypted = new byte[ct.Length];
        using (var aes = new AesGcm(key, 16))
            aes.Decrypt(baileysNonce, ct, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);

        // A wrong layout (counter as uint32 @ offset 0) must NOT decrypt — guards
        // against a future regression that moves the counter to the wrong position.
        var wrongNonce = new byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(wrongNonce.AsSpan(0), (uint)counter);
        using var aes2 = new AesGcm(key, 16);
        Assert.ThrowsAny<CryptographicException>(() =>
            aes2.Decrypt(wrongNonce, ct, tag, new byte[ct.Length], aad));
    }

    [Fact]
    public void CounterNonce_RoundtripsWithinDawa()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("roundtrip payload");
        const ulong counter = 42;

        var ct = AesGcmHelper.EncryptWithCounter(key, counter, plaintext);
        var pt = AesGcmHelper.DecryptWithCounter(key, counter, ct);

        Assert.Equal(plaintext, pt);
    }

    // ── underpins 869ceb2e8: DeriveKeys splits HKDF output in order ──────────────
    [Fact]
    public void DeriveKeys_ReturnsFirstAndSecondHalvesInOrder()
    {
        var ikm = RandomNumberGenerator.GetBytes(32);
        var salt = RandomNumberGenerator.GetBytes(32);

        var full = DawaHKDF.DeriveKey(ikm, salt, null, 64);
        var (first, second) = DawaHKDF.DeriveKeys(ikm, salt);

        Assert.Equal(full[..32], first);
        Assert.Equal(full[32..], second);
    }

    // ── 869ceb2e8: MixKey must set chaining key = FIRST HKDF half ────────────────
    // Baileys mixIntoKey: salt(=chaining key) = write = localHKDF()[0:32],
    //                     encKey            = read  = localHKDF()[32:64].
    [Fact]
    public void MixKey_SetsChainingKeyToFirstHalf()
    {
        var ns = new NoiseState();
        var ck0 = ns.ChainingKey;                 // initial ck (SHA-padded protocol name)
        var ikm = RandomNumberGenerator.GetBytes(32);

        ns.MixKey(ikm);

        var expectedCk = DawaHKDF.DeriveKeys(ikm, ck0).Item1; // first half
        Assert.Equal(expectedCk, ns.ChainingKey);
    }

    // ── 869ceb2e8: both parties derive identical transport keys ⇒ MixKey is
    //    self-consistent for _k as well (proves the second half feeds the cipher). ─
    [Fact]
    public void MixKey_TwoParties_DeriveMatchingTransportKeys()
    {
        var ikm = RandomNumberGenerator.GetBytes(32);
        var associated = RandomNumberGenerator.GetBytes(16);

        var alice = new NoiseState();
        var bob = new NoiseState();
        alice.MixHash(associated);
        bob.MixHash(associated);
        alice.MixKey(ikm);
        bob.MixKey(ikm);

        var plaintext = System.Text.Encoding.UTF8.GetBytes("mutual transport key check");
        var ct = alice.EncryptWithAssociatedData(plaintext);
        var pt = bob.DecryptWithAssociatedData(ct);

        Assert.Equal(plaintext, pt);            // identical _k, _h, counter ⇒ handshake keys agree
        Assert.Equal(alice.ChainingKey, bob.ChainingKey);
    }

    // ── 869ceb2jp: signed pre-key signature is over the 0x05-prefixed 33-byte key ─
    // XEdDSA.Sign here is deterministic (r = SHA-512(A‖M) mod l, no random nonce),
    // so we can use Dawa's own Sign as an oracle and recompute the expected value.
    [Fact]
    public void SignedPreKey_IsSignedOverDjbPrefixedKey()
    {
        var state = AuthState.CreateNew();

        var prefixed = new byte[33];
        prefixed[0] = 0x05; // KEY_BUNDLE_TYPE
        state.SignedPreKeyPublic.CopyTo(prefixed, 1);
        var expected = XEdDSA.Sign(state.SignedIdentityKeyPrivate, prefixed);

        Assert.Equal(expected, state.SignedPreKeySignature);

        // And it is NOT the signature over the raw 32-byte key (the old bug).
        var rawSig = XEdDSA.Sign(state.SignedIdentityKeyPrivate, state.SignedPreKeyPublic);
        Assert.NotEqual(rawSig, state.SignedPreKeySignature);
    }

    [Fact]
    public void SignedPreKey_HasExpectedLengths()
    {
        var state = AuthState.CreateNew();
        Assert.Equal(32, state.SignedPreKeyPublic.Length);
        Assert.Equal(64, state.SignedPreKeySignature.Length); // R‖s
    }

    // ── 869ceb3w5: DeviceProps OS presents as Macintosh ─────────────────────────
    [Fact]
    public void DeviceProps_OsIsMacintosh()
    {
        var props = new DevicePropsMessage();
        Assert.Equal("Macintosh", props.Os);

        var encoded = props.ToByteArray();
        var macBytes = System.Text.Encoding.ASCII.GetBytes("Macintosh");
        Assert.True(ContainsSequence(encoded, macBytes), "encoded DeviceProps should carry the OS string");
    }

    // ── 869ceb2t7: WA client version bumped to the current Baileys default ───────
    // NOTE: this is a moving target — a failure here after a Baileys bump is a
    // reminder to refresh WA_VERSION, not necessarily a code defect.
    [Fact]
    public void WaVersion_IsCurrentBaileysDefault()
    {
        var field = typeof(NoiseProcessor).GetField("WA_VERSION",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(field);
        Assert.Equal("2.3000.1035194821", (string?)field!.GetRawConstantValue());
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i + needle.Length <= haystack.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
                if (haystack[i + j] != needle[j]) { match = false; break; }
            if (match) return true;
        }
        return false;
    }
}
