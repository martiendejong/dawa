using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dawa.Auth;
using Dawa.Crypto;

namespace Dawa.Signal;

/// <summary>
/// Complete Signal Protocol session management — X3DH + Double Ratchet.
/// Handles session establishment (outgoing and incoming), message encryption, and decryption.
/// Persists sessions to signals.json in the session directory.
/// </summary>
public sealed class SignalKeyStore
{
    private readonly string _directory;
    private readonly Dictionary<string, SignalSession> _sessions = new();
    private readonly Dictionary<string, string> _lidToPhone = new(); // LID JID → phone JID mapping

    private static readonly JsonSerializerOptions _jsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    private string SessionsFilePath => Path.Combine(_directory, "signals.json");
    private string LidMappingFilePath => Path.Combine(_directory, "lid-mapping.json");

    public SignalKeyStore(string directory)
    {
        _directory = directory;
        Directory.CreateDirectory(directory);
        LoadSessions();
        LoadLidMappings();
    }

    // ─── Session management ───────────────────────────────────────────────────

    public SignalSession? GetSession(string jid) =>
        _sessions.TryGetValue(ResolveJid(jid), out var s) ? s : null;

    public void PutSession(string jid, SignalSession session)
    {
        _sessions[jid] = session;
        SaveSessions();
    }

    public bool HasSession(string jid) => _sessions.ContainsKey(ResolveJid(jid));

    public void DeleteSession(string jid)
    {
        _sessions.Remove(ResolveJid(jid));
        SaveSessions();
    }

    // ─── LID ↔ Phone JID mapping ────────────────────────────────────────────

    /// <summary>
    /// Registers a mapping from a LID JID (e.g. "824767959274@lid") to a phone JID
    /// (e.g. "31633984381@s.whatsapp.net"). Both formats refer to the same user/device
    /// and MUST share one Signal session. Registering also collapses (migrates) any
    /// existing lid-keyed session onto the canonical phone slot so the Double-Ratchet
    /// state is not split across two records — the primary cause of MAC failures on
    /// LID senders. Phone-canonical: the phone slot is the survivor.
    /// </summary>
    public void RegisterLidMapping(string lidJid, string phoneJid)
    {
        if (string.IsNullOrEmpty(lidJid) || string.IsNullOrEmpty(phoneJid)) return;
        if (!lidJid.Contains("@lid") || !phoneJid.Contains("@s.whatsapp.net")) return;

        var changed = !_lidToPhone.TryGetValue(lidJid, out var existing) || existing != phoneJid;
        if (changed)
        {
            _lidToPhone[lidJid] = phoneJid;
            SaveLidMappings();
        }

        // Collapse any lid-keyed session(s) for this user onto the canonical phone slot.
        MigrateLidSessionsToPhone(UserPart(lidJid), UserPart(phoneJid));
    }

    /// <summary>
    /// Resolves a JID to its canonical Signal session address (phone-canonical).
    /// If it's a known LID — matched exactly or by user part (device-insensitive) —
    /// returns the phone JID preserving the device id. Otherwise returns the JID as-is
    /// (an unmapped pure-LID contact keeps its own consistent lid-keyed session).
    /// </summary>
    public string ResolveJid(string jid)
    {
        if (!jid.Contains("@lid")) return jid;

        // Exact match first (fast path, handles legacy full-JID mappings)
        if (_lidToPhone.TryGetValue(jid, out var exact)) return exact;

        // User-part match: reconstruct the phone JID with the SAME device id.
        var lidUser = UserPart(jid);
        var device  = DevicePart(jid);
        foreach (var (k, v) in _lidToPhone)
        {
            if (UserPart(k) == lidUser)
            {
                var pnUser = UserPart(v);
                return device.Length > 0
                    ? $"{pnUser}:{device}@s.whatsapp.net"
                    : $"{pnUser}@s.whatsapp.net";
            }
        }
        return jid;
    }

    /// <summary>User part of a JID: "31633984381:78@s.whatsapp.net" → "31633984381".</summary>
    private static string UserPart(string jid)
    {
        var at = jid.IndexOf('@');
        var s  = at >= 0 ? jid[..at] : jid;
        var colon = s.IndexOf(':');
        return colon >= 0 ? s[..colon] : s;
    }

    /// <summary>Device part of a JID: "31633984381:78@s.whatsapp.net" → "78" ("" if none).</summary>
    private static string DevicePart(string jid)
    {
        var at = jid.IndexOf('@');
        var s  = at >= 0 ? jid[..at] : jid;
        var colon = s.IndexOf(':');
        return colon >= 0 ? s[(colon + 1)..] : "";
    }

    /// <summary>
    /// Moves every lid-keyed session for <paramref name="lidUser"/> onto the matching
    /// phone slot (same device id). Phone slot wins if it already exists (keep the
    /// canonical ratchet); otherwise the lid session is retagged to the phone JID.
    /// The lid slot is always removed afterwards so future lookups converge on one record.
    /// </summary>
    private void MigrateLidSessionsToPhone(string lidUser, string pnUser)
    {
        var lidKeys = _sessions.Keys
            .Where(k => k.Contains("@lid") && UserPart(k) == lidUser)
            .ToList();
        if (lidKeys.Count == 0) return;

        foreach (var lidKey in lidKeys)
        {
            var device   = DevicePart(lidKey);
            var phoneJid = device.Length > 0
                ? $"{pnUser}:{device}@s.whatsapp.net"
                : $"{pnUser}@s.whatsapp.net";

            if (!_sessions.ContainsKey(phoneJid))
            {
                var sess = _sessions[lidKey];
                sess.RemoteJid = phoneJid;
                _sessions[phoneJid] = sess;
            }
            _sessions.Remove(lidKey);
        }
        SaveSessions();
    }

    /// <summary>
    /// For an @lid JID with no explicit mapping, try to find an existing session
    /// by matching identity keys from the PreKeyWhisperMessage.
    /// </summary>
    private string? TryResolveByIdentity(string lidJid, byte[] theirIdentityPub)
    {
        foreach (var (existingJid, session) in _sessions)
        {
            if (existingJid.Contains("@s.whatsapp.net") &&
                session.TheirIdentityPublic.Length > 0 &&
                session.TheirIdentityPublic.SequenceEqual(theirIdentityPub))
            {
                // Found matching session — register the mapping
                RegisterLidMapping(lidJid, existingJid);
                return existingJid;
            }
        }
        return null;
    }

    // ─── X3DH: Outgoing (initiator) ──────────────────────────────────────────

    /// <summary>
    /// Initializes an outgoing session using X3DH key agreement.
    /// Call this before sending the first message to a new contact.
    /// </summary>
    public void InitOutgoingSession(string jid, PreKeyBundle bundle, AuthState auth)
    {
        // Generate ephemeral key pair EK1 (used as baseKey in PreKeyWhisperMessage header)
        var (ek1Priv, ek1Pub) = Curve25519Helper.GenerateKeyPair();

        // Strip 0x05 prefix from their keys before DH operations
        var theirIdentityPub     = StripKeyPrefix(bundle.TheirIdentityPub);
        var theirSignedPreKeyPub = StripKeyPrefix(bundle.TheirSignedPreKeyPub);

        // X3DH key agreement (WhatsApp/Signal convention):
        // DH1 = DH(our_identity_priv, their_signed_prekey_pub)
        // DH2 = DH(our_ephemeral_priv, their_identity_pub)
        // DH3 = DH(our_ephemeral_priv, their_signed_prekey_pub)
        // DH4 = DH(our_ephemeral_priv, their_one_time_prekey_pub) [if present]
        var dh1 = Curve25519Helper.DH(auth.SignedIdentityKeyPrivate, theirSignedPreKeyPub);
        var dh2 = Curve25519Helper.DH(ek1Priv, theirIdentityPub);
        var dh3 = Curve25519Helper.DH(ek1Priv, theirSignedPreKeyPub);

        byte[]? dh4 = null;
        if (bundle.TheirOneTimePreKeyPub != null && bundle.TheirOneTimePreKeyPub.Length > 0)
        {
            var theirOtpk = StripKeyPrefix(bundle.TheirOneTimePreKeyPub);
            dh4 = Curve25519Helper.DH(ek1Priv, theirOtpk);
        }

        // F = 32 bytes of 0xFF (Signal version 3 discontinuity padding)
        var f = new byte[32];
        Array.Fill(f, (byte)0xFF);

        // masterSecret = F || DH1 || DH2 || DH3 [|| DH4]
        var masterParts = new List<byte[]> { f, dh1, dh2, dh3 };
        if (dh4 != null) masterParts.Add(dh4);
        var masterSecret = Concat(masterParts.ToArray());

        // (rootKey, sharedChainKey) = HKDF(masterSecret, salt=zero32, info="WhisperText", 64)
        var zeroSalt = new byte[32];
        var info     = Encoding.UTF8.GetBytes("WhisperText");
        var derived  = DawaHKDF.DeriveKey(masterSecret, zeroSalt, info, 64);
        var rootKey0 = derived[..32];
        // sharedChainKey is derived but not directly used — we immediately do the first ratchet

        // Generate ratchet key pair (the ephemeralKeyPair in Baileys — goes into WhisperMessage)
        var (ek2Priv, ek2Pub) = Curve25519Helper.GenerateKeyPair();

        // ONE sending ratchet step: DH(ratchetKey, theirSignedPreKey) + rootKey0
        // Matches Baileys' calculateSendingRatchet(session, theirSignedPubKey)
        var ratchetDH = Curve25519Helper.DH(ek2Priv, theirSignedPreKeyPub);
        var (rootKey2, sendChainKey) = HkdfRatchetStep(rootKey0, ratchetDH);

        // === DEBUG: Log all intermediate X3DH values ===
        try
        {
            var logDir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);
            File.AppendAllText(Path.Combine(logDir, "signal-x3dh-debug.log"),
                $"[{DateTime.UtcNow:HH:mm:ss}] InitOutgoingSession for {jid}\n" +
                $"  bundle.TheirIdentityPub len={bundle.TheirIdentityPub.Length} hex={Convert.ToHexString(bundle.TheirIdentityPub)}\n" +
                $"  bundle.TheirSignedPreKeyPub len={bundle.TheirSignedPreKeyPub.Length} hex={Convert.ToHexString(bundle.TheirSignedPreKeyPub)}\n" +
                $"  bundle.TheirSignedPreKeyId={bundle.TheirSignedPreKeyId}\n" +
                $"  bundle.TheirOneTimePreKeyId={bundle.TheirOneTimePreKeyId}\n" +
                $"  bundle.TheirOneTimePreKeyPub len={bundle.TheirOneTimePreKeyPub?.Length ?? 0}\n" +
                $"  bundle.PeerRegistrationId={bundle.PeerRegistrationId}\n" +
                $"  auth.SignedIdentityKeyPub={Convert.ToHexString(auth.SignedIdentityKeyPublic)}\n" +
                $"  auth.RegistrationId={auth.RegistrationId}\n" +
                $"  ek1Pub={Convert.ToHexString(ek1Pub)}\n" +
                $"  ek2Pub={Convert.ToHexString(ek2Pub)}\n" +
                $"  theirIdentityPub(stripped)={Convert.ToHexString(theirIdentityPub)}\n" +
                $"  theirSignedPreKeyPub(stripped)={Convert.ToHexString(theirSignedPreKeyPub)}\n" +
                $"  DH1={Convert.ToHexString(dh1)}\n" +
                $"  DH2={Convert.ToHexString(dh2)}\n" +
                $"  DH3={Convert.ToHexString(dh3)}\n" +
                $"  DH4={( dh4 != null ? Convert.ToHexString(dh4) : "null")}\n" +
                $"  masterSecret len={masterSecret.Length} first8={Convert.ToHexString(masterSecret[..8])}\n" +
                $"  rootKey0={Convert.ToHexString(rootKey0)}\n" +
                $"  ratchetDH={Convert.ToHexString(ratchetDH)}\n" +
                $"  rootKey2={Convert.ToHexString(rootKey2)}\n" +
                $"  sendChainKey={Convert.ToHexString(sendChainKey)}\n\n");
        }
        catch { /* best effort */ }

        // Preserve existing ReceiveChainKey so incoming messages (e.g. ON_DEMAND history
        // sync response) can still be decrypted after we reset the outgoing session.
        var existingReceiveChainKey = GetSession(jid)?.ReceiveChainKey ?? [];

        var session = new SignalSession
        {
            RemoteJid                = jid,
            RootKey                  = rootKey2,
            SendChainKey             = sendChainKey,
            ReceiveChainKey          = existingReceiveChainKey,
            SendCounter              = 0,
            ReceiveCounter           = 0,
            PrevSendCounter          = 0,
            TheirCurrentRatchetPublic = bundle.TheirSignedPreKeyPub,
            OurRatchetPrivate        = ek2Priv,
            OurRatchetPublic         = ek2Pub,
            TheirIdentityPublic      = theirIdentityPub,  // CRITICAL: needed for MAC computation
            BaseKey                  = ek1Pub,
            PreKeyId                 = bundle.TheirOneTimePreKeyId,
            SignedPreKeyId           = bundle.TheirSignedPreKeyId,
            PeerRegistrationId       = bundle.PeerRegistrationId,
            IsEstablished            = false,  // first message will be PreKeyWhisperMessage
        };

        _sessions[jid] = session;
        SaveSessions();
    }

    // ─── X3DH: Incoming (responder) ──────────────────────────────────────────

    /// <summary>
    /// Initializes an incoming session when we receive the first PreKeyWhisperMessage.
    /// </summary>
    public void InitIncomingSession(string jid, PreKeyWhisperMessageProto pkmsg, AuthState auth)
    {
        var theirIdentityPub = StripKeyPrefix(pkmsg.IdentityKey);
        var baseKey          = StripKeyPrefix(pkmsg.BaseKey);

        // X3DH receiver side:
        // DH1 = DH(our_signed_prekey_priv, their_identity_pub)
        // DH2 = DH(our_identity_priv, their_base_key)
        // DH3 = DH(our_signed_prekey_priv, their_base_key)
        // DH4 = DH(our_one_time_prekey_priv[preKeyId], their_base_key) [if preKeyId != 0]
        var dh1 = Curve25519Helper.DH(auth.SignedPreKeyPrivate, theirIdentityPub);
        var dh2 = Curve25519Helper.DH(auth.SignedIdentityKeyPrivate, baseKey);
        var dh3 = Curve25519Helper.DH(auth.SignedPreKeyPrivate, baseKey);

        byte[]? dh4 = null;
        if (pkmsg.PreKeyId != 0)
        {
            var otpk = auth.PreKeys.FirstOrDefault(k => k.Id == pkmsg.PreKeyId);
            if (otpk != null)
            {
                dh4 = Curve25519Helper.DH(otpk.Private, baseKey);
                auth.PreKeys.RemoveAll(k => k.Id == pkmsg.PreKeyId);
            }
        }

        var f = new byte[32];
        Array.Fill(f, (byte)0xFF);

        var masterParts = new List<byte[]> { f, dh1, dh2, dh3 };
        if (dh4 != null) masterParts.Add(dh4);
        var masterSecret = Concat(masterParts.ToArray());

        var zeroSalt = new byte[32];
        var info     = Encoding.UTF8.GetBytes("WhisperText");
        var derived  = DawaHKDF.DeriveKey(masterSecret, zeroSalt, info, 64);

        // Signal protocol: X3DH HKDF(64 bytes) gives us:
        //   derived[0..32]  = root key
        //   derived[32..64] = NOT directly used as receive chain key
        //
        // The receive chain key is computed via a DH ratchet step on the FIRST decrypt:
        //   DH(ourSPKPriv, senderRatchetKey) + rootKey → (newRootKey, receiveChainKey)
        // where senderRatchetKey is the ephemeralKey in the inner WhisperMessage —
        // always a freshly generated key, DIFFERENT from the outer baseKey.
        //
        // To trigger this ratchet step on first decrypt, we store the outer baseKey as
        // TheirCurrentRatchetPublic (not the inner ratchet key). Since they differ,
        // ratchetMatched=false and the ratchet step runs correctly.
        var rootKey = derived[..32];

        // Debug: log X3DH details + key consistency check
        try
        {
            // Verify private→public consistency (derived pub should match stored pub)
            var spkPrivParam = new Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters(auth.SignedPreKeyPrivate, 0);
            var spkPubDerived = new byte[32]; spkPrivParam.GeneratePublicKey().Encode(spkPubDerived, 0);
            var idPrivParam  = new Org.BouncyCastle.Crypto.Parameters.X25519PrivateKeyParameters(auth.SignedIdentityKeyPrivate, 0);
            var idPubDerived = new byte[32];  idPrivParam.GeneratePublicKey().Encode(idPubDerived, 0);
            bool spkOk = spkPubDerived.SequenceEqual(auth.SignedPreKeyPublic);
            bool idOk  = idPubDerived.SequenceEqual(auth.SignedIdentityKeyPublic);

            var logDir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);
            File.AppendAllText(Path.Combine(logDir, "signal-debug.log"),
                $"[{DateTime.UtcNow:HH:mm:ss}] InitIncomingSession for {jid}\n" +
                $"  preKeyId={pkmsg.PreKeyId} signedPreKeyId={pkmsg.SignedPreKeyId}\n" +
                $"  preKeyFound={dh4 != null} preKeysRemaining={auth.PreKeys.Count}\n" +
                $"  KEY CONSISTENCY: spkPriv→pub={spkOk} (stored={Convert.ToHexString(auth.SignedPreKeyPublic[..4])} derived={Convert.ToHexString(spkPubDerived[..4])})\n" +
                $"  KEY CONSISTENCY: idPriv→pub={idOk}  (stored={Convert.ToHexString(auth.SignedIdentityKeyPublic[..4])} derived={Convert.ToHexString(idPubDerived[..4])})\n" +
                $"  theirIdentity={Convert.ToHexString(theirIdentityPub[..4])}\n" +
                $"  dh1={Convert.ToHexString(dh1)} dh2={Convert.ToHexString(dh2)} dh3={Convert.ToHexString(dh3)}" +
                (dh4 != null ? $"\n  dh4={Convert.ToHexString(dh4)}" : "") + "\n" +
                $"  masterSecret[..8]={Convert.ToHexString(masterSecret[..8])}\n" +
                $"  rootKey={Convert.ToHexString(rootKey)}\n" +
                $"  NOTE: ReceiveChainKey will be computed on first decrypt via DH ratchet step\n\n");
        }
        catch { /* best effort */ }

        // Use the OUTER baseKey as the initial TheirCurrentRatchetPublic.
        // The inner WhisperMessage's ephemeralKey (ratchet key) is always a DIFFERENT,
        // freshly-generated key from the sender. Storing baseKey here ensures
        // ratchetMatched=false on the first decrypt, triggering the correct DH ratchet step
        // that derives the actual receive chain key.
        var session = new SignalSession
        {
            RemoteJid                = jid,
            RootKey                  = rootKey,
            SendChainKey             = [],
            ReceiveChainKey          = [],  // Empty — computed via ratchet step on first decrypt
            SendCounter              = 0,
            ReceiveCounter           = 0,
            PrevSendCounter          = 0,
            TheirCurrentRatchetPublic = StripKeyPrefix(pkmsg.BaseKey),  // Outer baseKey, NOT inner ratchet key
            OurRatchetPrivate        = auth.SignedPreKeyPrivate,
            OurRatchetPublic         = auth.SignedPreKeyPublic,
            TheirIdentityPublic      = theirIdentityPub,
            BaseKey                  = pkmsg.BaseKey,
            PreKeyId                 = pkmsg.PreKeyId,
            SignedPreKeyId           = pkmsg.SignedPreKeyId,
            PeerRegistrationId       = 0,
            IsEstablished            = true,
        };

        _sessions[jid] = session;
        SaveSessions();
    }

    // ─── Encrypt ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Encrypts a plaintext for the given JID using the Double Ratchet.
    /// Returns (encryptedBytes, isPreKey) where isPreKey=true means the caller
    /// should wrap this in a PreKeyWhisperMessage frame.
    /// </summary>
    public (byte[] encBytes, bool isPreKey) EncryptMessage(string jid, byte[] plaintext, AuthState auth)
    {
        var session = _sessions.TryGetValue(jid, out var s) ? s
            : throw new InvalidOperationException($"No Signal session for {jid}. Call InitOutgoingSession first.");

        // Derive message key from current send chain key
        var (messageKey, nextChainKey) = DeriveMessageKeys(session.SendChainKey);
        session.SendChainKey = nextChainKey;

        // Expand message key — Signal spec requires info="WhisperMessageKeys"
        var keyMaterial = DawaHKDF.DeriveKey(messageKey, new byte[32], Encoding.UTF8.GetBytes("WhisperMessageKeys"), 80);
        var encKey = keyMaterial[..32];
        var macKey = keyMaterial[32..64];
        var iv     = keyMaterial[64..80];

        // AES-CBC encrypt
        var ciphertext = MessageCipher.AesCbcEncrypt(encKey, iv, plaintext);

        // Build WhisperMessageProto
        // Keys in Signal protobufs MUST include 0x05 prefix (33 bytes) — Baileys convention
        var whisperProto = new WhisperMessageProto
        {
            RatchetKey      = PrefixKey(session.OurRatchetPublic),
            Counter         = session.SendCounter,
            PreviousCounter = session.PrevSendCounter,
            Ciphertext      = ciphertext,
        };
        var protoBytes = whisperProto.ToByteArray();

        // MAC = HMAC-SHA256(macKey, senderIdentity_33 || receiverIdentity_33 || 0x33 || proto_bytes)[0:8]
        var ourIdentity33   = new byte[] { 0x05 }.Concat(auth.SignedIdentityKeyPublic).ToArray();
        var theirIdentity33 = new byte[] { 0x05 }.Concat(session.TheirIdentityPublic).ToArray();
        var macInput = new byte[33 + 33 + 1 + protoBytes.Length];
        ourIdentity33.CopyTo(macInput, 0);
        theirIdentity33.CopyTo(macInput, 33);
        macInput[66] = 0x33;
        protoBytes.CopyTo(macInput, 67);
        var mac = HMACSHA256.HashData(macKey, macInput)[..8];

        // whisperBytes = [0x33] + proto_bytes + mac
        var whisperBytes = new byte[1 + protoBytes.Length + 8];
        whisperBytes[0] = 0x33;
        protoBytes.CopyTo(whisperBytes, 1);
        mac.CopyTo(whisperBytes, 1 + protoBytes.Length);

        session.SendCounter++;

        bool isPreKey = !session.IsEstablished;

        byte[] result;
        if (isPreKey)
        {
            // Wrap in PreKeyWhisperMessageProto
            // Keys MUST include 0x05 prefix (33 bytes) — recipient's libsignal expects this
            var pkProto = new PreKeyWhisperMessageProto
            {
                PreKeyId       = session.PreKeyId,
                BaseKey        = PrefixKey(session.BaseKey),
                IdentityKey    = PrefixKey(auth.SignedIdentityKeyPublic),
                Message        = whisperBytes,
                RegistrationId = auth.RegistrationId,
                SignedPreKeyId = session.SignedPreKeyId,
            };
            var pkProtoBytes = pkProto.ToByteArray();
            result = new byte[1 + pkProtoBytes.Length];
            result[0] = 0x33;
            pkProtoBytes.CopyTo(result, 1);

            // Mark session as established after first message sent
            session.IsEstablished = true;
        }
        else
        {
            result = whisperBytes;
        }

        // === DEBUG: Log all encryption details ===
        try
        {
            var logDir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);
            File.AppendAllText(Path.Combine(logDir, "signal-encrypt-debug.log"),
                $"[{DateTime.UtcNow:HH:mm:ss}] EncryptMessage for {jid}\n" +
                $"  sendChainKey(before)={Convert.ToHexString(session.SendChainKey)}\n" +
                $"  messageKey={Convert.ToHexString(messageKey)}\n" +
                $"  encKey={Convert.ToHexString(encKey)}\n" +
                $"  macKey={Convert.ToHexString(macKey)}\n" +
                $"  iv={Convert.ToHexString(iv)}\n" +
                $"  plaintext len={plaintext.Length} first16={Convert.ToHexString(plaintext[..Math.Min(16, plaintext.Length)])}\n" +
                $"  ciphertext len={ciphertext.Length} first16={Convert.ToHexString(ciphertext[..Math.Min(16, ciphertext.Length)])}\n" +
                $"  ratchetKey(prefixed)={Convert.ToHexString(PrefixKey(session.OurRatchetPublic))}\n" +
                $"  counter={session.SendCounter - 1} prevCounter={session.PrevSendCounter}\n" +
                $"  protoBytes len={protoBytes.Length} hex={Convert.ToHexString(protoBytes)}\n" +
                $"  ourIdentity33={Convert.ToHexString(ourIdentity33)}\n" +
                $"  theirIdentity33={Convert.ToHexString(theirIdentity33)}\n" +
                $"  macInput len={macInput.Length} first32={Convert.ToHexString(macInput[..Math.Min(32, macInput.Length)])}\n" +
                $"  mac={Convert.ToHexString(mac)}\n" +
                $"  whisperBytes len={whisperBytes.Length} first32={Convert.ToHexString(whisperBytes[..Math.Min(32, whisperBytes.Length)])}\n" +
                $"  isPreKey={isPreKey}\n" +
                (isPreKey ? (
                    $"  preKeyId={session.PreKeyId}\n" +
                    $"  baseKey(prefixed)={Convert.ToHexString(PrefixKey(session.BaseKey))}\n" +
                    $"  identityKey(prefixed)={Convert.ToHexString(PrefixKey(auth.SignedIdentityKeyPublic))}\n" +
                    $"  registrationId={auth.RegistrationId}\n" +
                    $"  signedPreKeyId={session.SignedPreKeyId}\n" +
                    $"  result len={result.Length} first32={Convert.ToHexString(result[..Math.Min(32, result.Length)])}\n"
                ) : "") +
                "\n");
        }
        catch { /* best effort */ }

        SaveSessions();
        return (result, isPreKey);
    }

    // ─── Decrypt ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Decrypts a received Signal message. type is "pkmsg" or "msg".
    /// </summary>
    public byte[] DecryptMessage(string jid, string type, byte[] ciphertext, AuthState auth)
    {
        // Resolve LID JIDs to phone JIDs — they share the same Signal session
        var resolvedJid = ResolveJid(jid);

        if (type == "pkmsg")
        {
            // Parse PreKeyWhisperMessageProto from ciphertext[1:]
            if (ciphertext.Length < 2)
                throw new CryptographicException("PreKeyWhisperMessage too short.");

            var pkProto = PreKeyWhisperMessageProto.ParseFrom(ciphertext[1..]);

            // If this is an @lid JID with no mapping yet, try to find existing session by identity key
            if (resolvedJid.Contains("@lid") && !_sessions.ContainsKey(resolvedJid))
            {
                var theirIdentity = StripKeyPrefix(pkProto.IdentityKey);
                var mapped = TryResolveByIdentity(resolvedJid, theirIdentity);
                if (mapped != null)
                    resolvedJid = mapped;
            }

            // Mirrors libsignal's initIncoming logic:
            // Each distinct pkmsg session is identified by its base key.
            // - Same base key as existing session → this is a retry of the same pkmsg, reuse session
            // - Different/no base key → new X3DH session establishment, reinitialize
            // This correctly handles:
            //   (a) Multiple pkmsgs from same JID with different base keys (different messages/sessions)
            //   (b) Retries of the same pkmsg
            //   (c) Stale bad sessions from a previous failed decrypt
            var existingSession = _sessions.TryGetValue(resolvedJid, out var es) ? es : null;
            var incomingBaseKey = pkProto.BaseKey; // 33-byte prefixed
            bool shouldReinit = existingSession == null ||
                                !existingSession.BaseKey.SequenceEqual(incomingBaseKey);
            if (shouldReinit)
                InitIncomingSession(resolvedJid, pkProto, auth);

            // The inner message is in pkProto.Message
            return DecryptWhisperMessage(resolvedJid, pkProto.Message, auth);
        }
        else
        {
            // type == "msg": regular WhisperMessage
            // For @lid with no mapping, try existing sessions (won't have identity key here, just try)
            if (resolvedJid.Contains("@lid") && !_sessions.ContainsKey(resolvedJid))
            {
                // Can't resolve without identity key in a regular msg — log and throw
                throw new InvalidOperationException($"No Signal session for LID {jid} and no mapping found.");
            }
            return DecryptWhisperMessage(resolvedJid, ciphertext, auth);
        }
    }

    // ─── Internal decrypt ────────────────────────────────────────────────────

    private byte[] DecryptWhisperMessage(string jid, byte[] whisperFrame, AuthState auth)
    {
        if (whisperFrame.Length < 10)
            throw new CryptographicException("WhisperMessage too short.");

        // whisperFrame = [0x33] + proto_bytes + mac(8)
        var protoBytes = whisperFrame[1..(whisperFrame.Length - 8)];
        var receivedMac = whisperFrame[(whisperFrame.Length - 8)..];

        var innerMsg = WhisperMessageProto.ParseFrom(protoBytes);

        var session = _sessions.TryGetValue(jid, out var s) ? s
            : throw new InvalidOperationException($"No Signal session for {jid}.");

        // IMPORTANT: Work on cloned state so MAC failure does NOT corrupt the live session.
        // Only commit the updated state after MAC verification succeeds.
        // Without this, a single MAC failure corrupts the chain and cascades into all future failures.
        byte[] wRootKey                   = session.RootKey;
        byte[] wReceiveChainKey           = session.ReceiveChainKey;
        byte[] wSendChainKey              = session.SendChainKey;
        uint   wReceiveCounter            = session.ReceiveCounter;
        uint   wSendCounter               = session.SendCounter;
        uint   wPrevSendCounter           = session.PrevSendCounter;
        byte[] wTheirCurrentRatchetPublic = session.TheirCurrentRatchetPublic;
        byte[] wOurRatchetPrivate         = session.OurRatchetPrivate;
        byte[] wOurRatchetPublic          = session.OurRatchetPublic;

        // Check if we need to do a DH ratchet step (their ratchet key changed)
        var theirRatchetPub = StripKeyPrefix(innerMsg.RatchetKey);
        var ratchetMatched = theirRatchetPub.SequenceEqual(wTheirCurrentRatchetPublic);
        if (!ratchetMatched)
        {
            // DH ratchet: advance receive chain with new ratchet key
            var (newRootKey, newReceiveChainKey) = HkdfRatchetStep(
                wRootKey,
                Curve25519Helper.DH(wOurRatchetPrivate, theirRatchetPub));

            wPrevSendCounter          = wSendCounter;
            wTheirCurrentRatchetPublic = theirRatchetPub;
            wRootKey                  = newRootKey;
            wReceiveChainKey          = newReceiveChainKey;
            wReceiveCounter           = 0;

            // Generate new ratchet key pair for next send
            var (newRatchPriv, newRatchPub) = Curve25519Helper.GenerateKeyPair();
            var (newRootKey2, newSendChainKey) = HkdfRatchetStep(
                newRootKey,
                Curve25519Helper.DH(newRatchPriv, theirRatchetPub));
            wOurRatchetPrivate = newRatchPriv;
            wOurRatchetPublic  = newRatchPub;
            wRootKey           = newRootKey2;
            wSendChainKey      = newSendChainKey;
            wSendCounter       = 0;
        }

        // Advance chain to match the sender's counter (handles out-of-order / batched messages)
        var targetCounter = innerMsg.Counter;
        while (wReceiveCounter < targetCounter)
        {
            var (_, skip) = DeriveMessageKeys(wReceiveChainKey);
            wReceiveChainKey = skip;
            wReceiveCounter++;
        }

        // Derive message key
        var chainKeyBeforeDerive = wReceiveChainKey;
        var (messageKey, nextChainKey) = DeriveMessageKeys(wReceiveChainKey);
        wReceiveChainKey = nextChainKey;

        // Expand message key — Signal spec requires info="WhisperMessageKeys"
        var keyMaterial = DawaHKDF.DeriveKey(messageKey, new byte[32], Encoding.UTF8.GetBytes("WhisperMessageKeys"), 80);
        var encKey = keyMaterial[..32];
        var macKey = keyMaterial[32..64];
        var iv     = keyMaterial[64..80];

        // Verify MAC — Signal Protocol MAC includes the version byte:
        // MAC = HMAC-SHA256(macKey, senderIdentityPub_33 || receiverIdentityPub_33 || versionByte || protoBytes)
        // This matches libsignal-java WhisperMessage.getMac() which feeds:
        //   sender_identity_key (33 bytes) + receiver_identity_key (33 bytes) + versionByte + serializedProto
        // Identity keys use 33-byte format: 0x05 prefix + 32-byte raw key
        var senderIdentity33   = new byte[] { 0x05 }.Concat(session.TheirIdentityPublic).ToArray();
        var receiverIdentity33 = new byte[] { 0x05 }.Concat(auth.SignedIdentityKeyPublic).ToArray();
        var versionByte = whisperFrame[0]; // = 0x33 for Signal v3
        var macInput = new byte[33 + 33 + 1 + protoBytes.Length];
        senderIdentity33.CopyTo(macInput, 0);
        receiverIdentity33.CopyTo(macInput, 33);
        macInput[66] = versionByte;
        protoBytes.CopyTo(macInput, 67);
        var expectedMac = HMACSHA256.HashData(macKey, macInput)[..8];
        if (!expectedMac.AsSpan().SequenceEqual(receivedMac))
        {
            // MAC failed — do NOT commit any working state changes to the live session.
            // The live session remains at its last known-good state.
            var logDir = Path.Combine(AppContext.BaseDirectory, "logs");
            try { Directory.CreateDirectory(logDir); } catch { /* best effort */ }
            try { File.AppendAllText(Path.Combine(logDir, "signal-debug.log"),
                $"[{DateTime.UtcNow:HH:mm:ss}] MAC FAIL for {jid}\n" +
                $"  ratchetMatched={ratchetMatched} ratchetKey len={innerMsg.RatchetKey.Length}\n" +
                $"  theirIdentity={Convert.ToHexString(session.TheirIdentityPublic[..Math.Min(4, session.TheirIdentityPublic.Length)])}\n" +
                $"  ourIdentity={Convert.ToHexString(auth.SignedIdentityKeyPublic[..Math.Min(4, auth.SignedIdentityKeyPublic.Length)])}\n" +
                $"  chainKey(used)={Convert.ToHexString(chainKeyBeforeDerive[..Math.Min(8, chainKeyBeforeDerive.Length)])}\n" +
                $"  messageKey={Convert.ToHexString(messageKey[..8])}\n" +
                $"  macKey={Convert.ToHexString(macKey[..8])}\n" +
                $"  expected={Convert.ToHexString(expectedMac)} received={Convert.ToHexString(receivedMac)}\n" +
                $"  whisperFrame[0]=0x{whisperFrame[0]:X2} protoLen={protoBytes.Length}\n" +
                $"  counter={innerMsg.Counter} receiveCounter={session.ReceiveCounter}\n\n");
            } catch { /* best effort logging */ }
            throw new CryptographicException("WhisperMessage MAC verification failed.");
        }

        // MAC verified — commit working state to live session
        wReceiveCounter++;
        session.RootKey                  = wRootKey;
        session.ReceiveChainKey          = wReceiveChainKey;
        session.SendChainKey             = wSendChainKey;
        session.ReceiveCounter           = wReceiveCounter;
        session.SendCounter              = wSendCounter;
        session.PrevSendCounter          = wPrevSendCounter;
        session.TheirCurrentRatchetPublic = wTheirCurrentRatchetPublic;
        session.OurRatchetPrivate        = wOurRatchetPrivate;
        session.OurRatchetPublic         = wOurRatchetPublic;

        var plaintext = MessageCipher.AesCbcDecrypt(encKey, iv, innerMsg.Ciphertext);
        // Log success
        var logDir2 = Path.Combine(AppContext.BaseDirectory, "logs");
        try { Directory.CreateDirectory(logDir2); } catch { }
        try { File.AppendAllText(Path.Combine(logDir2, "signal-debug.log"),
            $"[{DateTime.UtcNow:HH:mm:ss}] MAC OK for {jid}\n" +
            $"  ratchetMatched={ratchetMatched} counter={innerMsg.Counter} plaintextLen={plaintext.Length}\n\n");
        } catch { }
        SaveSessions();
        return plaintext;
    }

    // ─── Pre-key access ───────────────────────────────────────────────────────

    public void RemovePreKey(uint id, AuthState auth)
    {
        auth.PreKeys.RemoveAll(k => k.Id == id);
    }

    // ─── Message key derivation (symmetric ratchet) ───────────────────────────

    private static (byte[] messageKey, byte[] nextChainKey) DeriveMessageKeys(byte[] chainKey)
    {
        var messageKey   = HMACSHA256.HashData(chainKey, new byte[] { 0x01 });
        var nextChainKey = HMACSHA256.HashData(chainKey, new byte[] { 0x02 });
        return (messageKey, nextChainKey);
    }

    // ─── DH Ratchet step ──────────────────────────────────────────────────────

    /// <summary>
    /// Performs one DH ratchet step.
    /// Returns (newRootKey, newChainKey).
    /// Uses rootKey as salt, dhOutput as IKM, "WhisperRatchet" as info.
    /// </summary>
    private static (byte[] newRootKey, byte[] chainKey) HkdfRatchetStep(byte[] rootKey, byte[] dhOutput)
    {
        var info   = Encoding.UTF8.GetBytes("WhisperRatchet");
        var output = DawaHKDF.DeriveKey(dhOutput, rootKey, info, 64);
        return (output[..32], output[32..]);
    }

    // ─── Key prefix stripping ─────────────────────────────────────────────────

    /// <summary>
    /// If key is 33 bytes and key[0]==0x05, returns key[1:].
    /// Otherwise returns the key as-is (or trimmed to 32 bytes if needed).
    /// </summary>
    public static byte[] StripKeyPrefix(byte[] key)
    {
        if (key.Length == 33 && key[0] == 0x05)
            return key[1..];
        return key;
    }

    /// <summary>
    /// Adds 0x05 KEY_BUNDLE_TYPE prefix to a 32-byte key (Signal convention).
    /// If already 33 bytes with prefix, returns as-is.
    /// </summary>
    public static byte[] PrefixKey(byte[] key)
    {
        if (key.Length == 33 && key[0] == 0x05)
            return key;
        var prefixed = new byte[33];
        prefixed[0] = 0x05;
        key.AsSpan(0, Math.Min(32, key.Length)).CopyTo(prefixed.AsSpan(1));
        return prefixed;
    }

    // ─── Persistence ──────────────────────────────────────────────────────────

    private void LoadSessions()
    {
        try
        {
            if (!File.Exists(SessionsFilePath)) return;
            var json = File.ReadAllText(SessionsFilePath);
            var loaded = JsonSerializer.Deserialize<Dictionary<string, SignalSession>>(json, _jsonOpts);
            if (loaded == null) return;
            foreach (var (k, v) in loaded)
                _sessions[k] = v;
        }
        catch
        {
            // Ignore corrupt sessions file — start fresh
        }
    }

    private void SaveSessions()
    {
        try
        {
            var json = JsonSerializer.Serialize(_sessions, _jsonOpts);
            File.WriteAllText(SessionsFilePath, json);
        }
        catch
        {
            // Best-effort persistence
        }
    }

    private void LoadLidMappings()
    {
        try
        {
            if (!File.Exists(LidMappingFilePath)) return;
            var json = File.ReadAllText(LidMappingFilePath);
            var loaded = JsonSerializer.Deserialize<Dictionary<string, string>>(json, _jsonOpts);
            if (loaded == null) return;
            foreach (var (k, v) in loaded)
                _lidToPhone[k] = v;
        }
        catch { /* Ignore corrupt file */ }
    }

    private void SaveLidMappings()
    {
        try
        {
            var json = JsonSerializer.Serialize(_lidToPhone, _jsonOpts);
            File.WriteAllText(LidMappingFilePath, json);
        }
        catch { /* Best-effort */ }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private static byte[] Concat(params byte[][] arrays)
    {
        var result = new byte[arrays.Sum(a => a.Length)];
        var offset = 0;
        foreach (var a in arrays)
        {
            a.CopyTo(result, offset);
            offset += a.Length;
        }
        return result;
    }
}

// ─── Session model ────────────────────────────────────────────────────────────

/// <summary>A Signal Double Ratchet session for a single remote device JID.</summary>
public sealed class SignalSession
{
    public string RemoteJid { get; set; } = "";
    public byte[] RootKey { get; set; } = [];
    public byte[] SendChainKey { get; set; } = [];
    public byte[] ReceiveChainKey { get; set; } = [];
    public uint SendCounter { get; set; }
    public uint ReceiveCounter { get; set; }
    public uint PrevSendCounter { get; set; }
    public byte[] TheirCurrentRatchetPublic { get; set; } = [];
    public byte[] OurRatchetPrivate { get; set; } = [];
    public byte[] OurRatchetPublic { get; set; } = [];

    /// <summary>Their identity public key (raw 32 bytes, no 0x05 prefix).</summary>
    public byte[] TheirIdentityPublic { get; set; } = [];

    /// <summary>X3DH ephemeral public key — sent in the PreKeyWhisperMessage header.</summary>
    public byte[] BaseKey { get; set; } = [];

    /// <summary>Their one-time pre-key ID used during X3DH (0 = none).</summary>
    public uint PreKeyId { get; set; }

    /// <summary>Their signed pre-key ID used during X3DH.</summary>
    public uint SignedPreKeyId { get; set; }

    /// <summary>Their registration ID.</summary>
    public uint PeerRegistrationId { get; set; }

    /// <summary>
    /// False when session was just initialized and the first outgoing message
    /// must be wrapped in a PreKeyWhisperMessage. Set to true after first send.
    /// </summary>
    public bool IsEstablished { get; set; }
}

// ─── PreKeyBundle ─────────────────────────────────────────────────────────────

/// <summary>Pre-key bundle fetched from the server for a remote device.</summary>
public sealed class PreKeyBundle
{
    public byte[] TheirIdentityPub { get; set; } = [];
    public byte[] TheirSignedPreKeyPub { get; set; } = [];
    public uint TheirSignedPreKeyId { get; set; }
    public byte[] TheirSignedPreKeySig { get; set; } = [];
    public byte[]? TheirOneTimePreKeyPub { get; set; }
    public uint TheirOneTimePreKeyId { get; set; }
    public uint PeerRegistrationId { get; set; }
}
