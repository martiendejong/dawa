using Dawa.Proto;

namespace Dawa.Signal;

/// <summary>
/// WhisperMessage proto (inner encrypted message).
/// field 1: ratchetKey (bytes) - sender's current ratchet public key (32 bytes)
/// field 2: counter (uint32) - message counter Ns
/// field 3: previousCounter (uint32) - PN (messages sent in previous sending chain)
/// field 4: ciphertext (bytes) - AES-CBC encrypted plaintext
/// </summary>
public sealed class WhisperMessageProto
{
    public byte[] RatchetKey { get; set; } = [];
    public uint Counter { get; set; }
    public uint PreviousCounter { get; set; }
    public byte[] Ciphertext { get; set; } = [];

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteBytes(buf, 1, RatchetKey);
        // Always write Counter and PreviousCounter even when 0 — Baileys' protobuf.js
        // includes them explicitly, and some Signal implementations require their presence.
        WriteUInt32Always(buf, 2, Counter);
        WriteUInt32Always(buf, 3, PreviousCounter);
        ProtoEncoder.WriteBytes(buf, 4, Ciphertext);
        return [.. buf];
    }

    private static void WriteUInt32Always(List<byte> buf, int field, uint value)
    {
        ProtoEncoder.WriteTag(buf, field, 0);
        ProtoEncoder.WriteVarint(buf, value);
    }

    public static WhisperMessageProto ParseFrom(byte[] data)
    {
        var msg = new WhisperMessageProto();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.RatchetKey      = r.ReadBytes(); break;
                case 2: msg.Counter         = r.ReadUInt32(); break;
                case 3: msg.PreviousCounter = r.ReadUInt32(); break;
                case 4: msg.Ciphertext      = r.ReadBytes(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>
/// PreKeyWhisperMessage proto (outer message for first contact).
/// field 1: preKeyId (uint32) - one-time pre-key ID (0 if not used)
/// field 2: baseKey (bytes) - X3DH ephemeral public key (32 bytes)
/// field 3: identityKey (bytes) - sender's identity public key (32 bytes)
/// field 4: message (bytes) - complete WhisperMessage bytes (version + proto + mac)
/// field 5: registrationId (uint32) - sender's registration ID
/// field 6: signedPreKeyId (uint32) - signed pre-key ID
/// </summary>
public sealed class PreKeyWhisperMessageProto
{
    public uint PreKeyId { get; set; }           // 0 = no one-time pre-key
    public byte[] BaseKey { get; set; } = [];    // X3DH ephemeral pub (32 bytes)
    public byte[] IdentityKey { get; set; } = []; // identity pub (32 bytes)
    public byte[] Message { get; set; } = [];    // embedded WhisperMessage bytes
    public uint RegistrationId { get; set; }
    public uint SignedPreKeyId { get; set; }

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteUInt32(buf, 1, PreKeyId);
        ProtoEncoder.WriteBytes(buf, 2, BaseKey);
        ProtoEncoder.WriteBytes(buf, 3, IdentityKey);
        ProtoEncoder.WriteBytes(buf, 4, Message);
        ProtoEncoder.WriteUInt32(buf, 5, RegistrationId);
        ProtoEncoder.WriteUInt32(buf, 6, SignedPreKeyId);
        return [.. buf];
    }

    public static PreKeyWhisperMessageProto ParseFrom(byte[] data)
    {
        var msg = new PreKeyWhisperMessageProto();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.PreKeyId       = r.ReadUInt32(); break;
                case 2: msg.BaseKey        = r.ReadBytes(); break;
                case 3: msg.IdentityKey    = r.ReadBytes(); break;
                case 4: msg.Message        = r.ReadBytes(); break;
                case 5: msg.RegistrationId = r.ReadUInt32(); break;
                case 6: msg.SignedPreKeyId = r.ReadUInt32(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}
