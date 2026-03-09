using System.Text;

namespace Dawa.Proto;

/// <summary>
/// Minimal proto3 encoder/decoder for WhatsApp messages.
/// Avoids the complexity of implementing IBufferMessage/IMessage directly.
/// </summary>
public static class ProtoEncoder
{
    // ─── Encoding ────────────────────────────────────────────────────────────

    public static void WriteTag(List<byte> buf, int fieldNumber, int wireType)
    {
        WriteVarint(buf, (uint)((fieldNumber << 3) | wireType));
    }

    public static void WriteVarint(List<byte> buf, ulong value)
    {
        while (value > 0x7F)
        {
            buf.Add((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }
        buf.Add((byte)value);
    }

    public static void WriteBytes(List<byte> buf, int field, byte[] data)
    {
        if (data.Length == 0) return;
        WriteTag(buf, field, 2);       // wire type 2 = length-delimited
        WriteVarint(buf, (ulong)data.Length);
        buf.AddRange(data);
    }

    public static void WriteString(List<byte> buf, int field, string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        WriteBytes(buf, field, Encoding.UTF8.GetBytes(value));
    }

    public static void WriteBool(List<byte> buf, int field, bool value)
    {
        if (!value) return;
        WriteTag(buf, field, 0);
        buf.Add(1);
    }

    public static void WriteInt32(List<byte> buf, int field, int value)
    {
        if (value == 0) return;
        WriteTag(buf, field, 0);
        WriteVarint(buf, (ulong)(uint)value);
    }

    public static void WriteUInt32(List<byte> buf, int field, uint value)
    {
        if (value == 0) return;
        WriteTag(buf, field, 0);
        WriteVarint(buf, value);
    }

    public static void WriteUInt64(List<byte> buf, int field, ulong value)
    {
        if (value == 0) return;
        WriteTag(buf, field, 0);
        WriteVarint(buf, value);
    }

    public static void WriteMessage(List<byte> buf, int field, byte[] serialized)
    {
        if (serialized.Length == 0) return;
        WriteTag(buf, field, 2);
        WriteVarint(buf, (ulong)serialized.Length);
        buf.AddRange(serialized);
    }

    // ─── Decoding ────────────────────────────────────────────────────────────

    public static ProtoReader CreateReader(byte[] data) => new(data);
}

public ref struct ProtoReader
{
    private readonly byte[] _data;
    private int _pos;

    public ProtoReader(byte[] data) { _data = data; _pos = 0; }
    public bool HasMore => _pos < _data.Length;

    public (int field, int wireType) ReadTag()
    {
        var raw = (int)ReadVarint();
        return (raw >> 3, raw & 0x7);
    }

    public ulong ReadVarint()
    {
        ulong result = 0;
        int shift = 0;
        while (true)
        {
            var b = _data[_pos++];
            result |= ((ulong)(b & 0x7F)) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        return result;
    }

    public byte[] ReadBytes()
    {
        var len = (int)ReadVarint();
        var data = _data[_pos..(_pos + len)];
        _pos += len;
        return data;
    }

    public string ReadString() => Encoding.UTF8.GetString(ReadBytes());

    public bool ReadBool() => ReadVarint() != 0;
    public int ReadInt32() => (int)ReadVarint();
    public uint ReadUInt32() => (uint)ReadVarint();
    public ulong ReadUInt64() => ReadVarint();

    public void Skip(int wireType)
    {
        switch (wireType)
        {
            case 0: ReadVarint(); break;
            case 1: _pos += 8; break;
            case 2: _pos += (int)ReadVarint(); break;
            case 5: _pos += 4; break;
        }
    }
}
