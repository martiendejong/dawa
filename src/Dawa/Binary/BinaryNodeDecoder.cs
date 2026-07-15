using System.IO.Compression;
using System.Text;

namespace Dawa.Binary;

/// <summary>
/// Decodes WhatsApp binary-encoded nodes from byte arrays.
/// </summary>
public static class BinaryNodeDecoder
{
    public static BinaryNode Decode(byte[] data)
    {
        // WhatsApp frames a binary node as [1 flag byte][node bytes]. The flag's bit 1
        // (0x02) means the node bytes are zlib-compressed. Matches Baileys
        // decompressingIfRequired: always strip byte 0, inflate the rest when 2 & flag.
        // Without this the flag byte (typically 0x00) is read as part of the node and the
        // decoder desyncs one byte in, later throwing "Unexpected string tag" (869e51uxu).
        if (data.Length == 0)
            throw new InvalidDataException("Empty binary frame.");

        byte[] body;
        if ((data[0] & 0x02) != 0)
        {
            using var input = new MemoryStream(data, 1, data.Length - 1);
            using var zlib = new ZLibStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            zlib.CopyTo(output);
            body = output.ToArray();
        }
        else
        {
            body = data[1..];
        }

        var reader = new BinaryReader(body);
        return ReadNode(ref reader);
    }

    private static BinaryNode ReadNode(ref BinaryReader reader)
    {
        var listSize = ReadListSize(ref reader);
        var tag = ReadString(ref reader);

        if (listSize == 0 || string.IsNullOrEmpty(tag))
            throw new InvalidDataException("Invalid binary node: empty list or tag.");

        var attrs = new Dictionary<string, string>();
        var attrCount = (listSize - 1) >> 1;
        for (int i = 0; i < attrCount; i++)
        {
            var key = ReadString(ref reader);
            var val = ReadString(ref reader);
            attrs[key] = val;
        }

        object? content = null;
        if (listSize % 2 == 0)
        {
            // Has content
            var b = reader.PeekByte();
            if (b is WATags.List8 or WATags.List16 or WATags.ListEmpty)
            {
                // Child nodes
                content = ReadNodes(ref reader);
            }
            else if (b == WATags.Binary8 || b == WATags.Binary20 || b == WATags.Binary32)
            {
                content = ReadBinary(ref reader);
            }
            else
            {
                content = ReadString(ref reader);
            }
        }

        return new BinaryNode(tag, attrs, content);
    }

    private static List<BinaryNode> ReadNodes(ref BinaryReader reader)
    {
        var size = ReadListSize(ref reader);
        var nodes = new List<BinaryNode>(size);
        for (int i = 0; i < size; i++)
            nodes.Add(ReadNode(ref reader));
        return nodes;
    }

    private static int ReadListSize(ref BinaryReader reader)
    {
        var b = reader.ReadByte();
        return b switch
        {
            WATags.ListEmpty => 0,
            WATags.List8 => reader.ReadByte(),
            WATags.List16 => reader.ReadUInt16BE(),
            _ => throw new InvalidDataException($"Unexpected list tag: {b:X2}")
        };
    }

    private static byte[] ReadBinary(ref BinaryReader reader)
    {
        var tag = reader.ReadByte();
        int length = tag switch
        {
            WATags.Binary8 => reader.ReadByte(),
            WATags.Binary20 => ((reader.ReadByte() & 0x0F) << 16) | (reader.ReadByte() << 8) | reader.ReadByte(),
            WATags.Binary32 => (int)reader.ReadUInt32BE(),
            _ => throw new InvalidDataException($"Unexpected binary tag: {tag:X2}")
        };
        return reader.ReadBytes(length);
    }

    // WAJIDDomains (Baileys jid-utils)
    private const int DomainLid = 1, DomainHosted = 128, DomainHostedLid = 129;

    private static string ReadString(ref BinaryReader reader)
    {
        var b = reader.ReadByte();

        // Bare single-byte token (Baileys: tag in [1, SINGLE_BYTE_TOKENS.length)).
        var single = WATags.GetSingleByteToken(b);
        if (single != null)
            return single;

        if (b >= WATags.DictionaryBase && b <= WATags.DictionaryBase + 3)
        {
            int dictIndex = b - WATags.DictionaryBase;
            int tokenIndex = reader.ReadByte();
            return WATags.GetToken(dictIndex, tokenIndex) ?? $"[DICT{dictIndex}:{tokenIndex}]";
        }

        switch (b)
        {
            case WATags.ListEmpty:
                return "";
            case WATags.Binary8:
            {
                var len = reader.ReadByte();
                return Encoding.UTF8.GetString(reader.ReadBytes(len));
            }
            case WATags.Binary20:
            {
                var len = ((reader.ReadByte() & 0x0F) << 16) | (reader.ReadByte() << 8) | reader.ReadByte();
                return Encoding.UTF8.GetString(reader.ReadBytes(len));
            }
            case WATags.Binary32:
            {
                var len = (int)reader.ReadUInt32BE();
                return Encoding.UTF8.GetString(reader.ReadBytes(len));
            }
            case WATags.JidPair:
            {
                var user = ReadString(ref reader);
                var server = ReadString(ref reader);
                if (string.IsNullOrEmpty(server))
                    throw new InvalidDataException("invalid jid pair");
                return $"{user}@{server}";
            }
            case WATags.AdJid:
            {
                var domainType = reader.ReadByte();
                var device = reader.ReadByte();
                var user = ReadString(ref reader);
                var server = domainType switch
                {
                    DomainLid => "lid",
                    DomainHosted => "hosted",
                    DomainHostedLid => "hosted.lid",
                    _ => "s.whatsapp.net",
                };
                return JidEncode(user, server, device);
            }
            case WATags.FbJid:
            {
                var user = ReadString(ref reader);
                var device = reader.ReadUInt16BE();
                var server = ReadString(ref reader);
                return $"{user}:{device}@{server}";
            }
            case WATags.InteropJid:
            {
                var user = ReadString(ref reader);
                var device = reader.ReadUInt16BE();
                var integrator = reader.ReadUInt16BE();
                var server = "interop";
                var before = reader.Position;
                try { server = ReadString(ref reader); }
                catch { reader.Position = before; }
                return $"{integrator}-{user}:{device}@{server}";
            }
            case WATags.Nibble8:
                return ReadPacked8(ref reader, WATags.Nibble8);
            case WATags.Hex8:
                return ReadPacked8(ref reader, WATags.Hex8);
            default:
                throw new InvalidDataException($"Unexpected string tag: {b:X2}");
        }
    }

    // Baileys readPacked8: append both nibbles per byte, then drop the last char when
    // the length byte's high bit is set (odd-length marker).
    private static string ReadPacked8(ref BinaryReader reader, byte tag)
    {
        var startByte = reader.ReadByte();
        var count = startByte & 0x7F;
        var sb = new StringBuilder(count * 2);
        for (int i = 0; i < count; i++)
        {
            var cur = reader.ReadByte();
            sb.Append(UnpackByte(tag, (cur & 0xF0) >> 4));
            sb.Append(UnpackByte(tag, cur & 0x0F));
        }
        if ((startByte >> 7) != 0 && sb.Length > 0)
            sb.Length -= 1;
        return sb.ToString();
    }

    private static char UnpackByte(byte tag, int v) =>
        tag == WATags.Nibble8 ? UnpackNibble(v) : UnpackHex(v);

    private static char UnpackNibble(int v) => v switch
    {
        >= 0 and <= 9 => (char)('0' + v),
        10 => '-',
        11 => '.',
        15 => '\0',
        _ => throw new InvalidDataException($"invalid nibble: {v}"),
    };

    private static char UnpackHex(int v) => v switch
    {
        >= 0 and <= 9 => (char)('0' + v),
        >= 10 and <= 15 => (char)('A' + v - 10),
        _ => throw new InvalidDataException($"invalid hex: {v}"),
    };

    private static string JidEncode(string? user, string server, int device) =>
        $"{user ?? ""}{(device != 0 ? $":{device}" : "")}@{server}";
}

/// <summary>Simple forward-only reader over a byte array.</summary>
internal ref struct BinaryReader
{
    private readonly byte[] _data;
    private int _pos;

    public BinaryReader(byte[] data) { _data = data; _pos = 0; }
    public int Position { readonly get => _pos; set => _pos = value; }
    public bool HasMore => _pos < _data.Length;

    public byte ReadByte() => _data[_pos++];
    public byte PeekByte() => _data[_pos];

    public byte[] ReadBytes(int count)
    {
        var slice = _data[_pos..(_pos + count)];
        _pos += count;
        return slice;
    }

    public int ReadUInt16BE()
    {
        int val = (_data[_pos] << 8) | _data[_pos + 1];
        _pos += 2;
        return val;
    }

    public uint ReadUInt32BE()
    {
        uint val = ((uint)_data[_pos] << 24) | ((uint)_data[_pos + 1] << 16)
                 | ((uint)_data[_pos + 2] << 8) | _data[_pos + 3];
        _pos += 4;
        return val;
    }
}
