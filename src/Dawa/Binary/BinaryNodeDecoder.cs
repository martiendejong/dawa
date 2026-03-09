using System.Text;

namespace Dawa.Binary;

/// <summary>
/// Decodes WhatsApp binary-encoded nodes from byte arrays.
/// </summary>
public static class BinaryNodeDecoder
{
    public static BinaryNode Decode(byte[] data)
    {
        var reader = new BinaryReader(data);
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

    private static string ReadString(ref BinaryReader reader)
    {
        var b = reader.ReadByte();

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
                return $"{user}@{server}";
            }
            case WATags.Nibble8:
            {
                var size = reader.ReadByte();
                var negative = (size & 0x80) != 0;
                size &= 0x7F;
                var sb = new StringBuilder();
                for (int i = 0; i < size; i++)
                {
                    var nibbleByte = reader.ReadByte();
                    var hi = (nibbleByte >> 4) & 0xF;
                    var lo = nibbleByte & 0xF;
                    sb.Append(DecodeNibble(hi));
                    if (!(negative && i == size - 1 && lo == 15))
                        sb.Append(DecodeNibble(lo));
                }
                return sb.ToString();
            }
            case WATags.Hex8:
            {
                var size = reader.ReadByte();
                var negative = (size & 0x80) != 0;
                size &= 0x7F;
                var sb = new StringBuilder();
                for (int i = 0; i < size; i++)
                {
                    var hexByte = reader.ReadByte();
                    var hi = (hexByte >> 4) & 0xF;
                    var lo = hexByte & 0xF;
                    sb.Append(DecodeHexNibble(hi));
                    if (!(negative && i == size - 1 && lo == 15))
                        sb.Append(DecodeHexNibble(lo));
                }
                return sb.ToString();
            }
            default:
                throw new InvalidDataException($"Unexpected string tag: {b:X2}");
        }
    }

    private static char DecodeNibble(int n) => n switch
    {
        <= 9 => (char)('0' + n),
        10 => '-',
        11 => '.',
        12 => '\0',
        13 => '\0',
        14 => '\0',
        15 => '\0',
        _ => (char)n
    };

    private static char DecodeHexNibble(int n) =>
        n < 10 ? (char)('0' + n) : (char)('A' + n - 10);
}

/// <summary>Simple forward-only reader over a byte array.</summary>
internal ref struct BinaryReader
{
    private readonly byte[] _data;
    private int _pos;

    public BinaryReader(byte[] data) { _data = data; _pos = 0; }
    public int Position => _pos;
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
