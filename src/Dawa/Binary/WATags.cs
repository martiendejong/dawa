namespace Dawa.Binary;

/// <summary>
/// WhatsApp binary encoding constants and dictionaries.
/// These tag bytes and string dictionaries are used to compress common strings.
/// </summary>
public static class WATags
{
    // Special byte tags
    public const byte ListEmpty = 0;
    public const byte StreamEnd = 2;
    public const byte DictionaryBase = 236;   // 0xEC  (DICTIONARY_0 through _3)
    public const byte List8 = 248;
    public const byte List16 = 249;
    public const byte JidPair = 250;
    public const byte Hex8 = 251;
    public const byte Binary8 = 252;
    public const byte Binary20 = 253;
    public const byte Binary32 = 254;
    public const byte Nibble8 = 255;

    // Dictionaries — ordered lists of common WhatsApp strings.
    // Index in array = compressed token byte (after base offset).
    public static readonly string[] Dictionary0 =
    [
        "xmlstreamstart", "account", "action", "add", "after", "age", "all", "allow",
        "apple", "audio", "auth", "author", "available", "bad-protocol", "bad-request",
        "before", "biz", "body", "broadcast", "cancel", "category", "challenge", "chat",
        "clean", "code", "composing", "config", "conflict", "contacts", "count", "create",
        "creation", "default", "delay", "delete", "delivery", "denied", "device", "devices",
        "digest", "dirty", "disable", "duplicate", "elapsed", "enable", "encoding", "error",
        "expiration", "expired", "failure", "false", "favorites", "feature", "features",
        "field", "filter", "format", "from", "full", "get", "group", "groups", "groups_v2",
        "hash", "id", "image", "in", "index", "info", "interactive", "iq", "item",
        "item-not-found", "items", "jid", "kind", "last", "latitude", "lc", "leave",
        "level", "list", "live", "lg", "longitude", "media", "message", "method",
        "mime-type", "missing", "modify", "name", "not-authorized", "notification",
        "notify", "out", "owner", "participant", "paused", "picture", "ping", "platform",
        "presence", "preview", "proceed", "prop", "properties", "protocol", "public",
        "push", "query", "raw", "read", "receipt", "received", "recipient", "recording",
        "relay", "remove", "request", "response", "result", "retry", "s.whatsapp.net",
        "seconds", "server", "server-error", "server_id", "set", "show", "sid",
        "signature", "size", "star", "state", "status", "stream:error", "stream:features",
        "subject", "success", "subscribe", "t", "text", "timeout", "to", "true", "type",
        "unarchive", "unavailable", "unsubscribe", "update", "uri", "user", "value",
        "vcard", "versions", "video", "w", "w:g2", "w:p", "w:p:r", "w:profile:picture",
        "xml", "xmlns", "xmlns:stream", "~"
    ];

    public static readonly string[] Dictionary1 =
    [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14",
        "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27",
        "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40",
        "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53",
        "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66",
        "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79",
        "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92",
        "93", "94", "95", "96", "97", "98", "99", "100", "101", "102", "103", "104",
        "105", "106", "107", "108", "109", "110", "111", "112", "113", "114", "115",
        "116", "117", "118", "119", "120", "121", "122", "123", "124", "125", "126",
        "127", "128", "129", "130", "131", "132", "133", "134", "135", "136", "137",
        "138", "139", "140", "141", "142", "143", "144", "145", "146", "147", "148",
        "149", "150", "151", "152", "153", "154", "155", "156", "157", "158", "159",
        "160", "161", "162", "163", "164", "165", "166", "167", "168", "169", "170",
        "171", "172", "173", "174", "175", "176", "177", "178", "179", "180", "181",
        "182", "183", "184", "185", "186", "187", "188", "189", "190", "191", "192",
        "193", "194", "195", "196", "197", "198", "199", "200", "201", "202", "203",
        "204", "205", "206", "207", "208", "209", "210", "211", "212", "213", "214",
        "215", "216", "217", "218", "219", "220", "221", "222", "223", "224", "225",
        "226", "227", "228", "229", "230", "231", "232", "233", "234", "235", "236",
        "237", "238", "239", "240", "241", "242", "243", "244", "245", "246", "247",
        "248", "249", "250", "251", "252", "253", "254", "255"
    ];

    public static readonly string[] Dictionary2 =
    [
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
        "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D",
        "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S",
        "T", "U", "V", "W", "X", "Y", "Z", "200", "201", "202", "203", "204", "205",
        "206", "207", "208", "209", "210", "211", "212", "213", "214", "215", "216",
        "217", "218", "219", "220", "221", "222", "223", "224", "225", "226", "227",
        "228", "229", "230", "231", "232", "233", "234", "235", "236", "237", "238",
        "239", "240", "241", "242", "243", "244", "245", "246", "247", "248", "249",
        "250", "251", "252", "253", "254", "255", "ac", "ae", "ag", "ah", "ai", "aj",
        "am", "an", "ao", "ap", "aq", "ar", "as", "at", "au", "av", "aw", "ax", "ay",
        "az", "ba", "bb", "bc", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bk", "bl",
        "bm", "bn", "bo", "bp", "bq", "br", "bs", "bt", "bu", "bv", "bw", "bx", "by",
        "bz", "ca", "cb", "cc", "cd", "ce", "cf", "cg", "ch", "ci", "cj", "ck", "cl",
        "cm", "cn", "co", "cp", "cq", "cr", "cs", "ct", "cu", "cv", "cw", "cx", "cy",
        "cz", "da", "db", "dc", "dd", "de", "df", "dg", "dh", "di", "dj", "dk", "dl",
        "dm", "dn", "do", "dp", "dq", "dr", "ds", "dt", "du", "dv", "dw", "dx", "dy",
        "dz", "ea", "eb", "ec", "ed", "ee", "ef", "eg", "eh", "ei", "ej", "ek", "el",
        "em", "en", "eo", "ep", "eq", "er", "es", "et", "eu", "ev", "ew", "ex", "ey",
        "ez", "fa", "fb", "fc", "fd", "fe", "ff", "fg", "fh", "fi", "fj", "fk", "fl",
        "fm", "fn", "fo", "fp", "fq", "fr", "fs", "ft", "fu", "fv", "fw", "fx", "fy",
        "fz"
    ];

    public static readonly string[] Dictionary3 =
    [
        "aba", "aca", "aga", "aha", "aia", "aja", "aka", "ala", "ama", "ana", "aoa",
        "apa", "aqa", "ara", "asa", "ata", "aua", "ava", "awa", "axa", "aya", "aza",
        "bba", "bca", "bda", "bea", "bfa", "bga", "bha", "bia", "bja", "bka", "bla",
        "bma", "bna", "boa", "bpa", "bqa", "bra", "bsa", "bta", "bua", "bva", "bwa",
        "bxa", "bya", "bza", "cca", "cda", "cea", "cfa", "cga", "cha", "cia", "cja",
        "cka", "cla", "cma", "cna", "coa", "cpa", "cqa", "cra", "csa", "cta", "cua",
        "cva", "cwa", "cxa", "cya", "cza", "dda", "dea", "dfa", "dga", "dha", "dia",
        "dja", "dka", "dla", "dma", "dna", "doa", "dpa", "dqa", "dra", "dsa", "dta",
        "dua", "dva", "dwa", "dxa", "dya", "dza", "eea", "efa", "ega", "eha", "eia",
        "eja", "eka", "ela", "ema", "ena", "eoa", "epa", "eqa", "era", "esa", "eta",
        "eua", "eva", "ewa", "exa", "eya", "eza", "ffa", "fga", "fha", "fia", "fja",
        "fka", "fla", "fma", "fna", "foa", "fpa", "fqa", "fra", "fsa", "fta", "fua",
        "fva", "fwa", "fxa", "fya", "fza", "gga", "gha", "gia", "gja", "gka", "gla",
        "gma", "gna", "goa", "gpa", "gqa", "gra", "gsa", "gta", "gua", "gva", "gwa",
        "gxa", "gya", "gza", "hha", "hia", "hja", "hka", "hla", "hma", "hna", "hoa",
        "hpa", "hqa", "hra", "hsa", "hta", "hua", "hva", "hwa", "hxa", "hya", "hza",
        "iia", "ija", "ika", "ila", "ima", "ina", "ioa", "ipa", "iqa", "ira", "isa",
        "ita", "iua", "iva", "iwa", "ixa", "iya", "iza", "jja", "jka", "jla", "jma",
        "jna", "joa", "jpa", "jqa", "jra", "jsa", "jta", "jua", "jva", "jwa", "jxa",
        "jya", "jza", "kka", "kla", "kma", "kna", "koa", "kpa", "kqa", "kra", "ksa",
        "kta", "kua", "kva", "kwa", "kxa", "kya", "kza", "lla", "lma", "lna", "loa",
        "lpa", "lqa", "lra", "lsa", "lta", "lua", "lva", "lwa", "lxa", "lya", "lza"
    ];

    public static readonly string[][] AllDictionaries = [Dictionary0, Dictionary1, Dictionary2, Dictionary3];

    // Build reverse lookup for encoding
    private static readonly Dictionary<string, (int dict, int idx)> _reverseMap = BuildReverseMap();

    private static Dictionary<string, (int dict, int idx)> BuildReverseMap()
    {
        var map = new Dictionary<string, (int, int)>();
        for (int d = 0; d < AllDictionaries.Length; d++)
            for (int i = 0; i < AllDictionaries[d].Length; i++)
                map.TryAdd(AllDictionaries[d][i], (d, i));
        return map;
    }

    public static bool TryGetToken(string value, out byte dictionaryByte, out byte indexByte)
    {
        if (_reverseMap.TryGetValue(value, out var pos))
        {
            dictionaryByte = (byte)(DictionaryBase + pos.dict);
            indexByte = (byte)pos.idx;
            return true;
        }
        dictionaryByte = 0;
        indexByte = 0;
        return false;
    }

    public static string? GetToken(int dictionaryIndex, int tokenIndex)
    {
        if (dictionaryIndex < 0 || dictionaryIndex >= AllDictionaries.Length) return null;
        var dict = AllDictionaries[dictionaryIndex];
        if (tokenIndex < 0 || tokenIndex >= dict.Length) return null;
        return dict[tokenIndex];
    }
}
