namespace Dawa.Proto;

// ─────────────────────────────────────────────────────────────
// Hand-crafted proto3 for WhatsApp message types.
// Field numbers verified against WAProto.proto from Baileys.
// ─────────────────────────────────────────────────────────────

public sealed class ClientPayload
{
    public ulong  Username      { get; set; }
    public bool   Passive       { get; set; }
    public UserAgent? UserAgent { get; set; }
    public WebInfo?   WebInfo   { get; set; }
    // ConnectType enum: WIFI_UNKNOWN=1
    public int    ConnectType   { get; set; } = 1;
    // ConnectReason enum: USER_ACTIVATED=1
    public int    ConnectReason { get; set; } = 1;
    public uint   Device        { get; set; }
    public DevicePairingRegistrationData? DevicePairingData { get; set; }
    public bool   Pull          { get; set; }

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        if (Username != 0)     ProtoEncoder.WriteUInt64(buf, 1, Username);
                               ProtoEncoder.WriteBoolAlways(buf, 3, Passive);       // always emit (Baileys emits false)
        if (UserAgent != null) ProtoEncoder.WriteMessage(buf, 5, UserAgent.ToByteArray());
        if (WebInfo   != null) ProtoEncoder.WriteMessageAlways(buf, 6, WebInfo.ToByteArray()); // always emit, even when 0-value
                               ProtoEncoder.WriteInt32(buf, 12, ConnectType);
                               ProtoEncoder.WriteInt32(buf, 13, ConnectReason);
        if (Device != 0)       ProtoEncoder.WriteUInt32(buf, 18, Device);
        if (DevicePairingData != null) ProtoEncoder.WriteMessage(buf, 19, DevicePairingData.ToByteArray());
                               ProtoEncoder.WriteBoolAlways(buf, 33, Pull);         // always emit (Baileys emits false)
        return [.. buf];
    }
}

public sealed class DevicePairingRegistrationData
{
    public byte[] ERegid   { get; set; } = [];
    public byte[] EKeytype { get; set; } = [];
    public byte[] EIdent   { get; set; } = [];
    public byte[] ESkeyId  { get; set; } = [];
    public byte[] ESkeyVal { get; set; } = [];
    public byte[] ESkeySig { get; set; } = [];
    public byte[] BuildHash   { get; set; } = [];
    public byte[] DeviceProps { get; set; } = [];

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteBytes(buf, 1, ERegid);
        ProtoEncoder.WriteBytes(buf, 2, EKeytype);
        ProtoEncoder.WriteBytes(buf, 3, EIdent);
        ProtoEncoder.WriteBytes(buf, 4, ESkeyId);
        ProtoEncoder.WriteBytes(buf, 5, ESkeyVal);
        ProtoEncoder.WriteBytes(buf, 6, ESkeySig);
        ProtoEncoder.WriteBytes(buf, 7, BuildHash);
        ProtoEncoder.WriteBytes(buf, 8, DeviceProps);
        return [.. buf];
    }
}

/// <summary>DeviceProps (companion registration info), field 8 of DevicePairingRegistrationData.</summary>
public sealed class DevicePropsMessage
{
    public string Os             { get; set; } = "Ubuntu";
    // Version = WA app version (Baileys sends [2, 3000, tertiary]), NOT the OS/browser version.
    public AppVersion? Version   { get; set; } = new AppVersion { Primary = 2, Secondary = 3000, Tertiary = 1035194821 };
    // PlatformType: CHROME=1
    public int PlatformType      { get; set; } = 1;
    // requireFullSync: true triggers the server to include history in initial sync (Baileys default: true)
    public bool RequireFullSync  { get; set; } = true;
    public HistorySyncConfigMessage? HistorySyncConfig { get; set; } = new();

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteString(buf, 1, Os);
        if (Version != null) ProtoEncoder.WriteMessage(buf, 2, Version.ToByteArray());
        ProtoEncoder.WriteInt32(buf, 3, PlatformType);
        ProtoEncoder.WriteBool(buf, 4, RequireFullSync);  // always emit — server expects it
        if (HistorySyncConfig != null) ProtoEncoder.WriteMessage(buf, 5, HistorySyncConfig.ToByteArray());
        return [.. buf];
    }
}

/// <summary>HistorySyncConfig nested in DeviceProps (field 5).</summary>
public sealed class HistorySyncConfigMessage
{
    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteUInt32(buf, 1, 3);        // fullSyncDaysLimit = 3  (Baileys: fullCount)
        ProtoEncoder.WriteUInt32(buf, 3, 2048);     // storageQuotaMb = 2048  (Baileys default)
        ProtoEncoder.WriteBool(buf, 4, true);        // inlineInitialPayloadInE2EeMsg
        ProtoEncoder.WriteUInt32(buf, 5, 25);        // recentSyncChunkSize = 25  (Baileys: count)
        // field 6: supportCallLogHistory = false — omit
        ProtoEncoder.WriteBool(buf, 7, true);        // supportBotUserAgentChatHistory
        ProtoEncoder.WriteBool(buf, 8, true);        // supportCagReactionsAndPolls
        ProtoEncoder.WriteBool(buf, 9, true);        // supportBizHostedMsg
        ProtoEncoder.WriteBool(buf, 10, true);       // supportRecentSyncChunkMessageCountTuning
        ProtoEncoder.WriteBool(buf, 11, true);       // supportHostedGroupMsg
        ProtoEncoder.WriteBool(buf, 12, true);       // supportFbidBotChatHistory
        ProtoEncoder.WriteBool(buf, 14, true);       // supportMessageAssociation
        // field 15: supportGroupHistory = false — omit
        return [.. buf];
    }
}

public sealed class UserAgent
{
    // Platform: WEB=14
    public int        Platform                  { get; set; } = 14;
    public AppVersion? AppVersion               { get; set; }
    public string Mcc                           { get; set; } = "000";
    public string Mnc                           { get; set; } = "000";
    public string OsVersion                     { get; set; } = "0.1";
    public string Manufacturer                  { get; set; } = "";
    public string Device                        { get; set; } = "Desktop";
    public string OsBuildNumber                 { get; set; } = "0.1";
    // field 9 = phoneId (skip)
    // field 10 = releaseChannel (RELEASE=0, default, skip)
    public string LocaleLanguageIso6391         { get; set; } = "en";  // field 11
    public string LocaleCountryIso31661Alpha2   { get; set; } = "US";  // field 12

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteInt32(buf, 1, Platform);
        if (AppVersion != null) ProtoEncoder.WriteMessage(buf, 2, AppVersion.ToByteArray());
        ProtoEncoder.WriteString(buf, 3, Mcc);
        ProtoEncoder.WriteString(buf, 4, Mnc);
        ProtoEncoder.WriteString(buf, 5, OsVersion);
        if (!string.IsNullOrEmpty(Manufacturer)) ProtoEncoder.WriteString(buf, 6, Manufacturer);
        ProtoEncoder.WriteString(buf, 7, Device);
        ProtoEncoder.WriteString(buf, 8, OsBuildNumber);
        // field 9 = phoneId (skip)
        ProtoEncoder.WriteInt32Always(buf, 10, 0); // releaseChannel = RELEASE(0), always emit (Baileys does)
        ProtoEncoder.WriteString(buf, 11, LocaleLanguageIso6391);
        ProtoEncoder.WriteString(buf, 12, LocaleCountryIso31661Alpha2);
        return [.. buf];
    }
}

public sealed class AppVersion
{
    public uint Primary   { get; set; } = 2;
    public uint Secondary { get; set; } = 3000;
    public uint Tertiary  { get; set; } = 1027934701;

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteUInt32(buf, 1, Primary);
        ProtoEncoder.WriteUInt32(buf, 2, Secondary);
        ProtoEncoder.WriteUInt32(buf, 3, Tertiary);
        return [.. buf];
    }
}

public sealed class WebInfo
{
    // WebSubPlatform: WEB_BROWSER=0
    public int WebSubPlatform { get; set; } = 0;

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteInt32Always(buf, 4, WebSubPlatform); // always emit 0 (Baileys does this)
        return [.. buf];
    }
}

// ─────────────────────────────────────────────────────────────
// ADV (Advanced Device Verification) protos used in QR pairing.
// Field numbers verified against WAProto.proto from Baileys.
// ─────────────────────────────────────────────────────────────

/// <summary>Server sends this in device-identity during pair-success. Contains HMAC-protected device identity.</summary>
public sealed class ADVSignedDeviceIdentityHMAC
{
    public byte[] Details     { get; set; } = [];  // field 1: encoded ADVSignedDeviceIdentity
    public byte[] Hmac        { get; set; } = [];  // field 2: HMAC-SHA256 over details
    public int    AccountType { get; set; } = 0;   // field 3: 0=E2EE, 1=HOSTED

    public static ADVSignedDeviceIdentityHMAC ParseFrom(byte[] data)
    {
        var msg = new ADVSignedDeviceIdentityHMAC();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.Details     = r.ReadBytes(); break;
                case 2: msg.Hmac        = r.ReadBytes(); break;
                case 3: msg.AccountType = r.ReadInt32(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Decoded from ADVSignedDeviceIdentityHMAC.Details. Client adds deviceSignature and re-encodes.</summary>
public sealed class ADVSignedDeviceIdentity
{
    public byte[] Details             { get; set; } = [];  // field 1: encoded ADVDeviceIdentity
    public byte[] AccountSignatureKey { get; set; } = [];  // field 2: phone's Curve25519 public key
    public byte[] AccountSignature    { get; set; } = [];  // field 3: phone's XEdDSA signature
    public byte[] DeviceSignature     { get; set; } = [];  // field 4: client fills this in

    public static ADVSignedDeviceIdentity ParseFrom(byte[] data)
    {
        var msg = new ADVSignedDeviceIdentity();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.Details             = r.ReadBytes(); break;
                case 2: msg.AccountSignatureKey = r.ReadBytes(); break;
                case 3: msg.AccountSignature    = r.ReadBytes(); break;
                case 4: msg.DeviceSignature     = r.ReadBytes(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }

    /// <summary>Encode all fields including accountSignatureKey (for device-identity in outgoing pkmsg).</summary>
    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteBytes(buf, 1, Details);
        if (AccountSignatureKey.Length > 0) ProtoEncoder.WriteBytes(buf, 2, AccountSignatureKey);
        ProtoEncoder.WriteBytes(buf, 3, AccountSignature);
        ProtoEncoder.WriteBytes(buf, 4, DeviceSignature);
        return [.. buf];
    }

    /// <summary>Encode WITHOUT accountSignatureKey (field 2 omitted per Baileys protocol).</summary>
    public byte[] ToByteArrayForReply()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteBytes(buf, 1, Details);
        // field 2 (accountSignatureKey) intentionally omitted in reply
        ProtoEncoder.WriteBytes(buf, 3, AccountSignature);
        ProtoEncoder.WriteBytes(buf, 4, DeviceSignature);
        return [.. buf];
    }
}

/// <summary>Decoded from ADVSignedDeviceIdentity.Details. Used to get keyIndex for the reply.</summary>
public sealed class ADVDeviceIdentity
{
    public uint   RawId       { get; set; }  // field 1
    public ulong  Timestamp   { get; set; }  // field 2
    public uint   KeyIndex    { get; set; }  // field 3
    public int    AccountType { get; set; }  // field 4
    public int    DeviceType  { get; set; }  // field 5

    public static ADVDeviceIdentity ParseFrom(byte[] data)
    {
        var msg = new ADVDeviceIdentity();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.RawId       = r.ReadUInt32(); break;
                case 2: msg.Timestamp   = r.ReadUInt64(); break;
                case 3: msg.KeyIndex    = r.ReadUInt32(); break;
                case 4: msg.AccountType = r.ReadInt32();  break;
                case 5: msg.DeviceType  = r.ReadInt32();  break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>
/// WhatsApp Message proto (field numbers from Baileys WAProto.proto).
/// Only the fields we need for text message extraction are implemented;
/// all others are safely skipped.
/// </summary>
public sealed class WAMessage
{
    public string? Conversation { get; set; }                        // field 1
    public SenderKeyDistributionMessage? SenderKeyDist { get; set; } // field 2
    public ImageMessage? ImageMessage { get; set; }                  // field 3
    public AudioMessage? AudioMessage { get; set; }                  // field 4
    public ExtendedTextMessage? ExtendedTextMessage { get; set; }    // field 6
    public VideoMessage? VideoMessage { get; set; }                  // field 5
    public StickerMessage? StickerMessage { get; set; }              // field 50
    public ProtocolMessage? ProtocolMsg { get; set; }                // field 12
    public DocumentMessage? DocumentMessage { get; set; }               // field 15
    public DeviceSentMessage? DeviceSentMessage { get; set; }           // field 31
    public MessageContextInfo? MessageContextInfo { get; set; }         // field 35
    public HistorySyncNotification? HistorySyncNotification { get; set; } // field 46
    public ReactionMessage? ReactionMessage { get; set; }               // field 85
    public PeerDataOperationRequestMessage?  PeerDataOperation { get; set; } // field 145
    public PeerDataOperationResponseMessage? PeerDataResponse  { get; set; } // field 146

    /// <summary>Extracts the text from whatever message type this is.</summary>
    public string? GetText()
    {
        if (!string.IsNullOrEmpty(Conversation))
            return Conversation;
        if (ExtendedTextMessage != null && !string.IsNullOrEmpty(ExtendedTextMessage.Text))
            return ExtendedTextMessage.Text;
        if (DeviceSentMessage?.Message != null)
            return DeviceSentMessage.Message.GetText();
        // Caption from media messages
        if (ImageMessage    != null && !string.IsNullOrEmpty(ImageMessage.Caption))    return ImageMessage.Caption;
        if (VideoMessage    != null && !string.IsNullOrEmpty(VideoMessage.Caption))    return VideoMessage.Caption;
        if (DocumentMessage != null && !string.IsNullOrEmpty(DocumentMessage.Title)) return DocumentMessage.Title;
        return null;
    }

    /// <summary>Returns the MessageType enum value for this message.</summary>
    public Messages.MessageType GetMessageType()
    {
        if (DeviceSentMessage?.Message != null) return DeviceSentMessage.Message.GetMessageType();
        if (!string.IsNullOrEmpty(Conversation))    return Messages.MessageType.Text;
        if (ExtendedTextMessage != null)            return Messages.MessageType.Text;
        if (ImageMessage    != null)                return Messages.MessageType.Image;
        if (AudioMessage    != null)                return Messages.MessageType.Audio;
        if (VideoMessage    != null)                return Messages.MessageType.Video;
        if (DocumentMessage != null)                return Messages.MessageType.Document;
        if (StickerMessage  != null)                return Messages.MessageType.Sticker;
        if (ReactionMessage != null)                return Messages.MessageType.Reaction;
        if (ProtocolMsg     != null)                return Messages.MessageType.Protocol;
        return Messages.MessageType.Unknown;
    }

    /// <summary>Extracts all fields needed to populate an IncomingMessage from this WAMessage.</summary>
    public (Messages.MessageType type, string? text, string? mediaUrl, string? mimeType,
            string? fileName, long? fileSize, uint? duration, uint? width, uint? height,
            string? mediaKey, string? mediaSha256Enc, string? reactionEmoji, string? reactionTargetId)
        GetAllFields()
    {
        var inner = DeviceSentMessage?.Message;
        if (inner != null) return inner.GetAllFields();

        var type = GetMessageType();
        var text = GetText();

        if (ImageMessage != null)
            return (type, text ?? ImageMessage.Caption,
                mediaUrl:      ImageMessage.Url,
                mimeType:      ImageMessage.MimeType,
                fileName:      null,
                fileSize:      (long?)ImageMessage.FileLength,
                duration:      null,
                width:         ImageMessage.Width,
                height:        ImageMessage.Height,
                mediaKey:      Convert.ToBase64String(ImageMessage.MediaKey),
                mediaSha256Enc:Convert.ToBase64String(ImageMessage.FileEncSha256),
                null, null);

        if (AudioMessage != null)
            return (type, text,
                mediaUrl:      AudioMessage.Url,
                mimeType:      AudioMessage.MimeType,
                fileName:      null,
                fileSize:      (long?)AudioMessage.FileLength,
                duration:      AudioMessage.Seconds,
                width:         null,
                height:        null,
                mediaKey:      Convert.ToBase64String(AudioMessage.MediaKey),
                mediaSha256Enc:Convert.ToBase64String(AudioMessage.FileEncSha256),
                null, null);

        if (VideoMessage != null)
            return (type, text,
                mediaUrl:      VideoMessage.Url,
                mimeType:      VideoMessage.MimeType,
                fileName:      null,
                fileSize:      (long?)VideoMessage.FileLength,
                duration:      VideoMessage.Seconds,
                width:         VideoMessage.Width,
                height:        VideoMessage.Height,
                mediaKey:      Convert.ToBase64String(VideoMessage.MediaKey),
                mediaSha256Enc:Convert.ToBase64String(VideoMessage.FileEncSha256),
                null, null);

        if (DocumentMessage != null)
            return (type, text,
                mediaUrl:      DocumentMessage.Url,
                mimeType:      DocumentMessage.MimeType,
                fileName:      DocumentMessage.FileName,
                fileSize:      (long?)DocumentMessage.FileLength,
                duration:      null,
                width:         null,
                height:        null,
                mediaKey:      Convert.ToBase64String(DocumentMessage.MediaKey),
                mediaSha256Enc:Convert.ToBase64String(DocumentMessage.FileEncSha256),
                null, null);

        if (StickerMessage != null)
            return (type, text,
                mediaUrl:      StickerMessage.Url,
                mimeType:      StickerMessage.MimeType,
                fileName:      null,
                fileSize:      (long?)StickerMessage.FileLength,
                duration:      null,
                width:         StickerMessage.Width,
                height:        StickerMessage.Height,
                mediaKey:      Convert.ToBase64String(StickerMessage.MediaKey),
                mediaSha256Enc:Convert.ToBase64String(StickerMessage.FileEncSha256),
                null, null);

        if (ReactionMessage != null)
            return (type, null, null, null, null, null, null, null, null, null, null,
                reactionEmoji:    ReactionMessage.Text,
                reactionTargetId: ReactionMessage.Key?.Id);

        return (type, text, null, null, null, null, null, null, null, null, null, null, null);
    }

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteString(buf, 1, Conversation);
        if (ImageMessage != null)    ProtoEncoder.WriteMessage(buf, 3,  ImageMessage.ToByteArray());
        if (AudioMessage != null)    ProtoEncoder.WriteMessage(buf, 4,  AudioMessage.ToByteArray());
        if (ExtendedTextMessage != null)
            ProtoEncoder.WriteMessage(buf, 6, ExtendedTextMessage.ToByteArray());
        if (DocumentMessage != null) ProtoEncoder.WriteMessage(buf, 15, DocumentMessage.ToByteArray());
        if (DeviceSentMessage != null)
            ProtoEncoder.WriteMessage(buf, 31, DeviceSentMessage.ToByteArray());
        return [.. buf];
    }

    public static WAMessage ParseFrom(byte[] data)
    {
        var msg = new WAMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1:  msg.Conversation = r.ReadString(); break;
                case 2:  msg.SenderKeyDist = SenderKeyDistributionMessage.ParseFrom(r.ReadBytes()); break;
                case 3:  msg.ImageMessage = ImageMessage.ParseFrom(r.ReadBytes()); break;
                case 4:  msg.AudioMessage = AudioMessage.ParseFrom(r.ReadBytes()); break;
                case 5:  msg.VideoMessage = VideoMessage.ParseFrom(r.ReadBytes()); break;
                case 6:  msg.ExtendedTextMessage = ExtendedTextMessage.ParseFrom(r.ReadBytes()); break;
                case 12: msg.ProtocolMsg = ProtocolMessage.ParseFrom(r.ReadBytes()); break;
                case 15: msg.DocumentMessage = DocumentMessage.ParseFrom(r.ReadBytes()); break;
                case 50: msg.StickerMessage = StickerMessage.ParseFrom(r.ReadBytes()); break;
                case 31: msg.DeviceSentMessage = DeviceSentMessage.ParseFrom(r.ReadBytes()); break;
                case 35: msg.MessageContextInfo = MessageContextInfo.ParseFrom(r.ReadBytes()); break;
                case 46:  msg.HistorySyncNotification = HistorySyncNotification.Decode(r.ReadBytes()); break;
                case 85:  msg.ReactionMessage = ReactionMessage.ParseFrom(r.ReadBytes()); break;
                case 145: msg.PeerDataOperation = null; r.Skip(wire); break; // outgoing only — skip
                case 146: msg.PeerDataResponse = PeerDataOperationResponseMessage.Decode(r.ReadBytes()); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }

    public byte[] ToByteArrayWithPeerDataOperation()
    {
        var buf = new List<byte>();
        if (PeerDataOperation != null)
            ProtoEncoder.WriteMessage(buf, 145, PeerDataOperation.ToByteArray());
        return [.. buf];
    }

    public byte[] ToByteArrayWithReaction()
    {
        var buf = new List<byte>();
        if (ReactionMessage != null)
            ProtoEncoder.WriteMessage(buf, 85, ReactionMessage.ToByteArray());
        return [.. buf];
    }

    public byte[] ToByteArrayWithRevoke()
    {
        var buf = new List<byte>();
        if (ProtocolMsg != null)
            ProtoEncoder.WriteMessage(buf, 12, ProtocolMsg.ToByteArray());
        return [.. buf];
    }

    /// <summary>
    /// Returns the ContextInfo (quoted message metadata) from whichever sub-message contains it.
    /// </summary>
    public ContextInfo? GetContextInfo()
    {
        var inner = DeviceSentMessage?.Message;
        if (inner != null) return inner.GetContextInfo();
        return ImageMessage?.ContextInfo
            ?? AudioMessage?.ContextInfo
            ?? VideoMessage?.ContextInfo
            ?? ExtendedTextMessage?.ContextInfo;
    }

    /// <summary>
    /// Returns quoted message context (id, sender, text preview, type) for reply display.
    /// </summary>
    public (string? quotedId, string? quotedFrom, string? quotedText, Messages.MessageType quotedType) GetQuotedContext()
    {
        var ctx = GetContextInfo();
        if (ctx == null || string.IsNullOrEmpty(ctx.StanzaId))
            return (null, null, null, Messages.MessageType.Unknown);

        var quotedText = ctx.QuotedMessage?.GetText();
        var quotedType = ctx.QuotedMessage?.GetMessageType() ?? Messages.MessageType.Unknown;
        return (ctx.StanzaId, ctx.Participant, quotedText, quotedType);
    }

    public byte[] ToByteArrayWithMedia()
    {
        var buf = new List<byte>();
        if (ImageMessage != null)    ProtoEncoder.WriteMessage(buf, 3,  ImageMessage.ToByteArray());
        if (AudioMessage != null)    ProtoEncoder.WriteMessage(buf, 4,  AudioMessage.ToByteArray());
        if (DocumentMessage != null) ProtoEncoder.WriteMessage(buf, 15, DocumentMessage.ToByteArray());
        return [.. buf];
    }
}

/// <summary>Field 6 of Message. Contains text with optional link preview etc.</summary>
public sealed class ExtendedTextMessage
{
    public string Text { get; set; } = "";          // field 1
    public ContextInfo? ContextInfo { get; set; }   // field 17

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteString(buf, 1, Text);
        if (ContextInfo != null) ProtoEncoder.WriteMessage(buf, 17, ContextInfo.ToByteArray());
        return [.. buf];
    }

    public static ExtendedTextMessage ParseFrom(byte[] data)
    {
        var msg = new ExtendedTextMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1:  msg.Text = r.ReadString(); break;
                case 17: msg.ContextInfo = ContextInfo.ParseFrom(r.ReadBytes()); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Field 3 of Message. An image with optional caption.</summary>
public sealed class ImageMessage
{
    public string Url { get; set; } = "";           // field 1
    public string MimeType { get; set; } = "";      // field 2
    public string Caption { get; set; } = "";       // field 3
    public byte[] FileSha256 { get; set; } = [];    // field 4
    public ulong FileLength { get; set; }            // field 5
    public uint Height { get; set; }                // field 6
    public uint Width { get; set; }                 // field 7
    public byte[] MediaKey { get; set; } = [];      // field 8
    public byte[] FileEncSha256 { get; set; } = []; // field 9
    public string DirectPath { get; set; } = "";    // field 11
    public long MediaKeyTimestamp { get; set; }      // field 12
    public byte[] JpegThumbnail { get; set; } = []; // field 16
    public ContextInfo? ContextInfo { get; set; }   // field 17
    public bool ViewOnce { get; set; }              // field 25

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteString(buf, 1, Url);
        ProtoEncoder.WriteString(buf, 2, MimeType);
        if (!string.IsNullOrEmpty(Caption)) ProtoEncoder.WriteString(buf, 3, Caption);
        if (FileSha256.Length > 0)    ProtoEncoder.WriteBytes(buf, 4, FileSha256);
        if (FileLength > 0)           ProtoEncoder.WriteUInt64(buf, 5, FileLength);
        if (Height > 0)               ProtoEncoder.WriteUInt32(buf, 6, Height);
        if (Width > 0)                ProtoEncoder.WriteUInt32(buf, 7, Width);
        if (MediaKey.Length > 0)      ProtoEncoder.WriteBytes(buf, 8, MediaKey);
        if (FileEncSha256.Length > 0) ProtoEncoder.WriteBytes(buf, 9, FileEncSha256);
        ProtoEncoder.WriteString(buf, 11, DirectPath);
        if (MediaKeyTimestamp != 0)   ProtoEncoder.WriteUInt64(buf, 12, (ulong)MediaKeyTimestamp);
        if (JpegThumbnail.Length > 0) ProtoEncoder.WriteBytes(buf, 16, JpegThumbnail);
        if (ContextInfo != null)      ProtoEncoder.WriteMessage(buf, 17, ContextInfo.ToByteArray());
        return [.. buf];
    }

    public static ImageMessage ParseFrom(byte[] data)
    {
        var msg = new ImageMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1:  msg.Url = r.ReadString(); break;
                case 2:  msg.MimeType = r.ReadString(); break;
                case 3:  msg.Caption = r.ReadString(); break;
                case 4:  msg.FileSha256 = r.ReadBytes(); break;
                case 5:  msg.FileLength = r.ReadUInt64(); break;
                case 6:  msg.Height = r.ReadUInt32(); break;
                case 7:  msg.Width = r.ReadUInt32(); break;
                case 8:  msg.MediaKey = r.ReadBytes(); break;
                case 9:  msg.FileEncSha256 = r.ReadBytes(); break;
                case 11: msg.DirectPath = r.ReadString(); break;
                case 12: msg.MediaKeyTimestamp = (long)r.ReadUInt64(); break;
                case 16: msg.JpegThumbnail = r.ReadBytes(); break;
                case 17: msg.ContextInfo = ContextInfo.ParseFrom(r.ReadBytes()); break;
                case 25: msg.ViewOnce = r.ReadUInt64() != 0; break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Field 4 of Message. An audio clip or voice note (ptt=true).</summary>
public sealed class AudioMessage
{
    public string Url { get; set; } = "";           // field 1
    public string MimeType { get; set; } = "";      // field 2
    public byte[] FileSha256 { get; set; } = [];    // field 3
    public ulong FileLength { get; set; }            // field 4
    public uint Seconds { get; set; }               // field 5 (duration)
    public bool Ptt { get; set; }                   // field 6 (push-to-talk = voice note)
    public byte[] MediaKey { get; set; } = [];      // field 7
    public byte[] FileEncSha256 { get; set; } = []; // field 8
    public string DirectPath { get; set; } = "";    // field 9
    public long MediaKeyTimestamp { get; set; }      // field 12
    public ContextInfo? ContextInfo { get; set; }   // field 17

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteString(buf, 1, Url);
        ProtoEncoder.WriteString(buf, 2, MimeType);
        if (FileSha256.Length > 0)    ProtoEncoder.WriteBytes(buf, 3, FileSha256);
        if (FileLength > 0)           ProtoEncoder.WriteUInt64(buf, 4, FileLength);
        if (Seconds > 0)              ProtoEncoder.WriteUInt32(buf, 5, Seconds);
        if (Ptt)                      ProtoEncoder.WriteBool(buf, 6, Ptt);
        if (MediaKey.Length > 0)      ProtoEncoder.WriteBytes(buf, 7, MediaKey);
        if (FileEncSha256.Length > 0) ProtoEncoder.WriteBytes(buf, 8, FileEncSha256);
        ProtoEncoder.WriteString(buf, 9, DirectPath);
        if (MediaKeyTimestamp != 0)   ProtoEncoder.WriteUInt64(buf, 12, (ulong)MediaKeyTimestamp);
        if (ContextInfo != null)      ProtoEncoder.WriteMessage(buf, 17, ContextInfo.ToByteArray());
        return [.. buf];
    }

    public static AudioMessage ParseFrom(byte[] data)
    {
        var msg = new AudioMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1:  msg.Url = r.ReadString(); break;
                case 2:  msg.MimeType = r.ReadString(); break;
                case 3:  msg.FileSha256 = r.ReadBytes(); break;
                case 4:  msg.FileLength = r.ReadUInt64(); break;
                case 5:  msg.Seconds = r.ReadUInt32(); break;
                case 6:  msg.Ptt = r.ReadBool(); break;
                case 7:  msg.MediaKey = r.ReadBytes(); break;
                case 8:  msg.FileEncSha256 = r.ReadBytes(); break;
                case 9:  msg.DirectPath = r.ReadString(); break;
                case 12: msg.MediaKeyTimestamp = (long)r.ReadUInt64(); break;
                case 17: msg.ContextInfo = ContextInfo.ParseFrom(r.ReadBytes()); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Field 5 of Message. A video with optional caption.</summary>
public sealed class VideoMessage
{
    public string Url { get; set; } = "";           // field 1
    public string MimeType { get; set; } = "";      // field 2
    public byte[] FileSha256 { get; set; } = [];    // field 3
    public ulong FileLength { get; set; }            // field 4
    public uint Seconds { get; set; }               // field 5
    public byte[] MediaKey { get; set; } = [];      // field 6
    public string Caption { get; set; } = "";       // field 7
    public bool GifPlayback { get; set; }           // field 8
    public uint Height { get; set; }                // field 9
    public uint Width { get; set; }                 // field 10
    public byte[] FileEncSha256 { get; set; } = []; // field 11
    public string DirectPath { get; set; } = "";    // field 13
    public long MediaKeyTimestamp { get; set; }      // field 14
    public ContextInfo? ContextInfo { get; set; }   // field 17

    public static VideoMessage ParseFrom(byte[] data)
    {
        var msg = new VideoMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1:  msg.Url = r.ReadString(); break;
                case 2:  msg.MimeType = r.ReadString(); break;
                case 3:  msg.FileSha256 = r.ReadBytes(); break;
                case 4:  msg.FileLength = r.ReadUInt64(); break;
                case 5:  msg.Seconds = r.ReadUInt32(); break;
                case 6:  msg.MediaKey = r.ReadBytes(); break;
                case 7:  msg.Caption = r.ReadString(); break;
                case 8:  msg.GifPlayback = r.ReadUInt64() != 0; break;
                case 9:  msg.Height = r.ReadUInt32(); break;
                case 10: msg.Width = r.ReadUInt32(); break;
                case 11: msg.FileEncSha256 = r.ReadBytes(); break;
                case 13: msg.DirectPath = r.ReadString(); break;
                case 14: msg.MediaKeyTimestamp = (long)r.ReadUInt64(); break;
                case 17: msg.ContextInfo = ContextInfo.ParseFrom(r.ReadBytes()); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Field 50 of Message. A sticker.</summary>
public sealed class StickerMessage
{
    public string Url { get; set; } = "";           // field 1
    public byte[] FileSha256 { get; set; } = [];    // field 2
    public byte[] FileEncSha256 { get; set; } = []; // field 3
    public byte[] MediaKey { get; set; } = [];      // field 4
    public string MimeType { get; set; } = "";      // field 5
    public uint Height { get; set; }                // field 6
    public uint Width { get; set; }                 // field 7
    public string DirectPath { get; set; } = "";    // field 8
    public ulong FileLength { get; set; }            // field 9
    public long MediaKeyTimestamp { get; set; }      // field 10
    public ContextInfo? ContextInfo { get; set; }   // field 17

    public static StickerMessage ParseFrom(byte[] data)
    {
        var msg = new StickerMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1:  msg.Url = r.ReadString(); break;
                case 2:  msg.FileSha256 = r.ReadBytes(); break;
                case 3:  msg.FileEncSha256 = r.ReadBytes(); break;
                case 4:  msg.MediaKey = r.ReadBytes(); break;
                case 5:  msg.MimeType = r.ReadString(); break;
                case 6:  msg.Height = r.ReadUInt32(); break;
                case 7:  msg.Width = r.ReadUInt32(); break;
                case 8:  msg.DirectPath = r.ReadString(); break;
                case 9:  msg.FileLength = r.ReadUInt64(); break;
                case 10: msg.MediaKeyTimestamp = (long)r.ReadUInt64(); break;
                case 17: msg.ContextInfo = ContextInfo.ParseFrom(r.ReadBytes()); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Field 15 of Message. A document/file attachment.</summary>
public sealed class DocumentMessage
{
    public string Url { get; set; } = "";           // field 1
    public string MimeType { get; set; } = "";      // field 2
    public string Title { get; set; } = "";         // field 3
    public byte[] FileSha256 { get; set; } = [];    // field 4
    public ulong FileLength { get; set; }            // field 5
    public byte[] MediaKey { get; set; } = [];      // field 7
    public string FileName { get; set; } = "";      // field 8
    public byte[] FileEncSha256 { get; set; } = []; // field 9
    public string DirectPath { get; set; } = "";    // field 10
    public long MediaKeyTimestamp { get; set; }      // field 11

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteString(buf, 1, Url);
        ProtoEncoder.WriteString(buf, 2, MimeType);
        ProtoEncoder.WriteString(buf, 3, Title);
        if (FileSha256.Length > 0)    ProtoEncoder.WriteBytes(buf, 4, FileSha256);
        if (FileLength > 0)           ProtoEncoder.WriteUInt64(buf, 5, FileLength);
        if (MediaKey.Length > 0)      ProtoEncoder.WriteBytes(buf, 7, MediaKey);
        ProtoEncoder.WriteString(buf, 8, FileName);
        if (FileEncSha256.Length > 0) ProtoEncoder.WriteBytes(buf, 9, FileEncSha256);
        ProtoEncoder.WriteString(buf, 10, DirectPath);
        if (MediaKeyTimestamp != 0)   ProtoEncoder.WriteUInt64(buf, 11, (ulong)MediaKeyTimestamp);
        return [.. buf];
    }

    public static DocumentMessage ParseFrom(byte[] data)
    {
        var msg = new DocumentMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1:  msg.Url = r.ReadString(); break;
                case 2:  msg.MimeType = r.ReadString(); break;
                case 3:  msg.Title = r.ReadString(); break;
                case 4:  msg.FileSha256 = r.ReadBytes(); break;
                case 5:  msg.FileLength = r.ReadUInt64(); break;
                case 7:  msg.MediaKey = r.ReadBytes(); break;
                case 8:  msg.FileName = r.ReadString(); break;
                case 9:  msg.FileEncSha256 = r.ReadBytes(); break;
                case 10: msg.DirectPath = r.ReadString(); break;
                case 11: msg.MediaKeyTimestamp = (long)r.ReadUInt64(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Field 31 of Message. Wraps messages sent from this account on another device.</summary>
public sealed class DeviceSentMessage
{
    public string? DestinationJid { get; set; }  // field 1
    public WAMessage? Message { get; set; }       // field 2

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        if (!string.IsNullOrEmpty(DestinationJid))
            ProtoEncoder.WriteString(buf, 1, DestinationJid);
        if (Message != null)
            ProtoEncoder.WriteMessage(buf, 2, Message.ToByteArray());
        return [.. buf];
    }

    public static DeviceSentMessage ParseFrom(byte[] data)
    {
        var msg = new DeviceSentMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.DestinationJid = r.ReadString(); break;
                case 2: msg.Message = WAMessage.ParseFrom(r.ReadBytes()); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Field 2 of Message. Distributes group encryption keys.</summary>
public sealed class SenderKeyDistributionMessage
{
    public string? GroupId { get; set; }          // field 1
    public byte[] AxolotlSenderKeyData { get; set; } = []; // field 2

    public static SenderKeyDistributionMessage ParseFrom(byte[] data)
    {
        var msg = new SenderKeyDistributionMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.GroupId = r.ReadString(); break;
                case 2: msg.AxolotlSenderKeyData = r.ReadBytes(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Field 12 of Message. Protocol-level messages (message revocation, history sync, etc.)</summary>
public sealed class ProtocolMessage
{
    public int Type { get; set; }  // field 5: type enum
    // field 1: key (MessageKey) — the message being revoked (for REVOKE)
    public MessageKey? Key { get; set; }
    // field 6: historySyncNotification (populated when Type == TYPE_HISTORY_SYNC_NOTIFICATION)
    public Dawa.Proto.HistorySyncNotification? HistorySyncNotification { get; set; }

    public const int TYPE_REVOKE                  = 0;
    public const int TYPE_HISTORY_SYNC_NOTIFICATION = 5;

    public static ProtocolMessage ParseFrom(byte[] data)
    {
        var msg = new ProtocolMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.Key  = MessageKey.ParseFrom(r.ReadBytes()); break;
                case 5: msg.Type = r.ReadInt32(); break;
                case 6:
                    var notifBytes = r.ReadBytes();
                    msg.HistorySyncNotification = Dawa.Proto.HistorySyncNotification.Decode(notifBytes);
                    break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        if (Key != null)  ProtoEncoder.WriteMessage(buf, 1, Key.ToByteArray());
        ProtoEncoder.WriteInt32(buf, 5, Type);
        return [.. buf];
    }
}

/// <summary>ContextInfo — quoted message metadata embedded in most message types (field 17).</summary>
public sealed class ContextInfo
{
    public string StanzaId     { get; set; } = "";  // field 4: ID of the quoted message
    public string Participant  { get; set; } = "";  // field 5: JID of the quoted message sender
    public WAMessage? QuotedMessage { get; set; }   // field 6: the quoted message content
    public bool IsForwarded    { get; set; }         // field 15: forwarded flag
    public uint ForwardingScore { get; set; }        // field 22: >0 means forwarded

    public static ContextInfo ParseFrom(byte[] data)
    {
        var msg = new ContextInfo();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 4:  msg.StanzaId    = r.ReadString(); break;
                case 5:  msg.Participant = r.ReadString(); break;
                case 6:  msg.QuotedMessage = WAMessage.ParseFrom(r.ReadBytes()); break;
                case 15: msg.IsForwarded = r.ReadBool(); break;
                case 22: msg.ForwardingScore = r.ReadUInt32(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        if (!string.IsNullOrEmpty(StanzaId))   ProtoEncoder.WriteString(buf, 4, StanzaId);
        if (!string.IsNullOrEmpty(Participant)) ProtoEncoder.WriteString(buf, 5, Participant);
        if (QuotedMessage != null)              ProtoEncoder.WriteMessage(buf, 6, QuotedMessage.ToByteArray());
        if (IsForwarded)                        ProtoEncoder.WriteBool(buf, 15, true);
        if (ForwardingScore > 0)                ProtoEncoder.WriteUInt32(buf, 22, ForwardingScore);
        return [.. buf];
    }
}

/// <summary>A single message inside a HistorySyncConversation.</summary>
public sealed class WebMessageInfo
{
    public WebMessageKey? Key { get; set; }       // field 1
    public WAMessage?     Message { get; set; }   // field 2
    public ulong          MessageTimestamp { get; set; } // field 3
    public int            Status { get; set; }    // field 4 (delivery status)
    public string         PushName { get; set; } = ""; // field 5

    public static WebMessageInfo ParseFrom(byte[] data)
    {
        var msg = new WebMessageInfo();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.Key               = WebMessageKey.ParseFrom(r.ReadBytes()); break;
                case 2: msg.Message           = WAMessage.ParseFrom(r.ReadBytes()); break;
                case 3: msg.MessageTimestamp  = r.ReadUInt64(); break;
                case 4: msg.Status            = r.ReadInt32(); break;
                case 5: msg.PushName          = r.ReadString(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Message key inside WebMessageInfo.</summary>
public sealed class WebMessageKey
{
    public string RemoteJid   { get; set; } = "";  // field 1
    public bool   FromMe      { get; set; }         // field 2
    public string Id          { get; set; } = "";  // field 3
    public string Participant { get; set; } = "";  // field 4 (group sender)

    public static WebMessageKey ParseFrom(byte[] data)
    {
        var msg = new WebMessageKey();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.RemoteJid   = r.ReadString(); break;
                case 2: msg.FromMe      = r.ReadBool(); break;
                case 3: msg.Id          = r.ReadString(); break;
                case 4: msg.Participant = r.ReadString(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Field 35 of Message. Contains device list metadata.</summary>
public sealed class MessageContextInfo
{
    public byte[] DeviceListMetadata { get; set; } = [];  // field 1

    public static MessageContextInfo ParseFrom(byte[] data)
    {
        var msg = new MessageContextInfo();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.DeviceListMetadata = r.ReadBytes(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

/// <summary>Field 85 of Message. Emoji reaction to another message.</summary>
public sealed class ReactionMessage
{
    /// <summary>The message being reacted to.</summary>
    public MessageKey? Key { get; set; }                  // field 1
    /// <summary>The reaction emoji (e.g. "👍") or "" to remove reaction.</summary>
    public string Text { get; set; } = "";                // field 2
    /// <summary>Sender timestamp in milliseconds.</summary>
    public long SenderTimestampMs { get; set; }           // field 4

    public static ReactionMessage ParseFrom(byte[] data)
    {
        var msg = new ReactionMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.Key = MessageKey.ParseFrom(r.ReadBytes()); break;
                case 2: msg.Text = r.ReadString(); break;
                case 4: msg.SenderTimestampMs = (long)r.ReadUInt64(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        if (Key != null) ProtoEncoder.WriteMessage(buf, 1, Key.ToByteArray());
        if (!string.IsNullOrEmpty(Text)) ProtoEncoder.WriteString(buf, 2, Text);
        if (SenderTimestampMs != 0) ProtoEncoder.WriteUInt64(buf, 4, (ulong)SenderTimestampMs);
        return [.. buf];
    }
}

/// <summary>
/// Field 145 of WAMessage.
/// Sent to our own JID to request the phone push an ON_DEMAND history sync blob
/// for a specific chat via HISTORY_SYNC_NOTIFICATION (syncType 5).
/// </summary>
public sealed class PeerDataOperationRequestMessage
{
    public const int TYPE_HISTORY_SYNC_ON_DEMAND = 7;  // PeerDataOperationRequestType enum

    public int    RequestType      { get; set; } = TYPE_HISTORY_SYNC_ON_DEMAND;  // field 1
    public string ChatJid          { get; set; } = "";  // historySyncOnDemandRequest.chatJid (field 6 → sub-field 1)
    public string OldestMsgId      { get; set; } = "";  // historySyncOnDemandRequest.oldestMsgId (field 6 → sub-field 2)
    public bool   OldestMsgFromMe  { get; set; }        // historySyncOnDemandRequest.oldestMsgFromMe (field 6 → sub-field 3)
    public int    OnDemandMsgCount { get; set; } = 50;  // historySyncOnDemandRequest.onDemandMsgCount (field 6 → sub-field 4)

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        // field 1: peerDataOperationRequestType
        ProtoEncoder.WriteInt32(buf, 1, RequestType);

        // field 6: historySyncOnDemandRequest (embedded message)
        var req = new List<byte>();
        ProtoEncoder.WriteString(req, 1, ChatJid);
        if (!string.IsNullOrEmpty(OldestMsgId)) ProtoEncoder.WriteString(req, 2, OldestMsgId);
        if (OldestMsgFromMe)                    ProtoEncoder.WriteBool(req, 3, true);
        ProtoEncoder.WriteInt32Always(req, 4, OnDemandMsgCount);  // always emit count even if 0
        ProtoEncoder.WriteMessage(buf, 6, [.. req]);

        return [.. buf];
    }
}

/// <summary>
/// Field 146 of WAMessage — response sent by the phone to a PeerDataOperationRequestMessage.
/// For ON_DEMAND history, historySyncOnDemandRequestResult.historyData contains
/// an inline compressed+encrypted history blob (same format as CDN download).
/// </summary>
public sealed class PeerDataOperationResponseMessage
{
    /// <summary>List of results, one per request item.</summary>
    public List<PeerDataOperationResult> Results { get; set; } = [];

    public static PeerDataOperationResponseMessage Decode(byte[] data)
    {
        var obj = new PeerDataOperationResponseMessage();
        var r   = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wt) = r.ReadTag();
            if (field == 1) obj.Results.Add(PeerDataOperationResult.Decode(r.ReadBytes()));
            else r.Skip(wt);
        }
        return obj;
    }
}

public sealed class PeerDataOperationResult
{
    public int    ResultType  { get; set; }   // field 1: 0=OK, 1=UNSUPPORTED, 2=NOT_FOUND
    public byte[] HistoryData { get; set; } = []; // field 6 → historySyncOnDemandRequestResult.historyData (sub-field 1)

    public static PeerDataOperationResult Decode(byte[] data)
    {
        var obj = new PeerDataOperationResult();
        var r   = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wt) = r.ReadTag();
            switch (field)
            {
                case 1: obj.ResultType  = r.ReadInt32(); break;
                case 6: obj.HistoryData = ReadHistoryData(r.ReadBytes()); break;
                default: r.Skip(wt); break;
            }
        }
        return obj;
    }

    private static byte[] ReadHistoryData(byte[] resultBytes)
    {
        var r = ProtoEncoder.CreateReader(resultBytes);
        while (r.HasMore)
        {
            var (f, wt) = r.ReadTag();
            if (f == 1) return r.ReadBytes();
            r.Skip(wt);
        }
        return [];
    }
}

/// <summary>Key that identifies a specific WhatsApp message.</summary>
public sealed class MessageKey
{
    public string RemoteJid { get; set; } = "";   // field 1
    public bool   FromMe    { get; set; }          // field 2
    public string Id        { get; set; } = "";    // field 3

    public static MessageKey ParseFrom(byte[] data)
    {
        var msg = new MessageKey();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.RemoteJid = r.ReadString(); break;
                case 2: msg.FromMe    = r.ReadBool();   break;
                case 3: msg.Id        = r.ReadString(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        if (!string.IsNullOrEmpty(RemoteJid)) ProtoEncoder.WriteString(buf, 1, RemoteJid);
        if (FromMe) ProtoEncoder.WriteBool(buf, 2, FromMe);
        if (!string.IsNullOrEmpty(Id)) ProtoEncoder.WriteString(buf, 3, Id);
        return [.. buf];
    }
}
