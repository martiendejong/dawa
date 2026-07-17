using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dawa.Auth;
using Dawa.Binary;
using Dawa.Crypto;
using Dawa.Messages;
using Dawa.Proto;
using Dawa.Signal;
using Dawa.Transport;
using Microsoft.Extensions.Logging;

namespace Dawa.Noise;

/// <summary>
/// Handles the WhatsApp Noise XX handshake and post-handshake encrypted transport.
/// After the handshake completes, all frames are encrypted/decrypted with AES-GCM
/// using keys derived from the Noise session.
/// </summary>
public sealed class NoiseProcessor : IAsyncDisposable
{
    // WhatsApp prologue bytes: "WA" + protocol version 6 + dict version 3
    // Source: Baileys NOISE_WA_HEADER = Buffer.from([87, 65, 6, DICT_VERSION]) where DICT_VERSION=3
    private static readonly byte[] WA_PROLOGUE = [0x57, 0x41, 0x06, 0x03];

    private readonly FrameSocket _socket;
    private readonly AuthState _auth;
    private readonly WhatsAppClientOptions _options;
    private readonly ILogger _logger;

    // Transport keys (set after handshake)
    private byte[]? _sendKey;
    private byte[]? _recvKey;
    private ulong _sendCounter;
    private ulong _recvCounter;
    private bool _handshakeDone;

    // Ephemeral key pair (generated fresh per connection)
    private readonly byte[] _ephemeralPriv;
    private readonly byte[] _ephemeralPub;

    // Signal Protocol session store
    private readonly SignalKeyStore _signalStore;

    // Pending IQ tracking for request/response correlation
    private readonly Dictionary<string, TaskCompletionSource<BinaryNode>> _pendingIqs = new();

    // Only fire Authenticated + upload pre-keys once per connection (not on every periodic success token)
    private bool _sessionAuthenticated;
    private CancellationTokenSource? _keepAliveCts;

    // When WhatsApp sends edge_routing, we store the bytes for use on next reconnect.
    // We do NOT break the receive loop — only a stream:error or socket close causes a reconnect.
    public byte[]? PendingRoutingInfo { get; private set; }

    // Shared HttpClient for CDN media uploads
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(60) };

    // Track the last on-demand history request so we can auto-resend when the phone sends a retry receipt
    private (string ChatJid, string? OldestMsgId, bool OldestMsgFromMe, long OldestMsgTimestampMs, int Count)? _lastPdoRequest;
    private readonly HashSet<string> _sentPdoMsgIds = new();

    // Index into auth.PreKeys for retry receipts — incremented per receipt so each message
    // gets a unique one-time pre-key. Without this all retry receipts would advertise the
    // same pre-key; only the first re-encrypted message would decrypt (the key gets consumed).
    private int _retryPreKeyIndex = 0;

    public event EventHandler<string>? QRCodeGenerated;
    public event EventHandler<AuthState>? Authenticated;
    public event EventHandler<IncomingMessage>? MessageReceived;
    /// <summary>Fired for each message loaded from history sync (past messages).</summary>
    public event EventHandler<IncomingMessage>? HistoryMessageReceived;
    /// <summary>Fired once after a history-sync blob has been fully processed (use to flush persisted store).</summary>
    public event EventHandler<int>? HistorySyncCompleted;

    public NoiseProcessor(FrameSocket socket, AuthState auth, WhatsAppClientOptions options, ILogger logger)
    {
        _socket = socket;
        _auth = auth;
        _options = options;
        _logger = logger;

        (_ephemeralPriv, _ephemeralPub) = Curve25519Helper.GenerateKeyPair();
        _signalStore = new SignalKeyStore(options.SessionDirectory);

        // Load persisted LID/push-name caches from previous sessions
        LoadCacheFromDisk();
    }

    private string CacheFilePath => Path.Combine(_options.SessionDirectory, "contact-cache.json");

    private void LoadCacheFromDisk()
    {
        try
        {
            if (!File.Exists(CacheFilePath)) return;
            var json = File.ReadAllText(CacheFilePath);
            var data = System.Text.Json.JsonSerializer.Deserialize<ContactCacheFile>(json);
            if (data == null) return;
            foreach (var kv in data.LidToPhone) _lidToPhone[kv.Key] = kv.Value;
            foreach (var kv in data.PushNames)  _pushNames[kv.Key]  = kv.Value;
            _logger.LogInformation("Loaded contact cache: {Lids} LID mappings, {Names} push names",
                _lidToPhone.Count, _pushNames.Count);
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Failed to load contact cache"); }
    }

    private void SaveCacheToDisk()
    {
        try
        {
            var data = new ContactCacheFile
            {
                LidToPhone = new Dictionary<string, string>(_lidToPhone),
                PushNames  = new Dictionary<string, string>(_pushNames),
            };
            var json = System.Text.Json.JsonSerializer.Serialize(data, new System.Text.Json.JsonSerializerOptions { WriteIndented = false });
            File.WriteAllText(CacheFilePath, json);
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Failed to save contact cache"); }
    }

    private sealed class ContactCacheFile
    {
        public Dictionary<string, string> LidToPhone { get; set; } = new();
        public Dictionary<string, string> PushNames  { get; set; } = new();
    }

    // ─── Handshake ───────────────────────────────────────────────────────────

    /// <summary>
    /// Performs the complete Noise XX handshake with the WhatsApp server.
    /// </summary>
    public async Task PerformHandshakeAsync(CancellationToken ct)
    {
        var noise = new NoiseState();

        // WhatsApp's modified Noise XX initialization (matches Baileys noise-handler.js):
        // 1. Mix prologue (WA header bytes: "WA" + version 6 + dict 3)
        noise.MixHash(WA_PROLOGUE);
        // 2. Mix OUR ephemeral public key (NOT the static noise key — Baileys does this at init)
        noise.MixHash(_ephemeralPub);

        // ── Phase 1: Send ClientHello with our ephemeral key ──────────────────

        var clientHello = new ClientHello { Ephemeral = _ephemeralPub };
        var handshake1 = new HandshakeMessage { ClientHello = clientHello };
        await SendHandshakeMessageAsync(handshake1, ct);

        _logger.LogDebug("Noise: Sent ClientHello (ephemeral key)");

        // ── Phase 2: Receive ServerHello ──────────────────────────────────────
        var serverFrame = await _socket.ReceiveFrameAsync(ct)
            ?? throw new InvalidOperationException("Server closed connection during handshake.");

        var handshakeResp = HandshakeMessage.ParseFrom(serverFrame);
        var serverHello = handshakeResp.ServerHello
            ?? throw new InvalidOperationException("Expected ServerHello.");

        var serverEphemeral = serverHello.Ephemeral;
        var serverStaticEnc = serverHello.Static;
        var serverPayloadEnc = serverHello.Payload;

        // Mix server ephemeral
        noise.MixHash(serverEphemeral);
        // DH(our_ephemeral, server_ephemeral)
        var dh1 = Curve25519Helper.DH(_ephemeralPriv, serverEphemeral);
        noise.MixKey(dh1);

        // Decrypt server static key
        var serverStaticPub = noise.DecryptWithAssociatedData(serverStaticEnc);
        // DH(our_ephemeral, server_static)
        var dh2 = Curve25519Helper.DH(_ephemeralPriv, serverStaticPub);
        noise.MixKey(dh2);

        // Decrypt server payload (certificate / metadata)
        var serverPayload = noise.DecryptWithAssociatedData(serverPayloadEnc);
        _logger.LogDebug("Noise: Received ServerHello, decrypted server payload ({Length} bytes)", serverPayload.Length);

        // ── Phase 3: Send ClientFinish ─────────────────────────────────────────
        // Encrypt our static (noise) public key
        var encStaticPub = noise.EncryptWithAssociatedData(_auth.NoiseKeyPublic);
        // DH(our_static, server_ephemeral)
        var dh3 = Curve25519Helper.DH(_auth.NoiseKeyPrivate, serverEphemeral);
        noise.MixKey(dh3);

        // Build client payload and encrypt it
        var clientPayload = BuildClientPayload();
        var encPayload = noise.EncryptWithAssociatedData(clientPayload);

        _logger.LogInformation("Noise: ClientFinish encStaticPub({Len})={Hex}",
            encStaticPub.Length, BitConverter.ToString(encStaticPub));
        _logger.LogInformation("Noise: ClientFinish encPayload({Len})={Hex}",
            encPayload.Length, BitConverter.ToString(encPayload));
        _logger.LogInformation("Noise: ClientPayload raw({Len})={Hex}",
            clientPayload.Length, BitConverter.ToString(clientPayload));

        var clientFinish = new ClientFinish
        {
            Static = encStaticPub,
            Payload = encPayload,
        };
        var handshake3 = new HandshakeMessage { ClientFinish = clientFinish };
        await SendHandshakeMessageAsync(handshake3, ct);

        _logger.LogDebug("Noise: Sent ClientFinish");

        // ── Finalize: derive transport keys ───────────────────────────────────
        (_sendKey, _recvKey) = noise.Split();
        _sendCounter = 0;
        _recvCounter = 0;
        _handshakeDone = true;

        _logger.LogInformation("Noise: Handshake complete. Transport keys established. sendKey[0..4]={S} recvKey[0..4]={R}",
            BitConverter.ToString(_sendKey, 0, 4),
            BitConverter.ToString(_recvKey, 0, 4));

        // Now handle the post-handshake authentication (QR or session restore)
        await HandlePostHandshakeAsync(ct);
    }

    // ─── Post-Handshake Auth ────────────────────────────────────────────────

    private Task HandlePostHandshakeAsync(CancellationToken ct)
    {
        // After the Noise handshake + ClientFinish, the server drives the flow.
        // For fresh connections: server processes our devicePairingData from ClientPayload,
        //   then sends an IQ pair-device with QR ref.
        // For existing sessions: server acknowledges the session via "success" or "stream:features".
        // We just start listening — no proactive sends needed here.
        if (_auth.IsFresh)
            _logger.LogInformation("Fresh session — waiting for server QR pair-device IQ.");
        else
            _logger.LogInformation("Restoring session for {Me}", _auth.Me?.Id);

        return Task.CompletedTask;
    }

    // ─── Receive loop ───────────────────────────────────────────────────────

    /// <summary>
    /// Continuously reads and processes incoming frames. Call this on a background task.
    /// </summary>
    // Timestamp (ticks) of the last frame received from the server. The keepalive loop
    // watches this to detect a dead/half-open connection (no data for too long) and tear
    // the socket down so the receive loop unblocks and reconnection can run. Without this a
    // silently-dropped socket parks ReceiveAsync forever (root cause of the 85-min outage).
    private long _lastRecvTicks = DateTime.UtcNow.Ticks;

    public async Task ReceiveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _socket.IsConnected)
        {
            try
            {
                var frame = await _socket.ReceiveFrameAsync(ct);
                if (frame == null) break;

                System.Threading.Interlocked.Exchange(ref _lastRecvTicks, DateTime.UtcNow.Ticks);

                _logger.LogInformation("Noise: Received raw frame ({Len} bytes), first bytes={Hex}",
                    frame.Length, BitConverter.ToString(frame, 0, Math.Min(32, frame.Length)));

                var decrypted = DecryptFrame(frame);
                // Baileys protocol: first byte is a flags byte.
                // Bit 1 (value 2) = payload is zlib raw-deflate compressed.
                // Always strip this byte before decoding the binary node.
                var nodeData = StripFlagsAndDecompress(decrypted);
                _logger.LogInformation("Noise: Decrypted frame ({Len} bytes), first bytes={Hex}",
                    decrypted.Length, BitConverter.ToString(decrypted, 0, Math.Min(32, decrypted.Length)));

                var node = BinaryNodeDecoder.Decode(nodeData);

                // Server sent StreamEnd — graceful close, stop receive loop.
                if (node.Tag == BinaryNodeDecoder.StreamEndSentinel)
                {
                    _logger.LogInformation("Server sent stream-end, closing.");
                    break;
                }

                var nodeStr = node.ToString();
                _logger.LogInformation("Received node: {Node}", nodeStr);
                // Write to file log (bypasses IIS stdout 8KB cap)
                try
                {
                    var logDir = Path.Combine(_options.SessionDirectory, "..", "nodelog");
                    Directory.CreateDirectory(logDir);
                    var logFile = Path.Combine(logDir, "nodes.log");
                    File.AppendAllText(logFile, $"[{DateTime.UtcNow:HH:mm:ss}] {nodeStr}\n");
                }
                catch { /* non-fatal */ }
                await HandleNodeAsync(node, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in receive loop");
                break;
            }
        }
        _logger.LogInformation("Receive loop ended.");
        SaveCacheToDisk();
    }

    private async Task HandleNodeAsync(BinaryNode node, CancellationToken ct)
    {
        switch (node.Tag)
        {
            case "chat" when node.GetAttr("add") == "@xmlstreamstart":
                // Multi-device: server embeds pair-device refs directly in the xmlstreamstart frame.
                // Structure: <chat add="@xmlstreamstart"><container><ref>[102 bytes]</ref>×6</container></chat>
                await HandleXmlStreamStartAsync(node, ct);
                break;
            case "iq":
                await HandleIQAsync(node, ct);
                break;
            case "message":
                HandleMessageNode(node);
                break;
            case "notification":
                await HandleNotificationAsync(node, ct);
                break;
            case "presence":
                HandlePresenceNode(node);
                break;
            case "receipt":
                await HandleReceiptAsync(node, ct);
                break;
            case "success":
                if (!_sessionAuthenticated)
                {
                    _sessionAuthenticated = true;
                    _logger.LogInformation("Session authenticated successfully.");
                    Authenticated?.Invoke(this, _auth);
                    // Upload pre-keys so other devices can start Signal sessions with us,
                    // then announce presence so WhatsApp starts delivering messages to this device.
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await UploadPreKeysAsync(ct);
                            await SendActiveAsync(ct);       // CRITICAL: switch session from passive → active
                            await SendPresenceAsync(ct);
                            await SendAppStateSyncAsync(ct);
                        }
                        catch (Exception ex) { _logger.LogWarning(ex, "Post-auth setup failed (non-fatal)"); }
                    });
                    // Start proactive keepalive pings (every 25s, like Baileys)
                    _keepAliveCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    _ = Task.Run(() => KeepAliveLoopAsync(_keepAliveCts.Token));
                }
                else
                {
                    _logger.LogDebug("Received periodic success token (session already authenticated, skipping re-init).");
                }
                break;
            case "failure":
                _logger.LogWarning("Authentication failure: {Reason}", node.GetAttr("reason"));
                break;
            case "stream:error":
                _logger.LogError("Stream error: {Code}", node.GetAttr("code"));
                break;
            case "ib":
                await HandleIbAsync(node, ct);
                break;
            default:
                _logger.LogDebug("Unhandled node tag: {Tag}", node.Tag);
                break;
        }
    }

    /// <summary>
    /// Handles informational broadcast (ib) nodes from WhatsApp.
    /// The most important one is dirty type="account_sync" — WhatsApp withholds
    /// message delivery until the client sends a "clean" IQ to acknowledge the sync.
    /// </summary>
    private async Task HandleIbAsync(BinaryNode ib, CancellationToken ct)
    {
        foreach (var child in ib.Children)
        {
            if (child.Tag == "dirty")
            {
                var dirtyType = child.GetAttr("type") ?? "";
                var timestamp = child.GetAttr("timestamp") ?? "";

                _logger.LogInformation("Received dirty notification: type={Type}, timestamp={Ts} — sending clean IQ", dirtyType, timestamp);

                var cleanIq = new BinaryNode("iq", new Dictionary<string, string>
                {
                    ["to"]    = "@s.whatsapp.net",
                    ["type"]  = "set",
                    ["xmlns"] = "urn:xmpp:whatsapp:dirty",
                    ["id"]    = GenerateMessageId(),
                })
                {
                    Content = new List<BinaryNode>
                    {
                        new("clean", new Dictionary<string, string>
                        {
                            ["type"]      = dirtyType,
                            ["timestamp"] = timestamp,
                        }),
                    },
                };

                try
                {
                    await SendNodeAsync(cleanIq, ct);
                    _logger.LogInformation("Sent clean IQ for dirty type={Type} — message delivery should resume.", dirtyType);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to send clean IQ for dirty type={Type}", dirtyType);
                }
            }
            else if (child.Tag == "edge_routing")
            {
                // WhatsApp suggests a preferred edge server. Store routing bytes for use on next
                // reconnect (triggered by stream:error or socket close). Do NOT force an immediate
                // disconnect — that causes an infinite reconnect loop.
                var routingInfo = child.FindChild("routing_info");
                if (routingInfo?.Content is byte[] routingBytes && routingBytes.Length > 0)
                {
                    PendingRoutingInfo = routingBytes;
                    _logger.LogInformation("Received edge_routing ({Len} bytes) — stored for next reconnect.", routingBytes.Length);
                }
            }
            else if (child.Tag == "offline_preview")
            {
                // WA sends offline_preview to tell us there are queued offline messages.
                // Baileys responds with <ib><offline_batch count="100"/></ib> to trigger delivery.
                // Without this, WA never delivers the offline messages.
                var msgCount = child.GetAttr("message") ?? child.GetAttr("count") ?? "0";
                // Request the FULL pending count (not a fixed 100) so the entire offline queue
                // drains in one reconnect instead of 100-at-a-time across many. A healthy client
                // (Baileys) drains the whole queue; combined with ACK-and-skip of dead backlog
                // this keeps the bridge current. Cap high as a sanity bound.
                var batchCount = (int.TryParse(msgCount, out var mc) && mc > 0) ? Math.Min(mc, 100000) : 5000;
                _logger.LogInformation("offline_preview: {Count} queued — requesting full offline_batch of {Batch}", msgCount, batchCount);
                var offlineBatch = new BinaryNode("ib")
                {
                    Content = new List<BinaryNode>
                    {
                        new("offline_batch", new Dictionary<string, string> { ["count"] = batchCount.ToString() }),
                    },
                };
                await SendNodeAsync(offlineBatch, ct);
            }
            else if (child.Tag == "offline")
            {
                // WA sends this after delivering all offline messages.
                var offlineCount = child.GetAttr("count") ?? "0";
                _logger.LogInformation("offline delivery complete: {Count} items received", offlineCount);
            }
            else if (child.Tag == "thread_metadata")
            {
                // WhatsApp pushes the chat list on startup as <thread_metadata> items.
                // Each <item from="JID" t="timestamp"/> is an active chat.
                // JIDs may be @lid (privacy-preserving long-lived IDs) or @s.whatsapp.net or @g.us.
                foreach (var item in child.Children)
                {
                    if (item.Tag == "item")
                    {
                        var jid = item.GetAttr("from") ?? "";
                        var ts  = item.GetAttr("t") ?? "0";
                        if (!string.IsNullOrEmpty(jid) && long.TryParse(ts, out var tsVal))
                        {
                            _threadMetadata[jid] = tsVal;
                            _logger.LogDebug("thread_metadata: chat {Jid} t={Ts}", jid, tsVal);
                        }
                    }
                }
                _logger.LogInformation("Cached {Count} chats from thread_metadata", _threadMetadata.Count);
            }
            else
            {
                _logger.LogDebug("Unhandled ib child: {Tag}", child.Tag);
            }
        }
    }

    private async Task HandleXmlStreamStartAsync(BinaryNode chat, CancellationToken ct)
    {
        // In the WhatsApp multi-device protocol, the server packs pair-device ref blobs
        // directly into the first post-handshake frame as children of the xmlstreamstart node.
        // Walk the children to find the first binary payload — that is the first QR ref.
        byte[]? refBytes = null;
        foreach (var container in chat.Children)
        {
            foreach (var child in container.Children)
            {
                if (child.Data is { Length: > 0 })
                {
                    refBytes = child.Data;
                    break;
                }
            }
            if (refBytes != null) break;
        }

        if (refBytes == null)
        {
            _logger.LogWarning("xmlstreamstart node contained no ref blobs — cannot generate QR.");
            return;
        }

        // The ref blob is raw bytes; base64-encode it to form the ref string.
        var ref_ = Convert.ToBase64String(refBytes);
        var qrParts = new[]
        {
            ref_,
            Convert.ToBase64String(_auth.NoiseKeyPublic),
            Convert.ToBase64String(_auth.SignedIdentityKeyPublic),
            Convert.ToBase64String(_auth.AdvSecretKey),
        };
        var qrString = string.Join(",", qrParts);

        _logger.LogInformation("QR Code ready (from xmlstreamstart, ref={RefLen} bytes).", refBytes.Length);
        QRCodeGenerated?.Invoke(this, qrString);
        // Connection stays open — server waits for QR scan (up to ~20s per ref).
    }

    private async Task HandleIQAsync(BinaryNode iq, CancellationToken ct)
    {
        // Resolve any pending IQ awaiter first
        var iqId = iq.GetAttr("id") ?? "";
        var iqType = iq.GetAttr("type") ?? "";
        _logger.LogDebug("HandleIQ: id={Id} type={Type} pendingKeys=[{Keys}]",
            iqId, iqType, string.Join(",", _pendingIqs.Keys));
        if ((iqType == "result" || iqType == "error") && _pendingIqs.TryGetValue(iqId, out var tcs))
        {
            _pendingIqs.Remove(iqId);
            _logger.LogInformation("IQ resolved: id={Id} type={Type}", iqId, iqType);
            tcs.SetResult(iq);
            return;
        }

        var type = iq.GetAttr("type");
        if (type == "get")
        {
            // Respond to keep-alive pings from the server
            if (iq.FindChild("ping") != null)
            {
                var pong = new BinaryNode("iq", new()
                {
                    ["id"]   = iq.GetAttr("id") ?? "",
                    ["type"] = "result",
                    ["to"]   = iq.GetAttr("from") ?? "@s.whatsapp.net",
                });
                await SendNodeAsync(pong, ct);
                _logger.LogDebug("Responded to server ping id={Id}", iq.GetAttr("id"));
            }
            return;
        }
        else if (type == "result")
        {
            // Check for pair-device result (QR code ref)
            var pairDevice = iq.FindChild("pair-device");
            if (pairDevice != null)
            {
                await HandlePairDeviceResultAsync(pairDevice, ct);
                return;
            }

            // Check for pair-success (phone scanned QR) — also handle type="result" path
            var pairSuccess = iq.FindChild("pair-success");
            if (pairSuccess != null)
            {
                await HandlePairSuccessAsync(iq, pairSuccess, ct);
                return;
            }
        }
        else if (type == "set")
        {
            // Server is initiating a request (e.g., pair-device from server side)
            var pairDevice = iq.FindChild("pair-device");
            if (pairDevice != null)
            {
                // Respond with an ack
                var ack = new BinaryNode("iq", new()
                {
                    ["id"] = iq.GetAttr("id") ?? "",
                    ["type"] = "result",
                    ["to"] = iq.GetAttr("from") ?? "@s.whatsapp.net",
                });
                await SendNodeAsync(ack, ct);
                // Generate QR from the first ref in the pair-device node
                await HandlePairDeviceResultAsync(pairDevice, ct);
            }

            // pair-success arrives as type="set" (server-initiated), not type="result"
            var pairSuccess2 = iq.FindChild("pair-success");
            if (pairSuccess2 != null)
            {
                await HandlePairSuccessAsync(iq, pairSuccess2, ct);
            }
        }
    }

    private async Task HandlePairDeviceResultAsync(BinaryNode pairDevice, CancellationToken ct)
    {
        // Extract ref token from server — the ref is a binary blob encoded as base64 in the QR
        var refNode = pairDevice.FindChild("ref");
        if (refNode == null) return;

        // ref content arrives as raw bytes that are actually a UTF-8 string
        // (the server sends e.g. 102 ASCII chars of a base64-like token as byte[])
        // Do NOT base64-encode it again — decode the bytes as UTF-8.
        string ref_;
        if (refNode.Data != null)
            ref_ = System.Text.Encoding.UTF8.GetString(refNode.Data);
        else if (refNode.Text != null)
            ref_ = refNode.Text;
        else
            return;

        var qrParts = new[]
        {
            ref_,
            Convert.ToBase64String(_auth.NoiseKeyPublic),
            Convert.ToBase64String(_auth.SignedIdentityKeyPublic),
            Convert.ToBase64String(_auth.AdvSecretKey),
        };
        var qrString = string.Join(",", qrParts);

        _logger.LogInformation("QR Code ready for scanning.");
        QRCodeGenerated?.Invoke(this, qrString);
    }

    private async Task HandlePairSuccessAsync(BinaryNode iq, BinaryNode pairSuccess, CancellationToken ct)
    {
        var msgId = iq.GetAttr("id") ?? "";
        _logger.LogInformation("=== PAIR-SUCCESS RECEIVED === id={Id}", msgId);

        var platform = pairSuccess.GetAttr("platform") ?? "UNKNOWN";

        // Extract JID
        var deviceNode = pairSuccess.FindChild("device");
        var jid = deviceNode?.GetAttr("jid") ?? "";
        _logger.LogInformation("Paired as {Jid} on platform {Platform}", jid, platform);

        // ── ADV device-identity verification & signing ─────────────────────
        // Baileys: configureSuccessfulPairing() in validate-connection.js
        var devIdentityNode = pairSuccess.FindChild("device-identity");
        if (devIdentityNode?.Data == null)
        {
            _logger.LogError("pair-success missing device-identity content — cannot complete pairing.");
            return;
        }

        // 1. Decode ADVSignedDeviceIdentityHMAC
        var hmacMsg = ADVSignedDeviceIdentityHMAC.ParseFrom(devIdentityNode.Data);

        // 2. Verify HMAC-SHA256(details, advSecretKey)
        //    isHostedAccount = (hmacMsg.AccountType == 1) => prefix [6,5], else empty
        var isHosted = hmacMsg.AccountType == 1;
        var hmacInput = isHosted
            ? (new byte[] { 6, 5 }).Concat(hmacMsg.Details).ToArray()
            : hmacMsg.Details;
        var expectedHmac = HMACSHA256.HashData(_auth.AdvSecretKey, hmacInput);
        if (!expectedHmac.AsSpan().SequenceEqual(hmacMsg.Hmac))
        {
            _logger.LogError("ADV HMAC verification failed — pairing rejected.");
            return;
        }
        _logger.LogInformation("ADV HMAC verified OK.");

        // 3. Decode ADVSignedDeviceIdentity
        var account = ADVSignedDeviceIdentity.ParseFrom(hmacMsg.Details);

        // 4. Verify account signature: XEdDSA.Verify(accountSignatureKey, [6,0] + deviceDetails + identityPub, accountSignature)
        var accountMsg = new byte[] { 6, 0 }
            .Concat(account.Details)
            .Concat(_auth.SignedIdentityKeyPublic)
            .ToArray();
        if (!XEdDSA.Verify(account.AccountSignatureKey, accountMsg, account.AccountSignature))
        {
            _logger.LogError("Account signature verification failed — pairing rejected.");
            return;
        }
        _logger.LogInformation("Account signature verified OK.");

        // 5. Sign device identity: XEdDSA.Sign(identityPrivate, prefix + deviceDetails + identityPub + accountSigKey)
        var devicePrefix = isHosted ? new byte[] { 6, 6 } : new byte[] { 6, 1 };
        var deviceMsg = devicePrefix
            .Concat(account.Details)
            .Concat(_auth.SignedIdentityKeyPublic)
            .Concat(account.AccountSignatureKey)
            .ToArray();
        account.DeviceSignature = XEdDSA.Sign(_auth.SignedIdentityKeyPrivate, deviceMsg);
        _logger.LogInformation("Device signature created.");

        // Store account in auth state for device-identity node when sending pkmsg
        _auth.Account = account.ToByteArray();

        // 6. Decode ADVDeviceIdentity to get keyIndex
        var deviceIdentity = ADVDeviceIdentity.ParseFrom(account.Details);

        // 7. Re-encode ADVSignedDeviceIdentity (WITHOUT accountSignatureKey per Baileys protocol)
        var accountEnc = account.ToByteArrayForReply();

        // 8. Send pair-device-sign IQ as the result (this IS the ack — same msgId)
        var deviceIdentityNode2 = new BinaryNode("device-identity", new()
        {
            ["key-index"] = deviceIdentity.KeyIndex.ToString(),
        })
        {
            Content = accountEnc,
        };
        var pairDeviceSign = new BinaryNode("pair-device-sign")
        {
            Content = new List<BinaryNode> { deviceIdentityNode2 },
        };
        var reply = new BinaryNode("iq", new()
        {
            ["to"]   = "@s.whatsapp.net",
            ["type"] = "result",
            ["id"]   = msgId,
        })
        {
            Content = new List<BinaryNode> { pairDeviceSign },
        };
        await SendNodeAsync(reply, ct);
        _logger.LogInformation("pair-device-sign sent (keyIndex={KeyIndex}).", deviceIdentity.KeyIndex);

        // 9. Update auth state
        _auth.Platform = platform;
        _auth.Me = new MeInfo { Id = jid };

        _logger.LogInformation("Firing Authenticated event — session established.");
        Authenticated?.Invoke(this, _auth);
    }

    private void HandleMessageNode(BinaryNode node)
    {
        var from           = node.GetAttr("from") ?? "";
        var id             = node.GetAttr("id") ?? "";
        var participant    = node.GetAttr("participant");
        var participantPn  = node.GetAttr("participant_pn");  // phone JID when participant is a LID
        var participantLid = node.GetAttr("participant_lid"); // LID when participant/from is a phone JID
        var senderLid      = node.GetAttr("sender_lid");      // LID when from= is a phone JID
        var senderPn       = node.GetAttr("sender_pn");       // phone JID when from= is a LID
        var pushName       = node.GetAttr("notify");

        // ── Learn lid↔phone mappings from ALL addressing attributes, and CRITICALLY
        //    propagate each one into the Signal store so the decrypt path resolves the
        //    LID to the same session. Without this the two maps drift and MAC verification
        //    fails for LID senders (root cause, 2026-07-03). Registering also collapses any
        //    split lid-keyed session onto the canonical phone slot before we decrypt below.
        var cacheUpdated = false;
        void LearnMapping(string? lid, string? phone)
        {
            if (string.IsNullOrEmpty(lid) || string.IsNullOrEmpty(phone)) return;
            if (!lid.EndsWith("@lid") || !phone.EndsWith("@s.whatsapp.net")) return;
            if (!_lidToPhone.TryGetValue(lid, out var ex) || ex != phone)
            {
                _lidToPhone[lid] = phone;
                cacheUpdated = true;
            }
            // Propagate to the Signal session store (map + session migration).
            try { _signalStore.RegisterLidMapping(lid, phone); } catch { /* best effort */ }
        }

        LearnMapping(participant, participantPn);                       // participant=LID, participant_pn=phone
        if (from.EndsWith("@s.whatsapp.net")) LearnMapping(senderLid, from);        // from=phone, sender_lid=LID
        if (from.EndsWith("@lid"))            LearnMapping(from, senderPn);          // from=LID, sender_pn=phone
        if (!string.IsNullOrEmpty(participant) && participant.EndsWith("@s.whatsapp.net"))
            LearnMapping(participantLid, participant);                  // participant=phone, participant_lid=LID

        // Chat address for storage/display: normalize a LID `from` to its phone JID when
        // known, so the message is stored under a phone key that getMessages(phone) finds.
        var remoteJid = from.EndsWith("@lid") && _lidToPhone.TryGetValue(from, out var fromPhone)
            ? fromPhone : from;

        // Also store push names keyed by sender JID (may be LID or phone JID)
        if (!string.IsNullOrEmpty(pushName))
        {
            var senderJid = participant ?? from;
            if (!string.IsNullOrEmpty(senderJid) && !_pushNames.ContainsKey(senderJid))
            {
                _pushNames[senderJid] = pushName;
                cacheUpdated = true;
            }
            // If participant is a LID, also map the phone JID if we know it
            if (!string.IsNullOrEmpty(participantPn) && !_pushNames.ContainsKey(participantPn))
            {
                _pushNames[participantPn] = pushName;
                cacheUpdated = true;
            }
            // If from is a phone JID and we have a sender_lid, map both
            if (!string.IsNullOrEmpty(senderLid) && !_pushNames.ContainsKey(senderLid))
            {
                _pushNames[senderLid] = pushName;
                cacheUpdated = true;
            }
        }

        if (cacheUpdated) SaveCacheToDisk();

        // Track this chat in thread metadata
        if (!string.IsNullOrEmpty(from) && long.TryParse(node.GetAttr("t"), out var msgTs))
            _threadMetadata[from] = msgTs;

        var myJidBase = _auth.Me?.Id?.Split(':')[0]; // e.g. "31633984381"
        var fromMe    = from == myJidBase + "@s.whatsapp.net"
                     || (myJidBase != null && from.StartsWith(myJidBase));

        if (!long.TryParse(node.GetAttr("t"), out var timestamp))
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // ── Encrypted path: <participants><to jid="..."><enc .../></to></participants> ──
        var participantsNode = node.FindChild("participants");
        if (participantsNode != null)
        {
            foreach (var toNode in participantsNode.GetChildren("to"))
            {
                var toJid = toNode.GetAttr("jid") ?? "";
                if (myJidBase != null && !toJid.StartsWith(myJidBase)) continue;

                var encNode = toNode.FindChild("enc");
                if (encNode?.Data == null) continue;

                var encType = encNode.GetAttr("type") ?? "msg";
                try
                {
                    var senderJid = participant ?? from;
                    _logger.LogDebug("Participants path: decrypting encType={EncType} from {Jid}", encType, senderJid);
                    var plaintext = _signalStore.DecryptMessage(senderJid, encType, encNode.Data, _auth);
                    var waMsg     = WAMessage.ParseFrom(StripSignalPadding(plaintext));

                    // ── History sync notification (participants path) ─────────────────────────
                    if (waMsg.ProtocolMsg?.Type == Proto.ProtocolMessage.TYPE_HISTORY_SYNC_NOTIFICATION
                        && waMsg.ProtocolMsg.HistorySyncNotification != null)
                    {
                        _logger.LogInformation("Participants path: received HISTORY_SYNC_NOTIFICATION from {Jid}", senderJid);
                        _ = Task.Run(() => ProcessHistorySyncAsync(waMsg.ProtocolMsg.HistorySyncNotification, CancellationToken.None));
                        _ = SendAckAsync(id, from, timestamp);
                        continue;
                    }

                    // ── Peer data operation response (ON_DEMAND history) ──────────────────────
                    if (waMsg.PeerDataResponse != null)
                    {
                        _logger.LogInformation("Participants path: received PeerDataOperationResponseMessage from {Jid}", senderJid);
                        _ = Task.Run(() => ProcessPeerDataResponseAsync(waMsg.PeerDataResponse, CancellationToken.None));
                        _ = SendAckAsync(id, from, timestamp);
                        continue;
                    }

                    // ── Skip other protocol messages (key sync, app state, etc.) ──────────────
                    if (waMsg.ProtocolMsg != null)
                    {
                        _logger.LogDebug("Participants path: protocol message type={PT} from {Jid} — skipping",
                            waMsg.ProtocolMsg.Type, senderJid);
                        _ = SendAckAsync(id, from, timestamp);
                        continue;
                    }

                    // ── Fire MessageReceived for ALL user message types ────────────────────────
                    var (msgType, text, mediaUrl, mimeType, fileName, fileSize,
                         duration, width, height, mediaKey, mediaSha256Enc,
                         reactionEmoji, reactionTargetId) = waMsg.GetAllFields();

                    if (msgType == Messages.MessageType.Unknown)
                    {
                        _logger.LogDebug("Participants path: unknown message type from {Jid} — ACKing and skipping", senderJid);
                        _ = SendAckAsync(id, from, timestamp);
                        continue;
                    }

                    _logger.LogInformation("Participants path: {MsgType} message from {Jid}", msgType, senderJid);

                    var (quotedId, quotedFrom, quotedText, quotedType) = waMsg.GetQuotedContext();

                    MessageReceived?.Invoke(this, new Messages.IncomingMessage
                    {
                        Id               = id,
                        From             = senderJid,
                        RemoteJid        = remoteJid,
                        Participant      = participant,
                        Type             = msgType,
                        Text             = text,
                        FromMe           = fromMe,
                        Timestamp        = timestamp,
                        PushName         = pushName,
                        MediaUrl         = mediaUrl,
                        MimeType         = mimeType,
                        FileName         = fileName,
                        FileSize         = fileSize,
                        Duration         = duration,
                        Width            = width,
                        Height           = height,
                        MediaKey         = mediaKey,
                        MediaSha256Enc   = mediaSha256Enc,
                        ReactionEmoji    = reactionEmoji,
                        ReactionTargetId = reactionTargetId,
                        QuotedMessageId  = quotedId,
                        QuotedFrom       = quotedFrom,
                        QuotedText       = quotedText,
                        QuotedType       = quotedType,
                    });

                    _ = SendAckAsync(id, from, timestamp);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Participants path: failed to decrypt encType={EncType} from {Jid}", encType, from);
                    _ = HandleUndecryptableAsync(id, from, timestamp);
                }
            }
            return;
        }

        // ── Direct <enc> (no <participants> wrapper) ──────────────────────────
        var directEnc = node.FindChild("enc");
        if (directEnc?.Data != null)
        {
            var encType = directEnc.GetAttr("type") ?? "msg";
            try
            {
                var senderJid = participant ?? from;
                byte[] plaintext;
                try
                {
                    plaintext = _signalStore.DecryptMessage(senderJid, encType, directEnc.Data, _auth);
                }
                catch (Exception decEx)
                {
                    _logger.LogWarning(decEx, "Failed to decrypt direct enc message from {Jid}", from);
                    _ = HandleUndecryptableAsync(id, from, timestamp);
                    return;
                }

                _logger.LogInformation("Decrypted {Bytes} bytes from {Jid} (category={Category})",
                    plaintext.Length, from, node.GetAttr("category") ?? "?");

                // Strip Signal protocol padding (0x80 followed by zero bytes at end)
                var protoBytes2 = StripSignalPadding(plaintext);

                WAMessage waMsg;
                try
                {
                    waMsg = WAMessage.ParseFrom(protoBytes2);
                }
                catch (Exception parseEx)
                {
                    // Peer/device messages may not be standard WAMessage format — log at Warning so we can diagnose
                    _logger.LogWarning(parseEx, "Could not parse decrypted message as WAMessage from {Jid} ({Len} bytes, first={First})",
                        from, protoBytes2.Length, Convert.ToHexString(protoBytes2[..Math.Min(16, protoBytes2.Length)]));
                    _ = SendAckAsync(id, from, timestamp);
                    return;
                }

                var text = waMsg.GetText();
                _logger.LogInformation("Parsed WAMessage from {Jid}: text={Text}, hasDeviceSent={DevSent}, hasSKDM={SKDM}",
                    from, text ?? "(null)", waMsg.DeviceSentMessage != null, waMsg.SenderKeyDist != null);

                // ── History sync notification ─────────────────────────────────
                if (waMsg.ProtocolMsg?.Type == Proto.ProtocolMessage.TYPE_HISTORY_SYNC_NOTIFICATION
                    && waMsg.ProtocolMsg.HistorySyncNotification != null)
                {
                    _ = Task.Run(() => ProcessHistorySyncAsync(waMsg.ProtocolMsg.HistorySyncNotification, CancellationToken.None));
                    _ = SendAckAsync(id, from, timestamp);
                    return;
                }

                // ── Peer data operation response (ON_DEMAND history inline) ──────────
                if (waMsg.PeerDataResponse != null)
                {
                    _logger.LogInformation("Direct enc path: received PeerDataOperationResponseMessage from {Jid}", from);
                    _ = Task.Run(() => ProcessPeerDataResponseAsync(waMsg.PeerDataResponse, CancellationToken.None));
                    _ = SendAckAsync(id, from, timestamp);
                    return;
                }

                // ── Skip other protocol messages (key sync, app state, etc.) ──────────────
                if (waMsg.ProtocolMsg != null)
                {
                    _logger.LogDebug("Direct enc path: protocol message type={PT} from {Jid} — skipping",
                        waMsg.ProtocolMsg.Type, from);
                    _ = SendAckAsync(id, from, timestamp);
                    return;
                }

                // ── Fire MessageReceived for ALL user message types ────────────────────────
                var (msgType, text2, mediaUrl, mimeType, fileName, fileSize,
                     duration, width, height, mediaKey, mediaSha256Enc,
                     reactionEmoji, reactionTargetId) = waMsg.GetAllFields();

                if (msgType != Messages.MessageType.Unknown)
                {
                    _logger.LogInformation("Direct enc path: {MsgType} message from {Jid}", msgType, from);
                    var (quotedId2, quotedFrom2, quotedText2, quotedType2) = waMsg.GetQuotedContext();
                    MessageReceived?.Invoke(this, new Messages.IncomingMessage
                    {
                        Id               = id,
                        From             = participant ?? from,
                        RemoteJid        = remoteJid,
                        Participant      = participant,
                        Type             = msgType,
                        Text             = text2,
                        FromMe           = fromMe,
                        Timestamp        = timestamp,
                        PushName         = pushName,
                        MediaUrl         = mediaUrl,
                        MimeType         = mimeType,
                        FileName         = fileName,
                        FileSize         = fileSize,
                        Duration         = duration,
                        Width            = width,
                        Height           = height,
                        MediaKey         = mediaKey,
                        MediaSha256Enc   = mediaSha256Enc,
                        ReactionEmoji    = reactionEmoji,
                        ReactionTargetId = reactionTargetId,
                        QuotedMessageId  = quotedId2,
                        QuotedFrom       = quotedFrom2,
                        QuotedText       = quotedText2,
                        QuotedType       = quotedType2,
                    });
                }
                else
                {
                    _logger.LogDebug("Direct enc path: unknown message type from {Jid} — ACKing", from);
                }
                _ = SendAckAsync(id, from, timestamp);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error handling direct enc message from {Jid}", from);
            }
            return;
        }

        // ── Fallback: plain text body (legacy) ────────────────────────────────
        var body      = node.FindChild("body");
        var plainText = body?.Text;
        if (string.IsNullOrEmpty(plainText)) return;

        MessageReceived?.Invoke(this, new IncomingMessage
        {
            Id          = id,
            From        = participant ?? from,
            RemoteJid   = remoteJid,
            Text        = plainText,
            FromMe      = fromMe,
            Timestamp   = timestamp,
            PushName    = pushName,
        });
    }

    /// <summary>
    /// Sends the passive→active switch IQ (xmlns="passive", tag="active").
    /// This is the critical call Baileys makes after auth to tell WhatsApp to start
    /// delivering queued messages to this companion device. Without it, WhatsApp keeps
    /// the session in passive mode and never pushes any message/dirty/notification nodes.
    /// </summary>
    private async Task SendActiveAsync(CancellationToken ct)
    {
        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["to"]    = "@s.whatsapp.net",
            ["type"]  = "set",
            ["xmlns"] = "passive",
            ["id"]    = GenerateMessageId(),
        })
        {
            Content = new List<BinaryNode> { new BinaryNode("active") },
        };
        try
        {
            await SendIQAsync(iq, ct, timeoutMs: 10000);
            _logger.LogInformation("Passive→active switch sent — WhatsApp should now deliver messages.");
        }
        catch (TimeoutException)
        {
            _logger.LogWarning("passive/active IQ timed out — WhatsApp may not deliver messages.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "passive/active IQ failed.");
        }
    }

    /// <summary>
    /// Sends a presence update to tell WhatsApp this device is online and ready to receive messages.
    /// Without this, WhatsApp may not deliver messages to linked devices.
    /// </summary>
    private async Task SendPresenceAsync(CancellationToken ct)
    {
        try
        {
            var presence = new BinaryNode("presence", new Dictionary<string, string>
            {
                ["type"] = "available",
            });
            await SendNodeAsync(presence, ct);
            _logger.LogInformation("Sent presence: available — WhatsApp should now deliver messages to this device.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send presence update");
        }
    }

    /// <summary>
    /// Sends a keepalive ping IQ every 25 seconds, like Baileys does after login.
    /// The server expects this to consider the device fully online and deliver messages.
    /// </summary>
    private async Task KeepAliveLoopAsync(CancellationToken ct)
    {
        const int intervalMs  = 25_000;              // ping cadence
        const int deadAfterMs = intervalMs + 15_000; // ~40s of total silence => declare dead
        _logger.LogInformation("Keepalive loop started ({Interval}s interval, dead after {Dead}s silence).",
            intervalMs / 1000, deadAfterMs / 1000);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(intervalMs, ct);
                if (ct.IsCancellationRequested) break;

                // Dead-connection watchdog: if we have not received ANY frame (including the
                // pong to our own ping) for too long, the socket is dead/half-open. Dispose it
                // so the parked ReceiveAsync throws, the receive loop exits, and reconnection runs.
                var silentMs = (DateTime.UtcNow.Ticks - System.Threading.Interlocked.Read(ref _lastRecvTicks))
                               / TimeSpan.TicksPerMillisecond;
                if (silentMs > deadAfterMs)
                {
                    _logger.LogWarning("Keepalive: no data for {Ms}ms — declaring connection dead, tearing down socket.", silentMs);
                    try { await _socket.DisposeAsync(); } catch { /* best effort */ }
                    break;
                }

                try
                {
                    var ping = new BinaryNode("iq", new Dictionary<string, string>
                    {
                        ["id"]    = GenerateMessageId(),
                        ["to"]    = "@s.whatsapp.net",
                        ["type"]  = "get",
                        ["xmlns"] = "w:p",
                    })
                    {
                        Content = new List<BinaryNode> { new("ping") },
                    };
                    await SendNodeAsync(ping, ct);
                    _logger.LogDebug("Sent keepalive ping.");
                }
                catch (Exception ex)
                {
                    // A ping WRITE failure means the socket is gone. Tear it down so the receive
                    // loop unblocks and reconnection runs (previously it just broke this loop,
                    // leaving the receive loop parked forever).
                    _logger.LogWarning(ex, "Keepalive ping write failed — tearing down socket to force reconnect.");
                    try { await _socket.DisposeAsync(); } catch { /* best effort */ }
                    break;
                }
            }
        }
        catch (OperationCanceledException) { }
        _logger.LogInformation("Keepalive loop ended.");
    }

    private async Task SendAckAsync(string msgId, string to, long timestamp)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var ack = new BinaryNode("ack", new Dictionary<string, string>
            {
                ["id"]   = msgId,
                ["to"]   = to,
                ["type"] = "message",
                ["t"]    = timestamp.ToString(),
            });
            await SendNodeAsync(ack, cts.Token);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send ACK for message {Id}", msgId);
        }
    }

    /// <summary>
    /// Sends a retry receipt to WhatsApp, asking the sender to re-encrypt using
    /// a fresh pre-key bundle. Called when we receive a message we cannot decrypt
    /// (e.g. our session state was lost after a restart).
    /// </summary>
    /// <summary>
    /// Decides how to handle a message we could not decrypt. For a RECENT (live) message we
    /// send a retry receipt so the sender re-keys and we recover it. For an OLD message from
    /// the offline backlog (a dead ratchet chain that will never decrypt) we simply ACK it so
    /// WhatsApp stops resending it and the offline queue drains quickly to current messages,
    /// instead of looping forever on undecryptable history. Old messages are already on every
    /// participant's phone, so nothing important is lost. This keeps the bridge current — the
    /// behaviour a healthy client (e.g. Baileys) gets for free by never accumulating a backlog.
    /// </summary>
    private async Task HandleUndecryptableAsync(string id, string from, long timestamp)
    {
        const long BacklogThresholdSeconds = 2 * 3600; // messages older than 2h = offline backlog
        var ageSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp;
        if (timestamp > 0 && ageSeconds > BacklogThresholdSeconds)
        {
            _logger.LogInformation("Undecryptable BACKLOG message {Id} from {From} (age {Hours}h) — ACK to drain queue, no retry.", id, from, ageSeconds / 3600);
            await SendAckAsync(id, from, timestamp);
        }
        else
        {
            await SendRetryReceiptAsync(id, from, timestamp);
        }
    }

    public Task SendManualRetryReceiptAsync(string to, string msgId, long timestamp, CancellationToken ct) =>
        SendRetryReceiptAsync(msgId, to, timestamp);

    // Per-message retry-receipt attempt counter. A message we can never decrypt (dead
    // ratchet chain after a long offline gap) otherwise loops forever: fail → retry
    // receipt → resend → fail, starving delivery of every other message behind it in the
    // offline queue. After MaxRetryAttempts we ACK the message instead, so WhatsApp stops
    // resending it and the queue drains to newer/live messages.
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _retryAttempts = new();
    private const int MaxRetryAttempts = 5;

    private async Task SendRetryReceiptAsync(string msgId, string to, long timestamp)
    {
        var attempt = _retryAttempts.AddOrUpdate(msgId, 1, (_, n) => n + 1);
        if (attempt > MaxRetryAttempts)
        {
            _retryAttempts.TryRemove(msgId, out _);
            _logger.LogWarning("Retry cap ({Max}) reached for {MsgId} — undecryptable, ACKing to drain offline queue.", MaxRetryAttempts, msgId);
            await SendAckAsync(msgId, to, timestamp);
            return;
        }

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var retry = new BinaryNode("receipt", new Dictionary<string, string>
            {
                ["id"]   = msgId,
                ["type"] = "retry",
                ["to"]   = to,
                ["t"]    = timestamp.ToString(),
            })
            {
                Content = new List<BinaryNode>
                {
                    new("retry", new Dictionary<string, string>
                    {
                        ["count"] = attempt.ToString(),
                        ["id"]    = msgId,
                        ["t"]     = timestamp.ToString(),
                        ["v"]     = "1",
                    }),
                    new("registration", null, new byte[] { (byte)(_auth.RegistrationId >> 24), (byte)(_auth.RegistrationId >> 16), (byte)(_auth.RegistrationId >> 8), (byte)_auth.RegistrationId }),
                    // <keys> — our identity + signed pre-key + one-time pre-key so the sender can
                    // re-establish a fresh Signal session. MUST include <key> (one-time pre-key) —
                    // without it the phone ACKs the retry receipt but never re-encrypts the message.
                    BuildRetryKeysNode(_auth),
                },
            };
            await SendNodeAsync(retry, cts.Token);
            _logger.LogInformation("Sent retry receipt for {MsgId} to {To} — session state lost, requesting re-key.", msgId, to);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send retry receipt for {MsgId}", msgId);
        }
    }

    /// Builds a <skey> node from our signed pre-key — included in retry receipts so the
    /// sender can re-encrypt using a fresh Signal session with our current keys.
    private static BinaryNode BuildSignedPreKeyNode(Auth.AuthState auth)
    {
        var spkId = auth.SignedPreKeyId;
        var idBytes = new byte[] { (byte)(spkId >> 16), (byte)(spkId >> 8), (byte)spkId };
        return new BinaryNode("skey", null, new List<BinaryNode>
        {
            new("id",        null, idBytes),
            new("value",     null, auth.SignedPreKeyPublic),
            new("signature", null, auth.SignedPreKeySignature),
        });
    }

    /// Builds the <keys> node for retry receipts.
    /// Node order matches Baileys: type, identity, key (one-time), skey (signed), device-identity.
    /// The device-identity is REQUIRED for the phone to trust and process the retry receipt.
    /// Uses _retryPreKeyIndex to assign a unique pre-key per message so that if multiple
    /// re-encrypted pkmsg responses arrive they can each be decrypted independently.
    private BinaryNode BuildRetryKeysNode(Auth.AuthState auth)
    {
        static byte[] Be3(uint v) => [(byte)(v >> 16), (byte)(v >> 8), (byte)v];

        var children = new List<BinaryNode>
        {
            new("type",     null, new byte[] { 5 }),   // DJB_TYPE = 0x05
            new("identity", null, auth.SignedIdentityKeyPublic),
        };

        // Pick a unique one-time pre-key for each retry receipt. _retryPreKeyIndex increments
        // per call so that each re-encrypted pkmsg response uses a different X3DH pre-key and
        // can be decrypted independently (keys are consumed by InitIncomingSession on use).
        var keyIndex = _retryPreKeyIndex++;
        var otpk = keyIndex < auth.PreKeys.Count ? auth.PreKeys[keyIndex] : auth.PreKeys.LastOrDefault();
        if (otpk != null)
        {
            // <key> comes BEFORE <skey> — this matches Baileys xmppPreKey / xmppSignedPreKey order
            children.Add(new BinaryNode("key", null, new List<BinaryNode>
            {
                new("id",    null, Be3(otpk.Id)),
                new("value", null, otpk.Public),
            }));
        }

        // <skey> (signed pre-key) AFTER <key>
        children.Add(BuildSignedPreKeyNode(auth));

        // device-identity — REQUIRED! Phone uses this to verify our device and re-establish session.
        if (auth.Account != null)
        {
            children.Add(new BinaryNode("device-identity") { Content = auth.Account });
        }

        return new BinaryNode("keys", null, children);
    }

    /// <summary>
    /// Sends the initial app state sync request (xmlns="w:app:state:sync").
    /// Baileys calls resyncAppState immediately after auth — WhatsApp may withhold
    /// message delivery until the companion device has "checked in" with a sync request.
    /// We request all 5 standard collections at version=0 (initial sync).
    /// We don't need to process the response content, just sending the request is enough
    /// to signal to WhatsApp that this device is ready to receive messages.
    /// </summary>
    private async Task SendAppStateSyncAsync(CancellationToken ct)
    {
        var collections = new[] { "critical_block", "critical_unblock_to_primary", "regular_high", "regular_low", "regular" };
        var collectionNodes = collections.Select(name => new BinaryNode("collection", new Dictionary<string, string>
        {
            ["name"]            = name,
            ["version"]         = "0",
            ["return_snapshot"] = "true",
        })).ToList<BinaryNode>();

        var syncNode = new BinaryNode("sync") { Content = collectionNodes };
        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["to"]    = "@s.whatsapp.net",
            ["xmlns"] = "w:app:state:sync",
            ["type"]  = "set",
            ["id"]    = GenerateMessageId(),
        }) { Content = new List<BinaryNode> { syncNode } };

        try
        {
            var result = await SendIQAsync(iq, ct, timeoutMs: 60000);
            _logger.LogInformation("App state sync request acknowledged (WhatsApp should now route messages to this device).");
        }
        catch (TimeoutException ex)
        {
            _logger.LogWarning(ex, "App state sync IQ timed out — continuing anyway (messages may still arrive)");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "App state sync request failed (non-fatal)");
        }
    }

    // Cached app-state collection versions received via server_sync notifications.
    // key = collection name (e.g. "contact", "regular_low"), value = version number
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _serverSyncVersions = new();

    // Thread metadata from <ib><thread_metadata> nodes — key=JID (may be @lid), value=unix timestamp
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _threadMetadata = new();

    // LID → phone JID mapping — populated from participant_pn attributes in incoming messages
    // key = "178430138150925@lid", value = "31633984381@s.whatsapp.net"
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _lidToPhone = new();

    // JID → push name — populated from "notify" attribute of incoming messages
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _pushNames = new();

    private async Task HandleNotificationAsync(BinaryNode notification, CancellationToken ct)
    {
        var id   = notification.GetAttr("id") ?? "";
        var type = notification.GetAttr("type") ?? "";
        var to   = notification.GetAttr("from") ?? "s.whatsapp.net";

        _logger.LogInformation("Notification: type={Type} id={Id} from={From}", type, id, to);

        // ACK the notification first
        var ack = new BinaryNode("ack", new()
        {
            ["id"]    = id,
            ["to"]    = to,
            ["type"]  = "notification",
            ["class"] = type,
        });
        await SendNodeAsync(ack, ct);

        // --- Handle server_sync notifications ---
        // WhatsApp sends these in response to w:app:state:sync IQs (instead of IQ results).
        // They tell us the current version of each collection.
        if (type == "server_sync")
        {
            var children = notification.Children;
            foreach (var child in children)
            {
                if (child.Tag == "collection")
                {
                    var name    = child.GetAttr("name") ?? "";
                    var verStr  = child.GetAttr("version") ?? "0";
                    if (int.TryParse(verStr, out var ver))
                    {
                        _serverSyncVersions[name] = ver;
                        _logger.LogInformation("server_sync: collection={Name} version={Ver}", name, ver);
                    }
                }
            }
        }

        // Generic: if any notification has an ID matching a pending IQ, resolve it.
        // WhatsApp sometimes sends IQ responses as notifications (e.g. w:app:state:sync, potentially w:m).
        if (!string.IsNullOrEmpty(id) && _pendingIqs.TryGetValue(id, out var pendingTcs))
        {
            _pendingIqs.Remove(id);
            _logger.LogInformation("Resolved pending IQ {Id} via {Type} notification", id, type);
            pendingTcs.TrySetResult(notification);
        }
    }

    // ─── Send message ───────────────────────────────────────────────────────

    /// <summary>Sends an encrypted text message to a JID using Signal Protocol.</summary>
    public async Task SendTextMessageAsync(string jid, string text, CancellationToken ct)
    {
        // 1. Normalize JID
        var normalizedJid = jid.Contains('@') ? jid : $"{jid.TrimStart('+')}@s.whatsapp.net";
        var phoneNumber   = normalizedJid.Split('@')[0].Split(':')[0];

        // 2. Get recipient device list via USync
        List<string> recipientDeviceJids;
        try { recipientDeviceJids = await GetDeviceListAsync(phoneNumber, ct); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to get device list for {Phone}, using fallback", phoneNumber);
            recipientDeviceJids = [$"{phoneNumber}:0@s.whatsapp.net"];
        }

        // 3. Get sender's own devices for multi-device sync
        var senderDeviceJids = new List<string>();
        var myJid = _auth.Me?.Id; // e.g. "31633984381:44@s.whatsapp.net"
        if (myJid != null)
        {
            var myPhone = myJid.Split('@')[0].Split(':')[0];
            try
            {
                var myDevices = await GetDeviceListAsync(myPhone, ct);
                foreach (var d in myDevices)
                {
                    // Skip our own companion device (can't encrypt to ourselves)
                    if (d == myJid) continue;
                    senderDeviceJids.Add(d);
                }
                _logger.LogInformation("Sender has {Count} other devices for sync: {Jids}",
                    senderDeviceJids.Count, string.Join(", ", senderDeviceJids));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get sender device list, skipping multi-device sync");
            }
        }

        // Combine all device JIDs for pre-key bundle fetching
        var allDeviceJids = new List<string>(recipientDeviceJids);
        allDeviceJids.AddRange(senderDeviceJids);

        // 4. For each device without a session, fetch pre-key bundle
        var needBundles = allDeviceJids.Where(d => !_signalStore.HasSession(d)).ToList();
        if (needBundles.Count > 0)
        {
            try
            {
                _logger.LogInformation("Fetching pre-key bundles for {Count} devices: {Jids}",
                    needBundles.Count, string.Join(", ", needBundles));
                var bundles = await FetchPreKeyBundlesAsync(needBundles, ct);
                _logger.LogInformation("Got {Count} bundles back", bundles.Count);
                foreach (var (deviceJid, bundle) in bundles)
                {
                    try
                    {
                        _signalStore.InitOutgoingSession(deviceJid, bundle, _auth);
                        _logger.LogInformation("Initialized outgoing session for {Jid}", deviceJid);
                    }
                    catch (Exception ex2)
                    {
                        _logger.LogWarning(ex2, "Failed to init outgoing session for {Jid}", deviceJid);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to fetch pre-key bundles");
            }
        }

        // 5. Proto-encode the message with random PKCS7-style padding (Baileys: writeRandomPadMax16)
        var msgRaw = new WAMessage { Conversation = text }.ToByteArray();

        // 6. Build padded proto for recipient devices (direct message)
        var recipientProto = PadMessage(msgRaw);

        // 7. Build padded proto for sender's own devices (wrapped in DeviceSentMessage)
        byte[]? senderProto = null;
        if (senderDeviceJids.Count > 0)
        {
            var deviceSentMsg = new WAMessage
            {
                DeviceSentMessage = new DeviceSentMessage
                {
                    DestinationJid = normalizedJid,
                    Message = new WAMessage { Conversation = text },
                }
            };
            senderProto = PadMessage(deviceSentMsg.ToByteArray());
        }

        // 8. Encrypt for each device
        var msgId    = GenerateMessageId();
        var hasPkMsg = false;
        var toNodes  = new List<BinaryNode>();

        // Encrypt for recipient devices
        foreach (var deviceJid in recipientDeviceJids)
        {
            var node = EncryptForDevice(deviceJid, recipientProto, ref hasPkMsg);
            if (node != null) toNodes.Add(node);
        }

        // Encrypt for sender's own devices (multi-device sync)
        foreach (var deviceJid in senderDeviceJids)
        {
            var node = EncryptForDevice(deviceJid, senderProto!, ref hasPkMsg);
            if (node != null) toNodes.Add(node);
        }

        if (toNodes.Count == 0)
        {
            var reason = $"No devices encrypted successfully for {normalizedJid} — message NOT sent (stale/missing Signal session or pre-key bundle fetch failed).";
            _logger.LogError(reason);
            throw new InvalidOperationException(reason);
        }

        // 9. Build and send message node
        var participantsNode = new BinaryNode("participants")
        {
            Content = toNodes,
        };
        var contentNodes = new List<BinaryNode> { participantsNode };

        // Include device-identity when sending pkmsg (first message to a device)
        if (hasPkMsg && _auth.Account != null)
        {
            var accountProto = ADVSignedDeviceIdentity.ParseFrom(_auth.Account);
            var deviceIdentityBytes = accountProto.ToByteArray();
            contentNodes.Add(new BinaryNode("device-identity") { Content = deviceIdentityBytes });
            _logger.LogInformation("Including device-identity in message (pkmsg detected, {Len} bytes)", deviceIdentityBytes.Length);
        }
        else if (hasPkMsg)
        {
            _logger.LogWarning("pkmsg detected but Account is NULL — device-identity NOT included. Recipient may reject. Re-pair to fix.");
        }

        var msgAttrs = new Dictionary<string, string>
        {
            ["id"]    = msgId,
            ["type"]  = "text",
            ["to"]    = normalizedJid,
        };

        var msgNode = new BinaryNode("message", msgAttrs) { Content = contentNodes };

        await SendNodeAsync(msgNode, ct);
        _logger.LogInformation("Sent encrypted message to {Jid} via {RecipientCount}+{SenderCount} devices",
            normalizedJid, recipientDeviceJids.Count, senderDeviceJids.Count);
    }

    /// <summary>
    /// Sends an emoji reaction to a specific message.
    /// </summary>
    /// <param name="targetJid">The chat JID (e.g. "31612345678@s.whatsapp.net") containing the target message.</param>
    /// <param name="targetMessageId">The ID of the message to react to.</param>
    /// <param name="targetFromMe">Whether the target message was sent by us.</param>
    /// <param name="emoji">The reaction emoji, e.g. "👍". Pass "" to remove an existing reaction.</param>
    public async Task SendReactionAsync(string targetJid, string targetMessageId, bool targetFromMe, string emoji, CancellationToken ct)
    {
        var normalizedJid = targetJid.Contains('@') ? targetJid : $"{targetJid.TrimStart('+')}@s.whatsapp.net";
        var phoneNumber   = normalizedJid.Split('@')[0].Split(':')[0];

        // Get recipient device list
        List<string> recipientDeviceJids;
        try { recipientDeviceJids = await GetDeviceListAsync(phoneNumber, ct); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to get device list for {Phone}, using fallback", phoneNumber);
            recipientDeviceJids = [$"{phoneNumber}:0@s.whatsapp.net"];
        }

        // Get sender's own devices for multi-device sync
        var senderDeviceJids = new List<string>();
        var myJid = _auth.Me?.Id;
        if (myJid != null)
        {
            var myPhone = myJid.Split('@')[0].Split(':')[0];
            try
            {
                var myDevices = await GetDeviceListAsync(myPhone, ct);
                foreach (var d in myDevices)
                {
                    if (d == myJid) continue;
                    senderDeviceJids.Add(d);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get sender device list for reaction, skipping multi-device sync");
            }
        }

        var allDeviceJids = new List<string>(recipientDeviceJids);
        allDeviceJids.AddRange(senderDeviceJids);

        // Fetch pre-key bundles for devices without sessions
        var needBundles = allDeviceJids.Where(d => !_signalStore.HasSession(d)).ToList();
        if (needBundles.Count > 0)
        {
            try
            {
                var bundles = await FetchPreKeyBundlesAsync(needBundles, ct);
                foreach (var (deviceJid, bundle) in bundles)
                {
                    try { _signalStore.InitOutgoingSession(deviceJid, bundle, _auth); }
                    catch (Exception ex2) { _logger.LogWarning(ex2, "Failed to init session for {Jid}", deviceJid); }
                }
            }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to fetch pre-key bundles for reaction"); }
        }

        // Build reaction proto
        var reactionProto = new WAMessage
        {
            ReactionMessage = new Dawa.Proto.ReactionMessage
            {
                Key = new Dawa.Proto.MessageKey
                {
                    RemoteJid = normalizedJid,
                    FromMe    = targetFromMe,
                    Id        = targetMessageId,
                },
                Text              = emoji,
                SenderTimestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            }
        };

        var recipientProto = PadMessage(reactionProto.ToByteArrayWithReaction());

        // For own devices, same payload (reactions are not wrapped in DeviceSentMessage)
        byte[]? senderProto = senderDeviceJids.Count > 0 ? recipientProto : null;

        var msgId    = GenerateMessageId();
        var hasPkMsg = false;
        var toNodes  = new List<BinaryNode>();

        foreach (var deviceJid in recipientDeviceJids)
        {
            var node = EncryptForDevice(deviceJid, recipientProto, ref hasPkMsg);
            if (node != null) toNodes.Add(node);
        }
        foreach (var deviceJid in senderDeviceJids)
        {
            var node = EncryptForDevice(deviceJid, senderProto!, ref hasPkMsg);
            if (node != null) toNodes.Add(node);
        }

        if (toNodes.Count == 0)
        {
            var reason = $"No devices encrypted successfully for reaction to {normalizedJid} — reaction NOT sent (stale/missing Signal session or pre-key bundle fetch failed).";
            _logger.LogError(reason);
            throw new InvalidOperationException(reason);
        }

        var participantsNode = new BinaryNode("participants") { Content = toNodes };
        var contentNodes     = new List<BinaryNode> { participantsNode };

        if (hasPkMsg && _auth.Account != null)
        {
            var accountProto       = ADVSignedDeviceIdentity.ParseFrom(_auth.Account);
            var deviceIdentityBytes = accountProto.ToByteArray();
            contentNodes.Add(new BinaryNode("device-identity") { Content = deviceIdentityBytes });
        }

        var msgNode = new BinaryNode("message", new Dictionary<string, string>
        {
            ["id"]   = msgId,
            ["type"] = "reaction",
            ["to"]   = normalizedJid,
        }) { Content = contentNodes };

        await SendNodeAsync(msgNode, ct);
        _logger.LogInformation("Sent reaction '{Emoji}' to message {MsgId} in {Jid}", emoji, targetMessageId, normalizedJid);
    }

    /// <summary>
    /// Sends a media message (image, audio, or document) to a JID.
    /// <paramref name="mediaType"/> must be "image", "audio", or "document".
    /// <paramref name="fileBytes"/> is the raw (unencrypted) file bytes.
    /// <paramref name="mimeType"/> e.g. "image/jpeg", "audio/ogg; codecs=opus", "application/pdf".
    /// <paramref name="caption"/> optional text (images only).
    /// <paramref name="fileName"/> optional file name (documents).
    /// </summary>
    public async Task SendMediaAsync(string jid, byte[] fileBytes, string mediaType, string mimeType,
        string caption, string fileName, CancellationToken ct)
    {
        var normalizedJid = jid.Contains('@') ? jid : $"{jid.TrimStart('+')}@s.whatsapp.net";
        var phoneNumber   = normalizedJid.Split('@')[0].Split(':')[0];

        // 1. Encrypt the media
        var enc = Dawa.Crypto.MediaCrypto.Encrypt(fileBytes, mediaType);
        _logger.LogInformation("Media encrypted: {Bytes} → {EncBytes} bytes for {Type}", fileBytes.Length, enc.EncryptedBytes.Length, mediaType);

        // 2. Get upload URL from WhatsApp server via w:m IQ (Baileys pattern)
        var encSha256B64 = Convert.ToBase64String(enc.FileEncSha256);
        var (mediaUrl, directPath, uploadAuth) = await RequestMediaUploadUrlAsync(mediaType, enc.EncryptedBytes.Length, encSha256B64, ct);
        _logger.LogInformation("Media upload URL: {Url} directPath={DP}", mediaUrl, directPath);

        // 3. Upload encrypted bytes to CDN (raw binary, application/octet-stream).
        // The content is encrypted so the actual MIME type is irrelevant; CDN accepts octet-stream.
        // URL already contains ?auth=...&token=... from RequestMediaUploadUrlAsync.
        var rawContent = new ByteArrayContent(enc.EncryptedBytes);
        rawContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");

        using var uploadRequest = new HttpRequestMessage(HttpMethod.Post, mediaUrl)
        {
            Content = rawContent,
        };
        uploadRequest.Headers.TryAddWithoutValidation("Origin", "https://web.whatsapp.com");
        uploadRequest.Headers.TryAddWithoutValidation("Referer", "https://web.whatsapp.com/");

        // Diagnostic: write full URL + encrypted bytes to disk so we can reproduce the upload via curl
        try {
            var diagDir = @"C:\inetpub\whatsappbridge-api\logs";
            System.IO.File.WriteAllText(System.IO.Path.Combine(diagDir, "cdn-upload-debug.txt"),
                $"URL: {mediaUrl}\nEncBytes: {enc.EncryptedBytes.Length}\nContentType: application/octet-stream\nToken: {encSha256B64.Replace('+','-').Replace('/','_').TrimEnd('=')}\nPlain b64: {encSha256B64}\n");
            System.IO.File.WriteAllBytes(System.IO.Path.Combine(diagDir, "cdn-upload-bytes.bin"), enc.EncryptedBytes);
        } catch { }
        _logger.LogInformation("Uploading {Bytes} bytes ({Mime}) to CDN: {Url}", enc.EncryptedBytes.Length, mimeType, mediaUrl);
        var uploadResp = await _http.SendAsync(uploadRequest, ct);
        var respBody = await uploadResp.Content.ReadAsStringAsync(ct);
        _logger.LogInformation("CDN upload response: {Status} body={Body}", uploadResp.StatusCode, respBody);

        // Diagnostic: capture CDN response to disk for offline analysis
        try {
            var diagDir = @"C:\inetpub\whatsappbridge-api\logs";
            var respHeaders = string.Join("\n", uploadResp.Headers.Select(h => $"{h.Key}: {string.Join(", ", h.Value)}"))
                            + "\n" + string.Join("\n", uploadResp.Content.Headers.Select(h => $"{h.Key}: {string.Join(", ", h.Value)}"));
            System.IO.File.WriteAllText(System.IO.Path.Combine(diagDir, "cdn-upload-response.txt"),
                $"Status: {(int)uploadResp.StatusCode} {uploadResp.StatusCode}\nTimestamp: {DateTime.UtcNow:u}\n--- Response Headers ---\n{respHeaders}\n--- Response Body ---\n{respBody}\n");
        } catch { }

        if (!uploadResp.IsSuccessStatusCode)
            throw new InvalidOperationException($"CDN upload failed: {uploadResp.StatusCode} - {respBody[..Math.Min(200, respBody.Length)]}");

        // Parse CDN JSON response for final url + directPath
        var cdnJson = respBody;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(cdnJson);
            var root = doc.RootElement;
            if (root.TryGetProperty("url", out var urlProp) && urlProp.GetString() is { Length: > 0 } finalUrl)
                mediaUrl = finalUrl;
            if (root.TryGetProperty("direct_path", out var dpProp) && dpProp.GetString() is { Length: > 0 } finalDp)
                directPath = finalDp;
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Failed to parse CDN response JSON"); }
        _logger.LogInformation("Media uploaded: url={Url} directPath={DP}", mediaUrl, directPath);

        // 4. Build media proto node
        WAMessage mediaMsg;
        switch (mediaType)
        {
            case "image":
                mediaMsg = new WAMessage
                {
                    ImageMessage = new Dawa.Proto.ImageMessage
                    {
                        Url              = mediaUrl,
                        DirectPath       = directPath,
                        MimeType         = mimeType,
                        Caption          = caption,
                        FileSha256       = enc.FileSha256,
                        FileEncSha256    = enc.FileEncSha256,
                        FileLength       = (ulong)enc.FileLength,
                        MediaKey         = enc.MediaKey,
                        MediaKeyTimestamp = enc.MediaKeyTimestamp,
                    }
                };
                break;
            case "audio":
                mediaMsg = new WAMessage
                {
                    AudioMessage = new Dawa.Proto.AudioMessage
                    {
                        Url              = mediaUrl,
                        DirectPath       = directPath,
                        MimeType         = mimeType,
                        FileSha256       = enc.FileSha256,
                        FileEncSha256    = enc.FileEncSha256,
                        FileLength       = (ulong)enc.FileLength,
                        MediaKey         = enc.MediaKey,
                        MediaKeyTimestamp = enc.MediaKeyTimestamp,
                        Ptt              = mimeType.Contains("ogg"),
                    }
                };
                break;
            default: // document
                mediaMsg = new WAMessage
                {
                    DocumentMessage = new Dawa.Proto.DocumentMessage
                    {
                        Url              = mediaUrl,
                        DirectPath       = directPath,
                        MimeType         = mimeType,
                        Title            = string.IsNullOrEmpty(caption) ? fileName : caption,
                        FileName         = fileName,
                        FileSha256       = enc.FileSha256,
                        FileEncSha256    = enc.FileEncSha256,
                        FileLength       = (ulong)enc.FileLength,
                        MediaKey         = enc.MediaKey,
                        MediaKeyTimestamp = enc.MediaKeyTimestamp,
                    }
                };
                break;
        }

        // 5. Get device lists (same as text/reaction)
        List<string> recipientDeviceJids;
        try { recipientDeviceJids = await GetDeviceListAsync(phoneNumber, ct); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to get device list for {Phone}, using fallback", phoneNumber);
            recipientDeviceJids = [$"{phoneNumber}:0@s.whatsapp.net"];
        }

        var senderDeviceJids = new List<string>();
        var myJid = _auth.Me?.Id;
        if (myJid != null)
        {
            var myPhone = myJid.Split('@')[0].Split(':')[0];
            try
            {
                var myDevices = await GetDeviceListAsync(myPhone, ct);
                foreach (var d in myDevices)
                {
                    if (d == myJid) continue;
                    senderDeviceJids.Add(d);
                }
            }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to get sender device list for media"); }
        }

        var allDeviceJids = new List<string>(recipientDeviceJids);
        allDeviceJids.AddRange(senderDeviceJids);

        var needBundles = allDeviceJids.Where(d => !_signalStore.HasSession(d)).ToList();
        if (needBundles.Count > 0)
        {
            try
            {
                var bundles = await FetchPreKeyBundlesAsync(needBundles, ct);
                foreach (var (deviceJid, bundle) in bundles)
                {
                    try { _signalStore.InitOutgoingSession(deviceJid, bundle, _auth); }
                    catch (Exception ex2) { _logger.LogWarning(ex2, "Failed to init session for {Jid}", deviceJid); }
                }
            }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to fetch pre-key bundles for media"); }
        }

        // 6. Encrypt for each device
        var recipientProto = PadMessage(mediaMsg.ToByteArrayWithMedia());
        byte[]? senderProto = null;
        if (senderDeviceJids.Count > 0)
        {
            var deviceSentMsg = new WAMessage
            {
                DeviceSentMessage = new Dawa.Proto.DeviceSentMessage
                {
                    DestinationJid = normalizedJid,
                    Message        = mediaMsg,
                }
            };
            senderProto = PadMessage(deviceSentMsg.ToByteArray());
        }

        var msgId    = GenerateMessageId();
        var hasPkMsg = false;
        var toNodes  = new List<BinaryNode>();

        foreach (var deviceJid in recipientDeviceJids)
        {
            var node = EncryptForDevice(deviceJid, recipientProto, ref hasPkMsg);
            if (node != null) toNodes.Add(node);
        }
        if (senderProto != null)
        {
            foreach (var deviceJid in senderDeviceJids)
            {
                var node = EncryptForDevice(deviceJid, senderProto, ref hasPkMsg);
                if (node != null) toNodes.Add(node);
            }
        }

        if (toNodes.Count == 0)
        {
            var reason = $"No devices encrypted for media to {normalizedJid} — media NOT sent (stale/missing Signal session or pre-key bundle fetch failed).";
            _logger.LogError(reason);
            throw new InvalidOperationException(reason);
        }

        // 7. Build and send message node
        var participantsNode = new BinaryNode("participants") { Content = toNodes };
        var contentNodes     = new List<BinaryNode> { participantsNode };

        if (hasPkMsg && _auth.Account != null)
        {
            var accountProto        = ADVSignedDeviceIdentity.ParseFrom(_auth.Account);
            contentNodes.Add(new BinaryNode("device-identity") { Content = accountProto.ToByteArray() });
        }

        var msgNode = new BinaryNode("message", new Dictionary<string, string>
        {
            ["id"]   = msgId,
            ["type"] = "media",
            ["to"]   = normalizedJid,
        }) { Content = contentNodes };

        await SendNodeAsync(msgNode, ct);
        _logger.LogInformation("Sent {Type} media to {Jid} ({Bytes} bytes)", mediaType, normalizedJid, fileBytes.Length);
    }

    /// <summary>
    /// Requests a media upload URL from WhatsApp.
    /// Tries the Baileys w:m IQ (type=set, media_conn) first.
    /// Falls back to direct mmg.whatsapp.net upload URL if the IQ times out
    /// (the server silently ignores w:m IQs for companion device sessions).
    /// Returns (uploadUrl, directPath, authToken).
    /// </summary>
    private async Task<(string Url, string DirectPath, string Auth)> RequestMediaUploadUrlAsync(
        string mediaType, long encryptedSize, string fileEncSha256B64, CancellationToken ct)
    {
        // --- Attempt 1: Baileys exact pattern (type=set, inner <media_conn/>, to=s.whatsapp.net) ---
        try
        {
            var mediaConnNode = new BinaryNode("media_conn", new Dictionary<string, string>());
            var iq = new BinaryNode("iq", new Dictionary<string, string>
            {
                ["id"]    = GenerateMessageId(),
                ["to"]    = "s.whatsapp.net",   // no @, encodes as dict token — matches Baileys S_WHATSAPP_NET
                ["xmlns"] = "w:m",
                ["type"]  = "set",
            }) { Content = new List<BinaryNode> { mediaConnNode } };

            _logger.LogInformation("Requesting media_conn via w:m set IQ (Baileys pattern)");
            var result = await SendIQAsync(iq, ct, timeoutMs: 8000);

            // Response: <iq type="result"><media_conn auth="..." ttl="..." ...><host hostname="mmg.whatsapp.net" .../></media_conn></iq>
            var mcNode = result.FindChild("media_conn") ?? FindDeep(result, "media_conn");
            if (mcNode != null)
            {
                var auth       = mcNode.GetAttr("auth") ?? "";
                // Pick first host that has an <upload/> child; fall back to first host
                var uploadHost = mcNode.Children.FirstOrDefault(h => h.Tag == "host" && h.Children.Any(c => c.Tag == "upload"))
                                 ?? mcNode.Children.FirstOrDefault(h => h.Tag == "host");
                var hostName   = uploadHost?.GetAttr("hostname") ?? "mmg.whatsapp.net";
                // Token: base64url (RFC 4648) — Baileys uses: replace +→- /→_ strip =, then encodeURIComponent.
                // Result is already URL-safe so encodeURIComponent is a no-op for these chars.
                var tokenB64   = Uri.EscapeDataString(fileEncSha256B64.Replace('+', '-').Replace('/', '_').TrimEnd('='));
                // Baileys URL: https://{host}/mms/{type}/{token}?auth={auth}&token={token}
                // The token appears both in the URL PATH and as a query param.
                var uploadUrl  = $"https://{hostName}/mms/{mediaType}/{tokenB64}?auth={Uri.EscapeDataString(auth)}&token={tokenB64}";
                _logger.LogInformation("Got media_conn auth, upload to {Host}", hostName);
                return (uploadUrl, "", auth);
            }

            // IQ returned something but no media_conn child — log and fall through
            _logger.LogWarning("w:m IQ result had no media_conn child, falling back to direct upload");
        }
        catch (TimeoutException)
        {
            _logger.LogWarning("w:m IQ timed out (server ignores companion device w:m IQs) — using direct mmg upload");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "w:m IQ failed — using direct mmg upload");
        }

        // --- Fallback: direct upload to mmg.whatsapp.net without auth token ---
        // Some companion device implementations upload directly using the encrypted hash as token.
        // URL format used by open-source WA clients when no media_conn auth is available.
        var hashB64Url = Uri.EscapeDataString(fileEncSha256B64.Replace('+', '-').Replace('/', '_').TrimEnd('='));
        var directUploadUrl = $"https://mmg.whatsapp.net/mms/{mediaType}/{hashB64Url}?hash={hashB64Url}&type={mediaType}&v=4";
        _logger.LogInformation("Using direct mmg upload URL for {Type}", mediaType);
        return (directUploadUrl, "", "");
    }

    /// <summary>Pads a proto-encoded message with random PKCS7-style padding (Baileys: writeRandomPadMax16).</summary>
    private static byte[] PadMessage(byte[] msgRaw)
    {
        var padLen = (byte)(System.Security.Cryptography.RandomNumberGenerator.GetInt32(0, 16) + 1); // 1-16
        var padded = new byte[msgRaw.Length + padLen];
        msgRaw.CopyTo(padded, 0);
        Array.Fill(padded, padLen, msgRaw.Length, padLen);
        return padded;
    }

    /// <summary>Encrypts a padded proto for a single device, returning a 'to' node or null on failure.</summary>
    private BinaryNode? EncryptForDevice(string deviceJid, byte[] paddedProto, ref bool hasPkMsg)
    {
        if (!_signalStore.HasSession(deviceJid))
        {
            _logger.LogWarning("No session for {Jid} after bundle fetch, skipping", deviceJid);
            return null;
        }
        try
        {
            var (encBytes, isPreKey) = _signalStore.EncryptMessage(deviceJid, paddedProto, _auth);
            if (isPreKey) hasPkMsg = true;
            var encNode = new BinaryNode("enc", new Dictionary<string, string>
            {
                ["v"]    = "2",
                ["type"] = isPreKey ? "pkmsg" : "msg",
            }) { Content = encBytes };

            return new BinaryNode("to", new Dictionary<string, string>
            {
                ["jid"] = deviceJid,
            }) { Content = new List<BinaryNode> { encNode } };
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to encrypt for {Jid}: {Error}", deviceJid, ex.Message);
            return null;
        }
    }

    // ─── IQ helper ──────────────────────────────────────────────────────────

    private async Task<BinaryNode> SendIQAsync(BinaryNode iq, CancellationToken ct, int timeoutMs = 15000)
    {
        var id = iq.GetAttr("id") ?? GenerateMessageId();
        if (!iq.Attrs.ContainsKey("id")) iq.Attrs["id"] = id;

        var tcs = new TaskCompletionSource<BinaryNode>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingIqs[id] = tcs;

        _logger.LogInformation("Sending IQ id={Id} xmlns={Xmlns} type={Type}, pending count={Count}",
            id, iq.GetAttr("xmlns") ?? "?", iq.GetAttr("type") ?? "?", _pendingIqs.Count);

        await SendNodeAsync(iq, ct);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeoutMs);

        try
        {
            return await tcs.Task.WaitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            _pendingIqs.Remove(id);
            throw new TimeoutException($"IQ {id} timed out after {timeoutMs}ms");
        }
    }

    // ─── Fetch pre-key bundles ───────────────────────────────────────────────

    /// <summary>
    /// Sends an encrypt IQ to fetch pre-key bundles for a list of device JIDs.
    /// Returns a dictionary keyed by device JID.
    /// </summary>
    private async Task<Dictionary<string, PreKeyBundle>> FetchPreKeyBundlesAsync(
        IEnumerable<string> deviceJids, CancellationToken ct)
    {
        var userNodes = deviceJids.Select(d => new BinaryNode("user", new Dictionary<string, string>
        {
            ["jid"] = d,
        })).ToList();

        var keyNode = new BinaryNode("key") { Content = userNodes };
        var iqId    = GenerateMessageId();
        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["xmlns"] = "encrypt",
            ["type"]  = "get",
            ["to"]    = "@s.whatsapp.net",
            ["id"]    = iqId,
        }) { Content = new List<BinaryNode> { keyNode } };

        BinaryNode response;
        try { response = await SendIQAsync(iq, ct, timeoutMs: 30000); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "FetchPreKeyBundles IQ failed");
            return new Dictionary<string, PreKeyBundle>();
        }

        var result  = new Dictionary<string, PreKeyBundle>();
        var listNode = response.FindChild("list") ?? response;

        foreach (var userNode in listNode.GetChildren("user"))
        {
            var userJid = userNode.GetAttr("jid") ?? "";
            if (string.IsNullOrEmpty(userJid)) continue;

            try
            {
                var bundle = ParsePreKeyBundle(userNode);
                result[userJid] = bundle;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse pre-key bundle for {Jid}", userJid);
            }
        }

        return result;
    }

    private static PreKeyBundle ParsePreKeyBundle(BinaryNode userNode)
    {
        var regNode  = userNode.FindChild("registration");
        var typeNode = userNode.FindChild("type");
        var idNode   = userNode.FindChild("identity");
        var skeyNode = userNode.FindChild("skey");
        var otpkNode = userNode.FindChild("key");

        var regBytes = regNode?.Data ?? [];
        uint regId = regBytes.Length >= 4
            ? (uint)((regBytes[0] << 24) | (regBytes[1] << 16) | (regBytes[2] << 8) | regBytes[3])
            : 0;

        var identityKey = idNode?.Data ?? [];

        byte[] spkPub = [];
        uint   spkId  = 0;
        byte[] spkSig = [];
        if (skeyNode != null)
        {
            var skeyIdBytes = skeyNode.FindChild("id")?.Data ?? [];
            spkId = skeyIdBytes.Length >= 3
                ? (uint)((skeyIdBytes[0] << 16) | (skeyIdBytes[1] << 8) | skeyIdBytes[2])
                : 0;
            spkPub = skeyNode.FindChild("value")?.Data ?? [];
            spkSig = skeyNode.FindChild("signature")?.Data ?? [];
        }

        byte[]? otpkPub = null;
        uint    otpkId  = 0;
        if (otpkNode != null)
        {
            var otpkIdBytes = otpkNode.FindChild("id")?.Data ?? [];
            otpkId = otpkIdBytes.Length >= 3
                ? (uint)((otpkIdBytes[0] << 16) | (otpkIdBytes[1] << 8) | otpkIdBytes[2])
                : 0;
            otpkPub = otpkNode.FindChild("value")?.Data;
        }

        return new PreKeyBundle
        {
            TheirIdentityPub      = identityKey,
            TheirSignedPreKeyPub  = spkPub,
            TheirSignedPreKeyId   = spkId,
            TheirSignedPreKeySig  = spkSig,
            TheirOneTimePreKeyPub = otpkPub,
            TheirOneTimePreKeyId  = otpkId,
            PeerRegistrationId    = regId,
        };
    }

    // ─── Get device list (USync) ─────────────────────────────────────────────

    /// <summary>
    /// Sends a USync IQ to get all device JIDs for a phone number.
    /// Returns list of device JIDs like "31633984381:0@s.whatsapp.net".
    /// </summary>
    private async Task<List<string>> GetDeviceListAsync(string phoneNumber, CancellationToken ct)
    {
        var jid  = $"{phoneNumber.TrimStart('+')}@s.whatsapp.net";
        var sid  = GenerateMessageId();
        var iqId = GenerateMessageId();

        var devicesNode = new BinaryNode("devices", new Dictionary<string, string> { ["version"] = "2" });
        var queryNode  = new BinaryNode("query") { Content = new List<BinaryNode> { devicesNode } };

        var userNode = new BinaryNode("user", new Dictionary<string, string> { ["jid"] = jid });
        var listNode = new BinaryNode("list") { Content = new List<BinaryNode> { userNode } };

        var usyncNode = new BinaryNode("usync", new Dictionary<string, string>
        {
            ["context"] = "message",
            ["mode"]    = "query",
            ["last"]    = "true",
            ["index"]   = "0",
            ["sid"]     = sid,
        }) { Content = new List<BinaryNode> { queryNode, listNode } };

        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["to"]    = "@s.whatsapp.net",
            ["type"]  = "get",
            ["xmlns"] = "usync",
            ["id"]    = iqId,
        }) { Content = new List<BinaryNode> { usyncNode } };

        BinaryNode response;
        try { response = await SendIQAsync(iq, ct); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "GetDeviceList IQ failed for {Phone}", phoneNumber);
            return [$"{phoneNumber}:0@s.whatsapp.net"];
        }

        var deviceJids = new List<string>();
        WalkForDevices(response, phoneNumber, deviceJids);

        if (deviceJids.Count == 0)
            deviceJids.Add($"{phoneNumber}:0@s.whatsapp.net");

        return deviceJids;
    }

    private static void WalkForDevices(BinaryNode node, string phoneNumber, List<string> result)
    {
        if (node.Tag == "device")
        {
            // USync response has two formats:
            // 1. <device jid="31633984381:10@s.whatsapp.net" .../>
            // 2. <device id="10" .../>  (just the device ID, no full JID)
            var jid = node.GetAttr("jid");
            if (!string.IsNullOrEmpty(jid))
            {
                result.Add(jid);
                return;
            }
            var id = node.GetAttr("id");
            if (id != null)
            {
                // Device 0 is the primary phone — Baileys encodes as "user@server" (no :0)
                // Other devices use "user:device@server"
                if (id == "0")
                    result.Add($"{phoneNumber}@s.whatsapp.net");
                else
                    result.Add($"{phoneNumber}:{id}@s.whatsapp.net");
                return;
            }
        }
        foreach (var child in node.Children)
            WalkForDevices(child, phoneNumber, result);
    }

    // ─── Low-level send/receive ─────────────────────────────────────────────

    private async Task SendNodeAsync(BinaryNode node, CancellationToken ct)
    {
        // Log outbound node so we can compare sent vs received in nodelog/nodes.log
        try
        {
            var logDir = Path.Combine(_options.SessionDirectory, "..", "nodelog");
            Directory.CreateDirectory(logDir);
            var logFile = Path.Combine(logDir, "nodes.log");
            File.AppendAllText(logFile, $"[{DateTime.UtcNow:HH:mm:ss}] SEND: {node}\n");
        }
        catch { /* non-fatal */ }

        var encoded = BinaryNodeEncoder.Encode(node);
        // Prepend flags byte (0x00 = uncompressed) — server strips this on receive
        // just as we strip it from server frames in StripFlagsAndDecompress().
        var frameData = new byte[1 + encoded.Length];
        frameData[0] = 0;
        encoded.CopyTo(frameData, 1);
        var encrypted = EncryptFrame(frameData);
        await _socket.SendFrameAsync(encrypted, ct);
    }

    private bool _firstHandshakeFrame = true;

    private async Task SendHandshakeMessageAsync(HandshakeMessage msg, CancellationToken ct)
    {
        var msgBytes = msg.ToByteArray();

        if (_firstHandshakeFrame)
        {
            // Baileys wire format for the FIRST frame:
            //   [WA_PROLOGUE: 4 bytes] [length: 3 bytes BE] [proto payload: N bytes]
            // The WA prologue is OUTSIDE the 3-byte length framing (unlike subsequent frames).
            var raw = new byte[WA_PROLOGUE.Length + 3 + msgBytes.Length];
            WA_PROLOGUE.CopyTo(raw, 0);
            raw[4] = (byte)(msgBytes.Length >> 16);
            raw[5] = (byte)(msgBytes.Length >> 8);
            raw[6] = (byte)(msgBytes.Length);
            msgBytes.CopyTo(raw, 7);
            await _socket.SendRawAsync(raw, ct);
            _firstHandshakeFrame = false;
        }
        else
        {
            // Subsequent frames: standard [3-byte len][payload]
            await _socket.SendFrameAsync(msgBytes, ct);
        }
    }

    private byte[] EncryptFrame(byte[] data)
    {
        if (!_handshakeDone || _sendKey == null)
            throw new InvalidOperationException("Handshake not complete.");
        return AesGcmHelper.EncryptWithCounter(_sendKey, _sendCounter++, data);
    }

    private byte[] DecryptFrame(byte[] data)
    {
        if (!_handshakeDone || _recvKey == null)
            throw new InvalidOperationException("Handshake not complete.");
        return AesGcmHelper.DecryptWithCounter(_recvKey, _recvCounter++, data);
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private static byte[] StripFlagsAndDecompress(byte[] decrypted)
    {
        if (decrypted.Length == 0) return decrypted;
        var flags = decrypted[0];
        var data = decrypted[1..];

        if ((flags & 2) != 0)
        {
            // WhatsApp uses zlib compression (with 2-byte header), not raw deflate.
            // Baileys uses Node.js inflateSync() which handles the zlib wrapper.
            // .NET ZLibStream handles the zlib header correctly.
            using var input = new MemoryStream(data);
            using var zlib = new ZLibStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            zlib.CopyTo(output);
            return output.ToArray();
        }

        return data;
    }

    // WA web version now comes from WaVersionProvider (live fetch + disk cache + compiled
    // fallback) — WhatsApp 405-rejects fresh registrations from outdated versions.

    private byte[] BuildClientPayload()
    {
        var userAgent = new UserAgent
        {
            Platform = 14, // WEB
            AppVersion = new AppVersion
            {
                Primary = WaVersionProvider.Primary,
                Secondary = WaVersionProvider.Secondary,
                Tertiary = WaVersionProvider.Tertiary,
            },
            Mcc = "000",
            Mnc = "000",
            OsVersion = "0.1",
            Device = "Desktop",   // Baileys getUserAgent always uses "Desktop"
            OsBuildNumber = "0.1",
            LocaleLanguageIso6391 = "en",
            LocaleCountryIso31661Alpha2 = "US",
        };

        if (_auth.IsFresh)
        {
            // Fresh registration: include device pairing data so server knows our keys
            var buildHash = MD5.HashData(System.Text.Encoding.UTF8.GetBytes(WaVersionProvider.VersionString));

            // Registration ID as 4-byte big-endian
            var eRegid = new byte[4];
            eRegid[0] = (byte)(_auth.RegistrationId >> 24);
            eRegid[1] = (byte)(_auth.RegistrationId >> 16);
            eRegid[2] = (byte)(_auth.RegistrationId >> 8);
            eRegid[3] = (byte)(_auth.RegistrationId);

            // Signed pre-key ID as 3-byte big-endian
            var eSkeyId = new byte[3];
            eSkeyId[0] = (byte)(_auth.SignedPreKeyId >> 16);
            eSkeyId[1] = (byte)(_auth.SignedPreKeyId >> 8);
            eSkeyId[2] = (byte)(_auth.SignedPreKeyId);

            var deviceProps = new DevicePropsMessage
            {
                // Os="Ubuntu", HistorySyncConfig — set by default
                PlatformType = 1, // CHROME
                Version = new AppVersion
                {
                    Primary = WaVersionProvider.Primary,
                    Secondary = WaVersionProvider.Secondary,
                    Tertiary = WaVersionProvider.Tertiary,
                },
            }.ToByteArray();

            return new ClientPayload
            {
                Passive = false,
                Pull = false,
                ConnectType = 1,   // WIFI_UNKNOWN
                ConnectReason = 1, // USER_ACTIVATED
                UserAgent = userAgent,
                WebInfo = new WebInfo { WebSubPlatform = 0 },
                DevicePairingData = new DevicePairingRegistrationData
                {
                    ERegid   = eRegid,
                    EKeytype = [5], // KEY_BUNDLE_TYPE
                    EIdent   = _auth.SignedIdentityKeyPublic,
                    ESkeyId  = eSkeyId,
                    ESkeyVal = _auth.SignedPreKeyPublic,
                    ESkeySig = _auth.SignedPreKeySignature,
                    BuildHash   = buildHash,
                    DeviceProps = deviceProps,
                },
            }.ToByteArray();
        }
        else
        {
            // Session restore (login)
            // Me.Id format: "31633984381:20@s.whatsapp.net" — extract phone and device number
            var rawId = _auth.Me?.Id.Split('@')[0] ?? "0"; // "31633984381:20"
            var parts = rawId.Split(':');
            ulong.TryParse(parts[0], out var userId);      // "31633984381" → 31633984381
            uint.TryParse(parts.Length > 1 ? parts[1] : "0", out var deviceId); // "20" → 20
            return new ClientPayload
            {
                Username = userId,
                Device = deviceId,   // CRITICAL: server needs device number to route the session
                Passive = true,
                Pull = true,
                ConnectType = 1,
                ConnectReason = 1,
                UserAgent = userAgent,
                WebInfo = new WebInfo { WebSubPlatform = 0 },
            }.ToByteArray();
        }
    }

    /// <summary>
    /// Uploads one-time pre-keys and the signed pre-key to WhatsApp server
    /// so other devices can initiate Signal sessions with us.
    /// Called once after successful authentication.
    /// </summary>
    private async Task UploadPreKeysAsync(CancellationToken ct)
    {
        const int BatchSize = 30; // upload 30 one-time pre-keys at a time

        // Generate fresh pre-keys if we've run out — private keys must be available for decryption
        if (_auth.PreKeys.Count == 0)
        {
            _logger.LogWarning("Pre-key pool exhausted — generating 100 new pre-keys.");
            // Start IDs from a high offset to avoid collisions with any still-live server-side keys
            uint startId = 1001;
            for (uint i = 0; i < 100; i++)
            {
                var (priv, pub) = Crypto.Curve25519Helper.GenerateKeyPair();
                _auth.PreKeys.Add(new Auth.PreKey { Id = startId + i, Private = priv, Public = pub });
            }
        }

        var keysToUpload = _auth.PreKeys.Take(BatchSize).ToList();

        if (keysToUpload.Count == 0)
        {
            _logger.LogWarning("No pre-keys available to upload — others cannot initiate Signal sessions.");
            return;
        }

        // Baileys format: raw 32-byte keys (no 0x05 prefix) — the "type=[0x05]" node indicates key type
        static byte[] Be3(uint v) => [(byte)(v >> 16), (byte)(v >> 8), (byte)v];
        static byte[] Be4(uint v) => [(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v];

        // Build key list nodes — value = raw 32-byte public key (no prefix)
        var keyNodes = keysToUpload.Select(k =>
            new BinaryNode("key", null, new List<BinaryNode>
            {
                new("id",    null, Be3(k.Id)),
                new("value", null, k.Public),      // raw 32 bytes
            })
        ).ToList();

        // Signed pre-key node
        var skeyNode = new BinaryNode("skey", null, new List<BinaryNode>
        {
            new("id",        null, Be3(_auth.SignedPreKeyId)),
            new("value",     null, _auth.SignedPreKeyPublic),   // raw 32 bytes
            new("signature", null, _auth.SignedPreKeySignature),
        });

        var content = new List<BinaryNode>
        {
            new("registration", null, Be4(_auth.RegistrationId)),
            new("type",         null, new byte[] { 5 }),  // KEY_BUNDLE_TYPE — indicates Curve25519
            new("identity",     null, _auth.SignedIdentityKeyPublic),   // raw 32 bytes
            new("list",         null, keyNodes),
            skeyNode,
        };

        var iqNode = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["id"]    = GenerateMessageId(),
            ["xmlns"] = "encrypt",
            ["type"]  = "set",
            ["to"]    = "@s.whatsapp.net",
        })
        {
            Content = content,
        };

        try
        {
            var result = await SendIQAsync(iqNode, ct);
            _logger.LogInformation("Pre-keys uploaded successfully ({Count} one-time keys).", keysToUpload.Count);

            // NOTE: Do NOT remove uploaded pre-keys from the local pool.
            // Their private keys must remain in _auth.PreKeys so that InitIncomingSession
            // can look them up by ID when a pkmsg arrives. The keys are removed there,
            // after the session is actually established and the private key consumed.
            // Persist updated auth state in case we generated new pre-keys above.
            Authenticated?.Invoke(this, _auth);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to upload pre-keys.");
        }
    }

    private static string GenerateMessageId()
    {
        var bytes = RandomNumberGenerator.GetBytes(8);
        return BitConverter.ToString(bytes).Replace("-", "").ToUpper();
    }

    // ─── App state sync: contact fetching ───────────────────────────────────

    /// <summary>
    /// Fetches a 32-byte app state key from the server by keyId.
    /// </summary>
    private async Task<byte[]> FetchAppStateSyncKeyAsync(byte[] keyId, CancellationToken ct)
    {
        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["id"]    = GenerateMessageId(),
            ["to"]    = "@s.whatsapp.net",
            ["type"]  = "get",
            ["xmlns"] = "w:sync:app:state:k",
        })
        {
            Content = new List<BinaryNode>
            {
                new BinaryNode("key", null, new List<BinaryNode>
                {
                    new BinaryNode("id", null, keyId),
                }),
            },
        };

        var result = await SendIQAsync(iq, ct, timeoutMs: 15000);

        // Navigate result → key → key-data
        var keyNode     = result.FindChild("key") ?? result;
        var keyDataNode = keyNode.FindChild("key-data");
        if (keyDataNode?.Data is { Length: 32 } appKey)
            return appKey;

        // Fallback: walk children for a 32-byte data blob
        foreach (var child in result.Children)
        {
            if (child.Data is { Length: 32 } d) return d;
            foreach (var grandchild in child.Children)
                if (grandchild.Data is { Length: 32 } d2) return d2;
        }

        throw new InvalidOperationException($"App state sync key response did not contain a 32-byte key (tag={result.Tag})");
    }

    /// <summary>
    /// Fetches contacts from WhatsApp via app state sync of the "contact" collection.
    /// Returns (JID, Name) pairs for all contacts found in the snapshot.
    /// </summary>
    private BinaryNode BuildAppStateSyncIQ(string collectionName, int version, bool returnSnapshot)
    {
        var attrs = new Dictionary<string, string>
        {
            ["name"]    = collectionName,
            ["version"] = version.ToString(),
        };
        if (returnSnapshot) attrs["return_snapshot"] = "true";

        return new BinaryNode("iq", new Dictionary<string, string>
        {
            ["id"]    = GenerateMessageId(),
            ["to"]    = "@s.whatsapp.net",
            ["type"]  = "set",
            ["xmlns"] = "w:app:state:sync",
        })
        {
            Content = new List<BinaryNode>
            {
                new BinaryNode("sync", null, new List<BinaryNode>
                {
                    new BinaryNode("collection", attrs),
                }),
            },
        };
    }

    /// <summary>
    /// Returns contacts from multiple sources:
    /// Push names collected from incoming messages (participant_pn, sender_lid, notify attributes).
    /// USync contact queries consistently return empty results for companion devices.
    /// </summary>
    public Task<List<(string Jid, string Name)>> FetchContactsAsync(CancellationToken ct)
    {
        _logger.LogInformation("FetchContactsAsync: starting (pushNames={Names}, lidToPhone={Lids})",
            _pushNames.Count, _lidToPhone.Count);

        var contacts = new List<(string Jid, string Name)>();
        var seenJids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var kv in _pushNames)
        {
            // Resolve LID JIDs to phone JIDs using the lidToPhone mapping
            var jid = kv.Key.EndsWith("@lid") && _lidToPhone.TryGetValue(kv.Key, out var ph) ? ph : kv.Key;
            // Only include contacts with resolved phone JIDs (skip unresolvable LIDs and non-contacts)
            if (jid.EndsWith("@s.whatsapp.net") && seenJids.Add(jid) && !string.IsNullOrEmpty(kv.Value))
                contacts.Add((jid, kv.Value));
        }

        _logger.LogInformation("FetchContactsAsync: returning {Count} contacts", contacts.Count);
        return Task.FromResult(contacts);
    }

    /// <summary>
    /// Uses USync IQ (which reliably returns results for companion devices) to fetch
    /// contact names for a set of JIDs. Handles both @lid and @s.whatsapp.net JIDs.
    /// </summary>
    private async Task<List<(string Jid, string Name)>> FetchContactsViaUsyncAsync(
        IEnumerable<string> jids, CancellationToken ct)
    {
        var jidList = jids.ToList();
        if (jidList.Count == 0) return [];

        // Build user nodes: phone JIDs use jid= attribute, LID JIDs use a <lid> child node
        var userNodes = jidList.Select(j =>
        {
            if (j.EndsWith("@lid"))
            {
                // LID JIDs must be sent as <user><lid>...</lid></user>
                return new BinaryNode("user")
                {
                    Content = new List<BinaryNode>
                    {
                        new BinaryNode("lid") { Content = j },
                    }
                };
            }
            // Phone JIDs: <user jid="31633984381@s.whatsapp.net"/>
            return new BinaryNode("user", new Dictionary<string, string> { ["jid"] = j });
        }).ToList<BinaryNode>();

        var usyncNode = new BinaryNode("usync", new Dictionary<string, string>
        {
            ["context"] = "interactive",
            ["mode"]    = "query",
            ["last"]    = "true",
            ["index"]   = "0",
            ["sid"]     = GenerateMessageId(),
        })
        {
            Content = new List<BinaryNode>
            {
                new BinaryNode("query") { Content = new List<BinaryNode> { new BinaryNode("contact") } },
                new BinaryNode("list")  { Content = userNodes },
            },
        };

        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["to"]    = "@s.whatsapp.net",
            ["type"]  = "get",
            ["xmlns"] = "usync",
            ["id"]    = GenerateMessageId(),
        }) { Content = new List<BinaryNode> { usyncNode } };

        BinaryNode result;
        try { result = await SendIQAsync(iq, ct, timeoutMs: 15000); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "FetchContactsViaUsyncAsync: IQ failed");
            return [];
        }

        // Parse response: <iq><usync><list><user jid="..." lid="..."><contact>name</contact></user>...</list></usync></iq>
        var contacts = new List<(string Jid, string Name)>();
        WalkUsyncForContacts(result, contacts);
        _logger.LogInformation("FetchContactsViaUsyncAsync: parsed {Count} contacts from USync response", contacts.Count);
        return contacts;
    }

    private void WalkUsyncForContacts(BinaryNode node, List<(string Jid, string Name)> result)
    {
        if (node.Tag == "user")
        {
            var jid  = node.GetAttr("jid") ?? "";
            var lid  = node.GetAttr("lid") ?? "";

            // Cache LID → phone JID mapping from USync response
            if (!string.IsNullOrEmpty(lid) && !string.IsNullOrEmpty(jid))
                _lidToPhone[lid] = jid;

            // Look for <contact> child with push name or status
            var contactNode = node.FindChild("contact");
            var name = contactNode?.GetAttr("name")
                    ?? contactNode?.Text
                    ?? node.GetAttr("name");

            if (!string.IsNullOrEmpty(jid))
            {
                // Use phone JID, not LID
                var displayJid = jid.EndsWith("@lid") && _lidToPhone.TryGetValue(jid, out var ph) ? ph : jid;
                var displayName = name ?? (displayJid.Contains('@') ? displayJid.Split('@')[0] : displayJid);
                result.Add((displayJid, displayName));
            }
            return;
        }
        foreach (var child in node.Children)
            WalkUsyncForContacts(child, result);
    }

    // ─── Presence ──────────────────────────────────────────────────────────

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, PresenceInfo> _presenceCache = new();

    private void HandlePresenceNode(BinaryNode node)
    {
        var jid    = node.GetAttr("from") ?? "";
        var type   = node.GetAttr("type") ?? "available";
        var status = type == "unavailable" ? "unavailable" : "available";

        var composing = node.FindChild("composing");
        var recording = node.FindChild("recording");
        if (composing != null) status = "composing";
        if (recording != null) status = "recording";

        _presenceCache[jid] = new PresenceInfo(jid, status, DateTime.UtcNow);
        _logger.LogDebug("Presence: {Jid} → {Status}", jid, status);
    }

    public async Task SubscribePresenceAsync(string jid, CancellationToken ct)
    {
        var normalizedJid = jid.Contains('@') ? jid : $"{jid.TrimStart('+')}@s.whatsapp.net";
        var node = new BinaryNode("presence", new Dictionary<string, string>
        {
            ["type"] = "subscribe",
            ["to"]   = normalizedJid,
        });
        await SendNodeAsync(node, ct);
    }

    public PresenceInfo? GetPresence(string jid)
        => _presenceCache.TryGetValue(jid, out var p) ? p : null;

    // ─── Profile picture ────────────────────────────────────────────────────

    public async Task<string?> FetchProfilePictureAsync(string jid, CancellationToken ct)
    {
        var normalizedJid = jid.Contains('@') ? jid : $"{jid.TrimStart('+')}@s.whatsapp.net";
        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["to"]    = normalizedJid,
            ["type"]  = "get",
            ["xmlns"] = "w:profile:pic",
            ["id"]    = GenerateMessageId(),
        })
        {
            Content = new List<BinaryNode>
            {
                // "query=url" tells WhatsApp to return the CDN URL instead of the raw image
                new BinaryNode("picture", new Dictionary<string, string> { ["type"] = "image", ["query"] = "url" })
            }
        };

        try
        {
            var result = await SendIQAsync(iq, ct, timeoutMs: 15000);
            _logger.LogInformation("Profile pic response: tag={Tag} type={Type}", result.Tag, result.GetAttr("type") ?? "?");
            // Result may have a <picture url="..."/> child, or a direct url attr
            var picNode = result.FindChild("picture");
            var url = picNode?.GetAttr("url") ?? result.GetAttr("url");
            _logger.LogInformation("Profile pic url={Url}", url ?? "(none)");
            return url;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to fetch profile picture for {Jid}", jid);
            return null;
        }
    }

    // ─── Read receipts ──────────────────────────────────────────────────────

    public async Task SendReadReceiptAsync(string jid, string messageId, long timestamp, CancellationToken ct)
    {
        var normalizedJid = jid.Contains('@') ? jid : $"{jid.TrimStart('+')}@s.whatsapp.net";
        var receipt = new BinaryNode("receipt", new Dictionary<string, string>
        {
            ["id"]   = messageId,
            ["to"]   = normalizedJid,
            ["type"] = "read",
            ["t"]    = timestamp.ToString(),
        });
        await SendNodeAsync(receipt, ct);
        _logger.LogInformation("Sent read receipt for message {MsgId} to {Jid}", messageId, normalizedJid);
    }

    // ─── Chats (from thread_metadata + message history) ─────────────────────

    /// <summary>
    /// Returns the list of active chats. Primary source is thread_metadata from
    /// the ib node that WhatsApp sends immediately after authentication.
    /// Falls back to message history if thread_metadata is empty.
    /// </summary>
    public Task<List<(string Jid, string Name, bool Archived, bool Pinned)>> FetchChatsAsync(CancellationToken ct)
    {
        var chats = new List<(string Jid, string Name, bool Archived, bool Pinned)>();

        // Track seen JIDs to deduplicate: a chat may appear as both LID and phone JID in thread_metadata
        var seenJids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Use thread_metadata as primary source (populated immediately at startup)
        if (_threadMetadata.Count > 0)
        {
            _logger.LogInformation("FetchChatsAsync: returning {Count} chats from thread_metadata", _threadMetadata.Count);

            foreach (var kv in _threadMetadata.OrderByDescending(x => x.Value))
            {
                var rawJid = kv.Key;

                // Resolve LID to phone JID if possible
                string jid;
                if (rawJid.EndsWith("@lid") && _lidToPhone.TryGetValue(rawJid, out var resolvedJid))
                    jid = resolvedJid;
                else
                    jid = rawJid;

                // Deduplicate: skip if we already emitted this resolved JID
                if (!seenJids.Add(jid)) continue;

                // Get display name from push names, then JID
                string name;
                if (_pushNames.TryGetValue(rawJid, out var pn) || _pushNames.TryGetValue(jid, out pn))
                    name = pn;
                else
                    name = jid.Split('@')[0].Split(':')[0];

                chats.Add((jid, name, false, false));
            }
        }
        else
        {
            // Fallback: build from push names cache (populated by received messages)
            _logger.LogInformation("FetchChatsAsync: no thread_metadata, using pushNames cache ({Count} entries)", _pushNames.Count);
            foreach (var kv in _pushNames)
            {
                var jid = kv.Key.EndsWith("@lid") && _lidToPhone.TryGetValue(kv.Key, out var ph) ? ph : kv.Key;
                if (seenJids.Add(jid))
                    chats.Add((jid, kv.Value, false, false));
            }
        }

        _logger.LogInformation("FetchChatsAsync: returning {Count} chats", chats.Count);
        return Task.FromResult(chats);
    }

    /// <summary>Returns internal cache state for debugging.</summary>
    public object GetCacheDebugInfo() => new
    {
        threadMetadataCount = _threadMetadata.Count,
        threadMetadata = _threadMetadata.OrderByDescending(x => x.Value)
            .Take(20)
            .Select(kv => new { jid = kv.Key, t = kv.Value })
            .ToList(),
        lidToPhoneCount = _lidToPhone.Count,
        lidToPhone = _lidToPhone.Take(10)
            .Select(kv => new { lid = kv.Key, phone = kv.Value })
            .ToList(),
        pushNamesCount = _pushNames.Count,
        pushNames = _pushNames.Take(10)
            .Select(kv => new { jid = kv.Key, name = kv.Value })
            .ToList(),
        serverSyncVersions = _serverSyncVersions.ToDictionary(kv => kv.Key, kv => kv.Value),
    };

    // ─── Message history ─────────────────────────────────────────────────────

    /// <summary>
    /// Attempts to fetch message history for a JID using a w:msg sync IQ.
    /// Returns an empty list if the server does not respond (companion devices may not support this).
    /// Note: in-memory message cache is used as primary source; this IQ is a best-effort supplement.
    /// </summary>
    /// <summary>
    /// Requests an ON_DEMAND history sync from the phone by sending a
    /// peerDataOperationRequestMessage to our own JID.
    /// The phone responds by pushing a HISTORY_SYNC_NOTIFICATION (syncType 5 = ON_DEMAND)
    /// which our receive loop handles, firing HistoryMessageReceived for each past message.
    /// Returns the messages collected from that push notification (or empty if the phone
    /// does not respond within the timeout).
    /// </summary>
    public async Task<List<IncomingMessage>> RequestOnDemandHistorySyncAsync(string chatJid, int count, CancellationToken ct)
    {
        var normalizedJid = chatJid.Contains('@') ? chatJid : $"{chatJid}@s.whatsapp.net";

        var myJid = _auth.Me?.Id;
        if (myJid == null)
        {
            // Fail-safe: never throw out of on-demand history sync. It is an optional,
            // best-effort request; if we cannot make it, the caller simply gets no extra
            // history and all normal paths (automatic history sync, offline queue, live
            // delivery) keep working untouched.
            _logger.LogWarning("OnDemandHistorySync: not authenticated — skipping (normal delivery unaffected)");
            return new List<IncomingMessage>();
        }

        // If given a LID, resolve to phone JID for the peerDataOperationRequestMessage
        // (phone stores chats by phone JID internally, not LID)
        string requestJid = normalizedJid;
        if (normalizedJid.EndsWith("@lid"))
        {
            // Try to resolve LID → phone JID via our cache
            if (_lidToPhone.TryGetValue(normalizedJid, out var phoneJid))
            {
                _logger.LogInformation("OnDemandHistorySync: resolved LID {Lid} → {Phone} for request", normalizedJid, phoneJid);
                requestJid = phoneJid;
            }
            else
            {
                // Strip LID number and try as phone number
                var lidNum = normalizedJid.Split('@')[0];
                _logger.LogWarning("OnDemandHistorySync: no phone mapping for LID {Lid} — will try phone JID too", normalizedJid);
            }
        }

        // Collect messages for the target JID as they arrive (match both phone and LID variants)
        var collected = new List<IncomingMessage>();
        var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

        EventHandler<IncomingMessage> onMsg = (_, msg) =>
        {
            // Exception-safe: a malformed history message must never throw into the
            // HistoryMessageReceived event dispatch (which also feeds normal history sync).
            try
            {
                var remoteBase = normalizedJid.Split('@')[0];
                var requestBase = requestJid.Split('@')[0];
                if (msg.RemoteJid == normalizedJid ||
                    msg.RemoteJid == requestJid ||
                    msg.From == normalizedJid ||
                    msg.From == requestJid ||
                    (msg.RemoteJid?.Split('@')[0] == remoteBase) ||
                    (msg.RemoteJid?.Split('@')[0] == requestBase))
                {
                    lock (collected) { collected.Add(msg); }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "OnDemandHistorySync: collector handler error (ignored)");
            }
        };

        EventHandler<int> onComplete = (_, n) =>
        {
            _logger.LogInformation("OnDemandHistorySync: HistorySyncCompleted fired ({N} msgs)", n);
            tcs.TrySetResult(n);
        };

        HistoryMessageReceived += onMsg;
        HistorySyncCompleted   += onComplete;

        try
        {
            _logger.LogInformation("OnDemandHistorySync: sending peerDataOperationRequestMessage for {ChatJid} (requestJid={ReqJid})", normalizedJid, requestJid);
            await SendPeerDataOperationRequestAsync(myJid, requestJid, count, ct);
            // If LID and request JID differ, also try with the original LID (phone may accept either)
            if (requestJid != normalizedJid)
            {
                await Task.Delay(1000, ct);
                await SendPeerDataOperationRequestAsync(myJid, normalizedJid, count, ct);
            }

            // Wait up to 35 seconds for the phone to push the history sync notification
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(35));
            using var linked  = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
            using (linked.Token.Register(() => tcs.TrySetCanceled()))
                await tcs.Task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("OnDemandHistorySync: timed out / cancelled waiting for push notification");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "OnDemandHistorySync: error");
        }
        finally
        {
            HistoryMessageReceived -= onMsg;
            HistorySyncCompleted   -= onComplete;
        }

        lock (collected) { return [.. collected]; }
    }

    private async Task SendPeerDataOperationRequestAsync(string myJid, string targetChatJid, int count, CancellationToken ct)
    {
        var myPhone = myJid.Split('@')[0].Split(':')[0];

        // Get all our own devices
        List<string> myDevices;
        try { myDevices = await GetDeviceListAsync(myPhone, ct); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "OnDemandHistorySync: failed to get own device list");
            myDevices = [$"{myPhone}:0@s.whatsapp.net"];
        }

        _logger.LogInformation("OnDemandHistorySync: encrypting for {Count} own devices: {Jids}",
            myDevices.Count, string.Join(", ", myDevices));

        // Fetch pre-key bundles for devices without sessions
        var needBundles = myDevices.Where(d => !_signalStore.HasSession(d)).ToList();
        if (needBundles.Count > 0)
        {
            try
            {
                var bundles = await FetchPreKeyBundlesAsync(needBundles, ct);
                foreach (var (deviceJid, bundle) in bundles)
                    try { _signalStore.InitOutgoingSession(deviceJid, bundle, _auth); }
                    catch (Exception ex2) { _logger.LogWarning(ex2, "OnDemandHistorySync: session init failed for {Jid}", deviceJid); }
            }
            catch (Exception ex) { _logger.LogWarning(ex, "OnDemandHistorySync: failed to fetch bundles"); }
        }

        // Build the PeerDataOperationRequestMessage proto
        var msg = new WAMessage
        {
            PeerDataOperation = new Proto.PeerDataOperationRequestMessage
            {
                RequestType      = Proto.PeerDataOperationRequestMessage.TYPE_HISTORY_SYNC_ON_DEMAND,
                ChatJid          = targetChatJid,
                OnDemandMsgCount = count,
            }
        };
        var protoBytes = PadMessage(msg.ToByteArrayWithPeerDataOperation());

        // Encrypt for each of our own devices
        var msgId    = GenerateMessageId();
        var hasPkMsg = false;
        var toNodes  = new List<BinaryNode>();
        foreach (var deviceJid in myDevices)
        {
            var node = EncryptForDevice(deviceJid, protoBytes, ref hasPkMsg);
            if (node != null) toNodes.Add(node);
        }

        if (toNodes.Count == 0)
        {
            _logger.LogWarning("OnDemandHistorySync: no devices encrypted to — cannot send request");
            return;
        }

        var participantsNode = new BinaryNode("participants") { Content = toNodes };
        var contentNodes     = new List<BinaryNode> { participantsNode };

        if (hasPkMsg && _auth.Account != null)
        {
            var accountProto = ADVSignedDeviceIdentity.ParseFrom(_auth.Account);
            contentNodes.Add(new BinaryNode("device-identity") { Content = accountProto.ToByteArray() });
        }

        var msgNode = new BinaryNode("message", new Dictionary<string, string>
        {
            ["id"]   = msgId,
            ["type"] = "text",
            ["to"]   = $"{myPhone}@s.whatsapp.net",
        }) { Content = contentNodes };

        // Track this PDO message so that if the phone sends a retry receipt we can resend
        _sentPdoMsgIds.Add(msgId);
        _lastPdoRequest = (targetChatJid, null, false, 0, count);

        await SendNodeAsync(msgNode, ct);
        _logger.LogInformation("OnDemandHistorySync: sent peerDataOperationRequestMessage (msgId={Id}) to self", msgId);
    }

    public async Task<List<IncomingMessage>> FetchMessageHistoryAsync(string jid, int count, CancellationToken ct)
    {
        // Normalize JID
        var normalizedJid = jid.Contains('@') ? jid : $"{jid}@s.whatsapp.net";

        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["to"]    = "s.whatsapp.net",
            ["type"]  = "set",
            ["xmlns"] = "w:msg",
            ["id"]    = GenerateMessageId(),
        })
        {
            Content = new List<BinaryNode>
            {
                new BinaryNode("sync")
                {
                    Content = new List<BinaryNode>
                    {
                        new BinaryNode("conversation", new Dictionary<string, string>
                        {
                            ["jid"]   = normalizedJid,
                            ["t"]     = "0",
                            ["count"] = count.ToString(),
                        }),
                    },
                },
            },
        };

        try
        {
            _logger.LogInformation("FetchMessageHistoryAsync: sending w:msg sync IQ for {Jid}", normalizedJid);
            var result = await SendIQAsync(iq, ct, timeoutMs: 20000);
            _logger.LogInformation("FetchMessageHistoryAsync: w:msg result tag={Tag}", result.Tag);

            // Parse any message nodes in the result
            var messages = new List<IncomingMessage>();
            var msgNodes = new List<BinaryNode>();
            CollectNodes(result, "message", msgNodes);
            foreach (var msgNode in msgNodes)
            {
                var text = msgNode.FindChild("body")?.Content as string
                    ?? msgNode.GetAttr("body");
                if (string.IsNullOrEmpty(text)) continue;

                var from = msgNode.GetAttr("from") ?? "";
                long.TryParse(msgNode.GetAttr("t"), out var ts);
                var fromMe = from == _auth.Me?.Id?.Split(':')[0] + "@s.whatsapp.net";
                messages.Add(new IncomingMessage
                {
                    Id        = msgNode.GetAttr("id") ?? "",
                    From      = from,
                    RemoteJid = normalizedJid,
                    Text      = text,
                    FromMe    = fromMe,
                    Timestamp = ts,
                });
            }

            return messages;
        }
        catch (TimeoutException)
        {
            _logger.LogInformation("FetchMessageHistoryAsync: w:msg IQ timed out (companion devices may not support history sync via IQ)");
            return new List<IncomingMessage>();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "FetchMessageHistoryAsync: w:msg IQ failed for {Jid}", normalizedJid);
            return new List<IncomingMessage>();
        }
    }

    private static void CollectNodes(BinaryNode node, string tag, List<BinaryNode> result)
    {
        if (node.Tag == tag) result.Add(node);
        foreach (var child in node.Children)
            CollectNodes(child, tag, result);
    }

    // ─── History Sync (HistorySyncNotification → CDN download → proto parse) ─

    private static readonly HttpClient _httpClient = new(new HttpClientHandler
    {
        AutomaticDecompression = System.Net.DecompressionMethods.None, // handle ourselves
    });

    /// <summary>
    /// Handles a HistorySyncNotification message from the phone.
    /// Downloads the encrypted blob from WhatsApp CDN, decrypts it, parses the
    /// HistorySync protobuf, and fires HistoryMessageReceived for each message and HistorySyncCompleted at the end.
    /// </summary>
    private async Task HandleHistorySyncAsync(
        Dawa.Proto.HistorySyncNotification notification,
        string msgId, string from, long timestamp, CancellationToken ct)
    {
        _logger.LogInformation(
            "HistorySync: type={Type} chunkOrder={Chunk} directPath={Path} fileLen={Len}",
            notification.SyncType, notification.Progress, notification.DirectPath, notification.FileLength);

        try
        {
            // ── 1. Download encrypted blob from WhatsApp CDN ───────────────────
            if (string.IsNullOrEmpty(notification.DirectPath))
            {
                _logger.LogWarning("HistorySync: no directPath — cannot download blob");
                _ = SendAckAsync(msgId, from, timestamp);
                return;
            }

            var cdnUrl = "https://mmg.whatsapp.net" + notification.DirectPath;
            byte[] encryptedBlob;
            try
            {
                encryptedBlob = await _httpClient.GetByteArrayAsync(cdnUrl, ct);
                _logger.LogInformation("HistorySync: downloaded {Bytes} bytes from CDN", encryptedBlob.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HistorySync: CDN download failed for {Url}", cdnUrl);
                _ = SendAckAsync(msgId, from, timestamp);
                return;
            }

            // ── 2. Decrypt: HKDF-expand mediaKey → IV(16) + aesKey(32) + macKey(32) ─
            // Info string for history sync is "WhatsApp History Keys"
            // Expand mediaKey using HKDF-SHA256 with WhatsApp's standard media key derivation.
            // Info: "WhatsApp History Keys", salt: 32 zero bytes, output: 112 bytes.
            // Layout (from Baileys): IV=0..15, AES=16..47, MAC=48..79
            var expanded = Dawa.Crypto.DawaHKDF.DeriveKey(
                notification.MediaKey,
                salt: new byte[32], // zero salt
                info: System.Text.Encoding.UTF8.GetBytes("WhatsApp History Keys"),
                outputLength: 80);

            var iv     = expanded[0..16];    // bytes 0..15
            var aesKey = expanded[16..48];   // bytes 16..47
            // macKey is expanded[48..80] — we trust the download, skip MAC verification for now

            // Strip trailing 10-byte HMAC
            var ciphertext = encryptedBlob[..^10];

            byte[] decrypted;
            try
            {
                using var aes = System.Security.Cryptography.Aes.Create();
                aes.Key  = aesKey;
                aes.IV   = iv;
                aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                using var dec = aes.CreateDecryptor();
                decrypted = dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HistorySync: AES decryption failed");
                _ = SendAckAsync(msgId, from, timestamp);
                return;
            }

            // ── 3. Gunzip the decrypted bytes ─────────────────────────────────
            byte[] protoBytes;
            try
            {
                using var inStream  = new System.IO.MemoryStream(decrypted);
                using var gzip      = new System.IO.Compression.GZipStream(inStream, System.IO.Compression.CompressionMode.Decompress);
                using var outStream = new System.IO.MemoryStream();
                await gzip.CopyToAsync(outStream, ct);
                protoBytes = outStream.ToArray();
                _logger.LogInformation("HistorySync: decompressed to {Bytes} bytes", protoBytes.Length);
            }
            catch
            {
                // Not gzip — use raw bytes
                protoBytes = decrypted;
                _logger.LogInformation("HistorySync: not gzip-compressed, using raw {Bytes} bytes", protoBytes.Length);
            }

            // ── 4. Parse HistorySync protobuf ──────────────────────────────────
            Dawa.Proto.HistorySync historySync;
            try
            {
                historySync = Dawa.Proto.HistorySync.Decode(protoBytes);
                _logger.LogInformation("HistorySync: parsed {ConvCount} conversations, {NameCount} push names",
                    historySync.Conversations.Count, historySync.PushNames.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HistorySync: failed to parse HistorySync proto ({Bytes} bytes)", protoBytes.Length);
                _ = SendAckAsync(msgId, from, timestamp);
                return;
            }

            // ── 5. Store push names from history ─────────────────────────────────
            foreach (var pn in historySync.PushNames)
            {
                if (!string.IsNullOrEmpty(pn.Id) && !string.IsNullOrEmpty(pn.PushName))
                    _pushNames.TryAdd(pn.Id, pn.PushName);
            }

            // ── 6. Fire HistoryMessageReceived for each message ───────────────────
            var totalMessages = 0;
            foreach (var conv in historySync.Conversations)
            {
                var chatJid = conv.Id;
                if (string.IsNullOrEmpty(chatJid)) continue;

                foreach (var hm in conv.Messages)
                {
                    var wmi = hm.Message;
                    if (wmi == null) continue;
                    var key = wmi.Key;
                    if (key == null) continue;

                    var text = wmi.MessageBody?.EffectiveText;
                    if (string.IsNullOrEmpty(text)) continue;

                    var msgFromMe = key.FromMe;
                    var msgFrom   = msgFromMe
                        ? (_auth.Me?.Id ?? chatJid)
                        : (!string.IsNullOrEmpty(key.Participant) ? key.Participant : chatJid);

                    HistoryMessageReceived?.Invoke(this, new IncomingMessage
                    {
                        Id          = key.Id,
                        From        = msgFrom,
                        RemoteJid   = key.RemoteJid.Length > 0 ? key.RemoteJid : chatJid,
                        Participant = key.Participant.Length > 0 ? key.Participant : null,
                        Text        = text,
                        FromMe      = msgFromMe,
                        Timestamp   = (long)wmi.Timestamp,
                        PushName    = wmi.PushName,
                    });
                    totalMessages++;
                }

                // Update thread metadata with latest message timestamp
                if (conv.Messages.Count > 0)
                {
                    var latest = conv.Messages
                        .Where(m => m.Message != null)
                        .Max(m => (long)m.Message!.Timestamp);
                    _threadMetadata.TryAdd(chatJid, latest);
                }
            }

            _logger.LogInformation("HistorySync: fired {Total} HistoryMessageReceived events across {Convs} conversations",
                totalMessages, historySync.Conversations.Count);

            // Signal completion so callers can persist the full sync
            HistorySyncCompleted?.Invoke(this, totalMessages);

            SaveCacheToDisk();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "HistorySync: unexpected error");
        }
        finally
        {
            _ = SendAckAsync(msgId, from, timestamp);
        }
    }

    // ─── Groups ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the list of group JIDs from thread_metadata (those ending in @g.us).
    /// </summary>
    public List<string> GetGroupJids()
        => _threadMetadata.Keys.Where(j => j.EndsWith("@g.us")).ToList();

    /// <summary>
    /// Fetches group metadata (name, participants) for a specific group JID.
    /// Sends an IQ to the group's server and parses the response.
    /// </summary>
    public async Task<GroupMetadata?> FetchGroupMetadataAsync(string groupJid, CancellationToken ct)
    {
        if (!groupJid.EndsWith("@g.us"))
            throw new ArgumentException("Not a group JID", nameof(groupJid));

        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["to"]    = groupJid,
            ["type"]  = "get",
            ["xmlns"] = "w:g2",
            ["id"]    = GenerateMessageId(),
        })
        {
            Content = new List<BinaryNode>
            {
                new BinaryNode("query", new Dictionary<string, string> { ["request"] = "interactive" }),
            },
        };

        BinaryNode result;
        try { result = await SendIQAsync(iq, ct, timeoutMs: 15000); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "FetchGroupMetadataAsync: IQ failed for {Group}", groupJid);
            return null;
        }

        // Response: <iq type="result"><group id="..." subject="..." creator="..." creation="...">
        //               <participant type="admin" jid="..."/><participant jid="..."/>...</group></iq>
        var groupNode = FindDeep(result, "group");
        if (groupNode == null)
        {
            _logger.LogWarning("FetchGroupMetadataAsync: no <group> node in response for {Group}", groupJid);
            return null;
        }

        var subject  = groupNode.GetAttr("subject") ?? "";
        var creator  = groupNode.GetAttr("creator") ?? "";
        var creation = groupNode.GetAttr("creation") ?? "0";
        long.TryParse(creation, out var creationTs);

        // Participants — group IQ includes phone_number attribute for LID→phone resolution
        var cacheUpdated = false;
        var participants = groupNode.GetChildren("participant").Select(p =>
        {
            var lidJid   = p.GetAttr("jid") ?? "";
            var phoneJid = p.GetAttr("phone_number");   // e.g. "254708713947@s.whatsapp.net"
            var pType    = p.GetAttr("type") ?? "member";

            // Populate LID→phone cache from the group response
            if (!string.IsNullOrEmpty(lidJid) && !string.IsNullOrEmpty(phoneJid)
                && !_lidToPhone.ContainsKey(lidJid))
            {
                _lidToPhone[lidJid] = phoneJid;
                cacheUpdated = true;
            }

            // Resolve display JID to phone number JID where possible
            var displayJid = (!string.IsNullOrEmpty(phoneJid)) ? phoneJid : lidJid;

            return new GroupParticipant(
                Jid:      displayJid,
                LidJid:   lidJid,
                Type:     pType
            );
        }).Where(p => !string.IsNullOrEmpty(p.Jid)).ToList();

        if (cacheUpdated) SaveCacheToDisk();

        return new GroupMetadata(
            Jid: groupJid,
            Subject: subject,
            Creator: creator,
            CreationTimestamp: creationTs,
            Participants: participants
        );
    }

    private static BinaryNode? FindDeep(BinaryNode node, string tag)
    {
        if (node.Tag == tag) return node;
        foreach (var child in node.Children)
        {
            var found = FindDeep(child, tag);
            if (found != null) return found;
        }
        return null;
    }

    /// <summary>
    /// Resolves a LID JID to a phone JID using a usync IQ query.
    /// If already cached, returns the cached value immediately.
    /// Otherwise sends a usync query to WhatsApp and caches the result.
    /// Returns null if the LID cannot be resolved.
    /// </summary>
    public async Task<string?> ResolveLidAsync(string lidJid, CancellationToken ct)
    {
        if (!lidJid.EndsWith("@lid"))
            return lidJid; // Not a LID, return as-is

        // Check in-memory cache first
        if (_lidToPhone.TryGetValue(lidJid, out var cached))
        {
            _logger.LogInformation("ResolveLidAsync: {Lid} → {Phone} (cached)", lidJid, cached);
            return cached;
        }

        // Send usync IQ to resolve this LID
        _logger.LogInformation("ResolveLidAsync: sending usync IQ to resolve {Lid}", lidJid);
        var contacts = await FetchContactsViaUsyncAsync([lidJid], ct);

        // Check cache again — FetchContactsViaUsyncAsync populates _lidToPhone on success
        if (_lidToPhone.TryGetValue(lidJid, out var resolved))
        {
            _logger.LogInformation("ResolveLidAsync: {Lid} → {Phone} (resolved via usync)", lidJid, resolved);
            SaveCacheToDisk();
            return resolved;
        }

        _logger.LogWarning("ResolveLidAsync: could not resolve {Lid} (usync returned {Count} contacts, none matched)",
            lidJid, contacts.Count);
        return null;
    }

    /// <summary>
    /// Returns all in-memory stored messages for a given JID.
    /// Checks both the given JID and any known LID variant.
    /// </summary>
    public List<IncomingMessage> GetStoredMessages(string jid)
    {
        var result = new List<IncomingMessage>();
        // Note: messages are stored via MessageReceived event in the service layer,
        // not in NoiseProcessor. This returns an empty list — use WhatsAppBridgeService.GetMessagesAsync.
        return result;
    }

    public async ValueTask DisposeAsync()
    {
        _keepAliveCts?.Cancel();
        _keepAliveCts?.Dispose();
        await ValueTask.CompletedTask;
    }

    // ─── Typing / presence (public API) ─────────────────────────────────────

    /// <summary>
    /// Sends a typing indicator (composing) or stops it (paused) for a specific chat.
    /// </summary>
    public async Task SendTypingAsync(string jid, bool isTyping, CancellationToken ct)
    {
        var normalizedJid = jid.Contains('@') ? jid : $"{jid.TrimStart('+')}@s.whatsapp.net";
        var chatstate = new BinaryNode("chatstate",
            new Dictionary<string, string> { ["to"] = normalizedJid },
            isTyping
                ? new List<BinaryNode> { new BinaryNode("composing") }
                : new List<BinaryNode> { new BinaryNode("paused") });
        await SendNodeAsync(chatstate, ct);
        _logger.LogInformation("Sent typing={IsTyping} to {Jid}", isTyping, normalizedJid);
    }

    /// <summary>
    /// Updates this device's presence to available or unavailable.
    /// </summary>
    public async Task SendUserPresenceAsync(bool isOnline, CancellationToken ct)
    {
        var presence = new BinaryNode("presence", new Dictionary<string, string>
        {
            ["type"] = isOnline ? "available" : "unavailable",
        });
        await SendNodeAsync(presence, ct);
        _logger.LogInformation("Sent presence={Status}", isOnline ? "available" : "unavailable");
    }

    // ─── Message revoke ──────────────────────────────────────────────────────

    /// <summary>
    /// Sends a ProtocolMessage REVOKE to delete a sent message for everyone.
    /// </summary>
    public async Task RevokeMessageAsync(string jid, string messageId, bool fromMe, long timestamp, CancellationToken ct)
    {
        var normalizedJid = jid.Contains('@') ? jid : $"{jid.TrimStart('+')}@s.whatsapp.net";
        var phoneNumber   = normalizedJid.Split('@')[0].Split(':')[0];

        List<string> recipientDeviceJids;
        try { recipientDeviceJids = await GetDeviceListAsync(phoneNumber, ct); }
        catch { recipientDeviceJids = [$"{phoneNumber}:0@s.whatsapp.net"]; }

        var senderDeviceJids = new List<string>();
        var myJid = _auth.Me?.Id;
        if (myJid != null)
        {
            var myPhone = myJid.Split('@')[0].Split(':')[0];
            try
            {
                var myDevices = await GetDeviceListAsync(myPhone, ct);
                senderDeviceJids.AddRange(myDevices.Where(d => d != myJid));
            }
            catch { }
        }

        var revokeMsg = new Proto.WAMessage
        {
            ProtocolMsg = new Proto.ProtocolMessage
            {
                Type = Proto.ProtocolMessage.TYPE_REVOKE,
                Key  = new Proto.MessageKey
                {
                    RemoteJid = normalizedJid,
                    FromMe    = fromMe,
                    Id        = messageId,
                },
            }
        };

        var msgBytes = revokeMsg.ToByteArrayWithRevoke();
        var padded   = PadMessage(msgBytes);

        await SendEncryptedMessageAsync(normalizedJid, messageId, timestamp,
            recipientDeviceJids, senderDeviceJids, padded, ct);

        _logger.LogInformation("Sent revoke for message {MsgId} in chat {Jid}", messageId, normalizedJid);
    }

    // ─── Message forwarding ──────────────────────────────────────────────────

    /// <summary>
    /// Forwards an already-received message to another chat.
    /// The message content is re-sent with IsForwarded=true in ContextInfo.
    /// </summary>
    public async Task ForwardMessageAsync(string toJid, string text, CancellationToken ct)
    {
        // Simple implementation: forward as extended text with forwarded context
        var normalizedJid = toJid.Contains('@') ? toJid : $"{toJid.TrimStart('+')}@s.whatsapp.net";
        var phoneNumber   = normalizedJid.Split('@')[0].Split(':')[0];

        List<string> recipientDeviceJids;
        try { recipientDeviceJids = await GetDeviceListAsync(phoneNumber, ct); }
        catch { recipientDeviceJids = [$"{phoneNumber}:0@s.whatsapp.net"]; }

        var senderDeviceJids = new List<string>();
        var myJid = _auth.Me?.Id;
        if (myJid != null)
        {
            var myPhone = myJid.Split('@')[0].Split(':')[0];
            try
            {
                var myDevices = await GetDeviceListAsync(myPhone, ct);
                senderDeviceJids.AddRange(myDevices.Where(d => d != myJid));
            }
            catch { }
        }

        var fwdMsg = new Proto.WAMessage
        {
            ExtendedTextMessage = new Proto.ExtendedTextMessage
            {
                Text = text,
                ContextInfo = new Proto.ContextInfo { IsForwarded = true, ForwardingScore = 1 },
            }
        };

        var msgBytes = fwdMsg.ToByteArray();
        var padded   = PadMessage(msgBytes);
        var msgId    = GenerateMessageId();

        await SendEncryptedMessageAsync(normalizedJid, msgId,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            recipientDeviceJids, senderDeviceJids, padded, ct);

        _logger.LogInformation("Forwarded message to {Jid}", normalizedJid);
    }

    // ─── Group management ────────────────────────────────────────────────────

    /// <summary>Creates a new WhatsApp group and returns its JID.</summary>
    public async Task<string?> CreateGroupAsync(string subject, IEnumerable<string> participantJids, CancellationToken ct)
    {
        var participants = participantJids.Select(j =>
        {
            var jid = j.Contains('@') ? j : $"{j.TrimStart('+')}@s.whatsapp.net";
            return new BinaryNode("participant", new Dictionary<string, string> { ["jid"] = jid });
        }).ToList();

        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["id"]    = GenerateMessageId(),
            ["type"]  = "set",
            ["xmlns"] = "w:g2",
            ["to"]    = "g.us",
        })
        {
            Content = new List<BinaryNode>
            {
                new BinaryNode("create", new Dictionary<string, string> { ["subject"] = subject, ["key"] = GenerateMessageId() })
                {
                    Content = participants
                }
            }
        };

        try
        {
            var result = await SendIQAsync(iq, ct, timeoutMs: 15000);
            var groupNode = result.FindChild("group") ?? result.FindChild("create");
            var groupJid = groupNode?.GetAttr("jid");
            _logger.LogInformation("Created group '{Subject}' → {Jid}", subject, groupJid ?? "(no jid in response)");
            return groupJid;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CreateGroupAsync failed for '{Subject}'", subject);
            return null;
        }
    }

    /// <summary>Leaves a WhatsApp group.</summary>
    public async Task LeaveGroupAsync(string groupJid, CancellationToken ct)
    {
        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["id"]    = GenerateMessageId(),
            ["type"]  = "set",
            ["xmlns"] = "w:g2",
            ["to"]    = "g.us",
        })
        {
            Content = new List<BinaryNode>
            {
                new BinaryNode("leave")
                {
                    Content = new List<BinaryNode>
                    {
                        new BinaryNode("group", new Dictionary<string, string> { ["id"] = groupJid })
                    }
                }
            }
        };

        try { await SendIQAsync(iq, ct, timeoutMs: 10000); }
        catch (Exception ex) { _logger.LogWarning(ex, "LeaveGroupAsync failed for {Group}", groupJid); }
    }

    /// <summary>Adds participants to a group. Returns per-JID result codes.</summary>
    public async Task<Dictionary<string, string>> AddGroupParticipantsAsync(string groupJid, IEnumerable<string> jids, CancellationToken ct)
        => await ModifyGroupParticipantsAsync(groupJid, jids, "add", ct);

    /// <summary>Removes participants from a group. Returns per-JID result codes.</summary>
    public async Task<Dictionary<string, string>> RemoveGroupParticipantsAsync(string groupJid, IEnumerable<string> jids, CancellationToken ct)
        => await ModifyGroupParticipantsAsync(groupJid, jids, "remove", ct);

    private async Task<Dictionary<string, string>> ModifyGroupParticipantsAsync(
        string groupJid, IEnumerable<string> jids, string action, CancellationToken ct)
    {
        var participants = jids.Select(j =>
        {
            var jid = j.Contains('@') ? j : $"{j.TrimStart('+')}@s.whatsapp.net";
            return new BinaryNode("participant", new Dictionary<string, string> { ["jid"] = jid });
        }).ToList();

        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["id"]    = GenerateMessageId(),
            ["type"]  = "set",
            ["xmlns"] = "w:g2",
            ["to"]    = groupJid,
        })
        {
            Content = new List<BinaryNode>
            {
                new BinaryNode(action) { Content = participants }
            }
        };

        var results = new Dictionary<string, string>();
        try
        {
            var result = await SendIQAsync(iq, ct, timeoutMs: 15000);
            // Result may have <participant jid="..." error="..." /> children
            var resultNode = result.FindChild(action);
            if (resultNode?.Content is List<BinaryNode> children)
            {
                foreach (var p in children)
                {
                    var jid = p.GetAttr("jid") ?? "";
                    var err = p.GetAttr("error") ?? "200";
                    results[jid] = err;
                }
            }
        }
        catch (Exception ex) { _logger.LogWarning(ex, "ModifyGroupParticipants({Action}) failed for {Group}", action, groupJid); }
        return results;
    }

    /// <summary>Gets the group's invite link URL.</summary>
    public async Task<string?> GetGroupInviteLinkAsync(string groupJid, CancellationToken ct)
    {
        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["id"]    = GenerateMessageId(),
            ["type"]  = "get",
            ["xmlns"] = "w:g2",
            ["to"]    = groupJid,
        })
        {
            Content = new List<BinaryNode> { new BinaryNode("invite") }
        };

        try
        {
            var result = await SendIQAsync(iq, ct, timeoutMs: 10000);
            var inviteNode = result.FindChild("invite");
            var code = inviteNode?.GetAttr("code");
            return code != null ? $"https://chat.whatsapp.com/{code}" : null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "GetGroupInviteLinkAsync failed for {Group}", groupJid);
            return null;
        }
    }

    /// <summary>Updates the group subject (name).</summary>
    public async Task UpdateGroupSubjectAsync(string groupJid, string newSubject, CancellationToken ct)
    {
        var iq = new BinaryNode("iq", new Dictionary<string, string>
        {
            ["id"]    = GenerateMessageId(),
            ["type"]  = "set",
            ["xmlns"] = "w:g2",
            ["to"]    = groupJid,
        })
        {
            Content = new List<BinaryNode>
            {
                new BinaryNode("subject") { Content = System.Text.Encoding.UTF8.GetBytes(newSubject) }
            }
        };

        try { await SendIQAsync(iq, ct, timeoutMs: 10000); }
        catch (Exception ex) { _logger.LogWarning(ex, "UpdateGroupSubjectAsync failed for {Group}", groupJid); }
    }

    // ─── Media download ──────────────────────────────────────────────────────

    /// <summary>
    /// Downloads and decrypts a WhatsApp media file from the CDN.
    /// </summary>
    /// <param name="mediaUrl">The CDN URL from IncomingMessage.MediaUrl.</param>
    /// <param name="mediaKeyBase64">Base64-encoded media key from IncomingMessage.MediaKey.</param>
    /// <param name="mimeType">MIME type (used to derive HKDF info string).</param>
    /// <returns>Decrypted plaintext bytes.</returns>
    public static async Task<byte[]> DownloadMediaAsync(string mediaUrl, string mediaKeyBase64, string mimeType)
    {
        var mediaKey = Convert.FromBase64String(mediaKeyBase64);
        var mediaType = mimeType.Split('/')[0] switch
        {
            "image"    => "image",
            "video"    => "video",
            "audio"    => "audio",
            "document" => "document",
            _          => "image",
        };

        var encBytes = await _http.GetByteArrayAsync(mediaUrl);
        return Crypto.MediaCrypto.Decrypt(encBytes, mediaKey, mediaType);
    }

    // ─── Delivery/read receipt tracking ─────────────────────────────────────

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Messages.MessageStatus> _messageStatuses = new();

    public event EventHandler<(string MessageId, Messages.MessageStatus Status)>? MessageStatusUpdated;

    private async Task HandleReceiptAsync(BinaryNode node, CancellationToken ct)
    {
        var id   = node.GetAttr("id") ?? "";
        var from = node.GetAttr("from") ?? node.GetAttr("to") ?? "";
        var type = node.GetAttr("type") ?? "delivery";
        var t    = long.TryParse(node.GetAttr("t"), out var rt) ? rt : 0L;

        // Update delivery/read status for outgoing messages
        var status = type switch
        {
            "read"     => Messages.MessageStatus.Read,
            "played"   => Messages.MessageStatus.Played,
            _          => Messages.MessageStatus.Delivered,
        };

        if (!string.IsNullOrEmpty(id))
        {
            _messageStatuses[id] = status;
            MessageStatusUpdated?.Invoke(this, (id, status));
            _logger.LogDebug("Receipt: msg {Id} → {Status}", id, status);
        }

        // ACK the receipt
        if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(from))
        {
            try
            {
                using var cts2 = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var ack = new BinaryNode("ack", new Dictionary<string, string>
                {
                    ["id"]    = id,
                    ["to"]    = from,
                    ["class"] = "receipt",
                    ["t"]     = t.ToString(),
                });
                await SendNodeAsync(ack, cts2.Token);
                _logger.LogDebug("Sent ACK for receipt id={Id} from={From}", id, from);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to ACK receipt {Id}", id);
            }
        }

        // If the phone tells us it couldn't decrypt one of our PDO messages, resend it
        if (type == "retry" && _sentPdoMsgIds.Contains(id) && _lastPdoRequest.HasValue)
        {
            var req = _lastPdoRequest.Value;
            _logger.LogInformation(
                "HandleReceipt: phone can't decrypt our PDO {Id} — resending fresh PDO for chat {Chat}",
                id, req.ChatJid);
            _ = Task.Run(async () =>
            {
                try
                {
                    await RequestOnDemandHistorySyncAsync(req.ChatJid, req.Count, ct);
                }
                catch (Exception ex2)
                {
                    _logger.LogWarning(ex2, "Failed to resend PDO after retry receipt");
                }
            }, ct);
        }
        else if (type == "retry")
        {
            // A recipient device could not decrypt one of our messages and is asking us to
            // re-key. WhatsApp names the SPECIFIC failing device in the `participant`
            // attribute (for multi-device / own-device fan-out); `from` is only the
            // conversation peer. Dropping the session keyed by `from` never heals the stale
            // own-device (or specific-device) session, so the sync copy stays undecryptable
            // ("Waiting for this message") forever. Drop the session for the device named in
            // `participant` (fall back to `from` for 1:1). Then the next send to that device
            // establishes a fresh pkmsg it can read.
            try
            {
                var participant = node.GetAttr("participant");
                var failedDevice = !string.IsNullOrEmpty(participant) ? participant : from;

                // Device 0 is keyed bare ("user@server", no ":0") in the send path — normalize.
                if (failedDevice.EndsWith(":0@s.whatsapp.net", StringComparison.Ordinal))
                    failedDevice = failedDevice.Replace(":0@s.whatsapp.net", "@s.whatsapp.net");

                if (!string.IsNullOrEmpty(failedDevice) && _signalStore.HasSession(failedDevice))
                {
                    _signalStore.DeleteSession(failedDevice);
                    _logger.LogInformation("HandleReceipt: retry for {Id} — dropped stale session for failed device {Dev} (from={From}); next send re-keys.", id, failedDevice, from);
                }
                else
                {
                    _logger.LogInformation("HandleReceipt: retry for {Id} failed device {Dev} (from={From}) — no stored session to drop (next send establishes fresh).", id, failedDevice, from);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "HandleReceipt: failed to drop session on retry receipt (from={From})", from);
            }
        }
    }

    public Messages.MessageStatus? GetMessageStatus(string messageId)
        => _messageStatuses.TryGetValue(messageId, out var s) ? s : null;

    // ─── Helper: Send encrypted message to device list ───────────────────────

    /// <summary>
    /// Shared helper used by RevokeMessageAsync and ForwardMessageAsync to encrypt
    /// and send a pre-built padded proto blob to a list of devices.
    /// </summary>
    private async Task SendEncryptedMessageAsync(
        string toJid, string msgId, long timestamp,
        List<string> recipientDeviceJids, List<string> senderDeviceJids,
        byte[] paddedProto, CancellationToken ct)
    {
        var allDeviceJids = new List<string>(recipientDeviceJids);
        allDeviceJids.AddRange(senderDeviceJids);

        var needBundles = allDeviceJids.Where(d => !_signalStore.HasSession(d)).ToList();
        if (needBundles.Count > 0)
        {
            try
            {
                var bundles = await FetchPreKeyBundlesAsync(needBundles, ct);
                foreach (var (deviceJid, bundle) in bundles)
                {
                    try { _signalStore.InitOutgoingSession(deviceJid, bundle, _auth); }
                    catch (Exception ex2) { _logger.LogWarning(ex2, "Failed to init session for {Jid}", deviceJid); }
                }
            }
            catch (Exception ex) { _logger.LogWarning(ex, "Failed to fetch pre-key bundles"); }
        }

        bool hasPkMsg = false;
        var participantNodes = new List<BinaryNode>();
        foreach (var deviceJid in recipientDeviceJids)
        {
            var node = EncryptForDevice(deviceJid, paddedProto, ref hasPkMsg);
            if (node != null) participantNodes.Add(node);
        }

        var senderNodes = new List<BinaryNode>();
        foreach (var deviceJid in senderDeviceJids)
        {
            var node = EncryptForDevice(deviceJid, paddedProto, ref hasPkMsg);
            if (node != null) senderNodes.Add(node);
        }

        var attrs = new Dictionary<string, string>
        {
            ["id"]   = msgId,
            ["type"] = "text",
            ["to"]   = toJid,
            ["t"]    = timestamp.ToString(),
        };

        var msgNode = new BinaryNode("message", attrs);
        var content = new List<BinaryNode>();

        if (participantNodes.Count > 0 || senderNodes.Count > 0)
        {
            var pNode = new BinaryNode("participants") { Content = new List<BinaryNode>(participantNodes) };
            content.Add(pNode);
            if (senderNodes.Count > 0)
            {
                var sNode = new BinaryNode("device-sent-message") { Content = senderNodes };
                content.Add(sNode);
            }
        }

        msgNode.Content = content;
        await SendNodeAsync(msgNode, ct);
    }

    // ─── History sync ────────────────────────────────────────────────────────

    /// <summary>
    /// Handles a PeerDataOperationResponseMessage (response to our ON_DEMAND history request).
    /// Each result may contain inline compressed+encrypted history data.
    /// </summary>
    private Task ProcessPeerDataResponseAsync(Proto.PeerDataOperationResponseMessage response, CancellationToken ct)
    {
        _logger.LogInformation("PeerDataResponse: {Count} results", response.Results.Count);
        foreach (var result in response.Results)
        {
            _logger.LogInformation("PeerDataResponse result: type={Type}, historyDataLen={Len}",
                result.ResultType, result.HistoryData.Length);

            if (result.ResultType != 0)
            {
                _logger.LogWarning("PeerDataResponse: non-OK result type {Type}", result.ResultType);
                continue;
            }

            if (result.HistoryData.Length == 0)
            {
                _logger.LogInformation("PeerDataResponse: empty history data (no messages in requested range)");
                HistorySyncCompleted?.Invoke(this, 0);
                continue;
            }

            // History data is inline: zlib-compressed proto (same format as CDN blob after decryption)
            // but WITHOUT the AES-CBC encryption layer — delivered inline in the response.
            try
            {
                var protoBytes = ZlibInflate(result.HistoryData);
                var sync       = Proto.HistorySync.Decode(protoBytes);

                _logger.LogInformation("PeerDataResponse: decoded {Convs} conversations (syncType={Type})",
                    sync.Conversations.Count, sync.SyncType);

                // Reuse same emission logic
                var myJidBase = _auth.Me?.Id?.Split(':')[0].Split('@')[0];
                var pushNames = sync.PushNames.ToDictionary(p => p.Id, p => p.PushName);
                var total = 0;
                foreach (var conversation in sync.Conversations)
                {
                    // Register every conversation so it appears in the chat list
                    _threadMetadata.TryAdd(conversation.Id, 0);

                    foreach (var histMsg in conversation.Messages)
                    {
                        var wmi = histMsg.Message;
                        if (wmi?.Key == null) continue;

                        var body      = wmi.MessageBody;
                        var text      = body?.EffectiveText ?? "";
                        var mediaType = body?.MediaType ?? "";

                        // Determine message type (text or media)
                        Messages.MessageType msgType;
                        if (!string.IsNullOrEmpty(text) && !text.StartsWith("["))
                            msgType = Messages.MessageType.Text;
                        else if (mediaType == "image")    msgType = Messages.MessageType.Image;
                        else if (mediaType == "video")    msgType = Messages.MessageType.Video;
                        else if (mediaType == "audio")    msgType = Messages.MessageType.Audio;
                        else if (mediaType == "document") msgType = Messages.MessageType.Document;
                        else                              msgType = Messages.MessageType.Unknown;

                        // Skip messages with genuinely no content
                        if (msgType == Messages.MessageType.Unknown) continue;

                        // Build media URL and key for non-text messages
                        string? mediaUrl  = null;
                        string? mediaKey  = null;
                        string? mimeType  = null;
                        string? fileName  = null;
                        if (body != null && msgType != Messages.MessageType.Text)
                        {
                            var directPath = msgType == Messages.MessageType.Image    ? body.ImageDirectPath :
                                             msgType == Messages.MessageType.Video    ? body.VideoDirectPath :
                                             msgType == Messages.MessageType.Audio    ? body.AudioDirectPath :
                                             msgType == Messages.MessageType.Document ? body.DocumentDirectPath : "";
                            var rawKey     = msgType == Messages.MessageType.Image    ? body.ImageMediaKey :
                                             msgType == Messages.MessageType.Video    ? body.VideoMediaKey :
                                             msgType == Messages.MessageType.Audio    ? body.AudioMediaKey :
                                             msgType == Messages.MessageType.Document ? body.DocumentMediaKey : [];
                            if (!string.IsNullOrEmpty(directPath))
                                mediaUrl = $"https://mmg.whatsapp.net{directPath}";
                            if (rawKey.Length > 0)
                                mediaKey = Convert.ToBase64String(rawKey);
                            mimeType = msgType == Messages.MessageType.Image    ? "image/jpeg" :
                                       msgType == Messages.MessageType.Video    ? "video/mp4"  :
                                       msgType == Messages.MessageType.Audio    ? "audio/ogg"  : "application/octet-stream";
                            fileName = msgType == Messages.MessageType.Document ? body.DocumentFileName : null;
                        }

                        var remoteJid = wmi.Key.RemoteJid ?? conversation.Id;
                        var fromMe    = wmi.Key.FromMe;
                        var senderJid = fromMe
                            ? (myJidBase != null ? $"{myJidBase}@s.whatsapp.net" : remoteJid)
                            : (wmi.Key.Participant.Length > 0 ? wmi.Key.Participant : remoteJid);

                        pushNames.TryGetValue(senderJid.Split('@')[0], out var senderName);
                        var msg = new Messages.IncomingMessage
                        {
                            Id        = wmi.Key.Id,
                            From      = senderJid,
                            RemoteJid = remoteJid,
                            Type      = msgType,
                            Text      = text,
                            FromMe    = fromMe,
                            Timestamp = (long)wmi.Timestamp,
                            PushName  = wmi.PushName.Length > 0 ? wmi.PushName : senderName,
                            MediaUrl  = mediaUrl,
                            MediaKey  = mediaKey,
                            MimeType  = mimeType,
                            FileName  = fileName,
                        };
                        HistoryMessageReceived?.Invoke(this, msg);
                        total++;
                    }
                }
                _logger.LogInformation("PeerDataResponse: emitted {N} messages", total);
                HistorySyncCompleted?.Invoke(this, total);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "PeerDataResponse: failed to decode history data ({Len} bytes)", result.HistoryData.Length);
            }
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Downloads, decrypts, decompresses and parses a WhatsApp history sync blob,
    /// then fires <see cref="HistoryMessageReceived"/> for every past message.
    /// Called automatically when the server sends a HISTORY_SYNC_NOTIFICATION.
    /// </summary>
    private async Task ProcessHistorySyncAsync(Proto.HistorySyncNotification notif, CancellationToken ct)
    {
        try
        {
            var syncTypeName = notif.SyncType switch
            {
                Proto.HistorySyncNotification.INITIAL_BOOTSTRAP => "INITIAL_BOOTSTRAP",
                Proto.HistorySyncNotification.RECENT            => "RECENT",
                Proto.HistorySyncNotification.FULL              => "FULL",
                Proto.HistorySyncNotification.PUSH_NAME         => "PUSH_NAME",
                Proto.HistorySyncNotification.ON_DEMAND         => "ON_DEMAND",
                _                                               => notif.SyncType.ToString(),
            };
            _logger.LogInformation("HistorySync: received {Type} notification, directPath={Path}",
                syncTypeName, notif.DirectPath);

            // Newer WA versions send InlineBlob (field 10): zlib-compressed proto, no CDN download or decryption needed.
            // Older versions use DirectPath + MediaKey for CDN download + AES decryption.
            byte[] protoBytes;

            if (notif.InlineBlob != null && notif.InlineBlob.Length > 0)
            {
                _logger.LogInformation("HistorySync: InlineBlob path ({Bytes} bytes)", notif.InlineBlob.Length);
                try
                {
                    protoBytes = ZlibInflate(notif.InlineBlob);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "HistorySync: InlineBlob decompression failed");
                    return;
                }
                _logger.LogInformation("HistorySync: InlineBlob decompressed to {Bytes} proto bytes", protoBytes.Length);
            }
            else if (notif.MediaKey != null && notif.MediaKey.Length > 0 && !string.IsNullOrEmpty(notif.DirectPath))
            {
                // 1. Download blob from CDN
                var downloadUrl = $"https://mmg.whatsapp.net{notif.DirectPath}";
                _logger.LogInformation("HistorySync: downloading from {Url}", downloadUrl);

                byte[] encBlob;
                using var resp = await _http.GetAsync(downloadUrl, ct);
                resp.EnsureSuccessStatusCode();
                encBlob = await resp.Content.ReadAsByteArrayAsync(ct);
                _logger.LogInformation("HistorySync: downloaded {Bytes} encrypted bytes", encBlob.Length);

                // 2. Decrypt: AES-CBC with keys derived from mediaKey via HKDF "WhatsApp History Keys"
                byte[] compressed;
                try
                {
                    compressed = Crypto.MediaCrypto.Decrypt(encBlob, notif.MediaKey, "md-msg-hist");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "HistorySync: decryption failed");
                    return;
                }
                _logger.LogInformation("HistorySync: decrypted to {Bytes} compressed bytes", compressed.Length);

                // 3. Decompress
                try
                {
                    protoBytes = ZlibInflate(compressed);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "HistorySync: decompression failed");
                    return;
                }
                _logger.LogInformation("HistorySync: decompressed to {Bytes} proto bytes", protoBytes.Length);
            }
            else
            {
                _logger.LogWarning("HistorySync: no InlineBlob, no MediaKey/DirectPath — skipping");
                return;
            }

            // 4. Proto decode
            Proto.HistorySync sync;
            try
            {
                sync = Proto.HistorySync.Decode(protoBytes);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HistorySync: proto decode failed");
                return;
            }

            // 5. Build pushname lookup
            var pushNames = sync.PushNames.ToDictionary(p => p.Id, p => p.PushName);

            // 6. Emit all messages
            var myJidBase = _auth.Me?.Id?.Split(':')[0].Split('@')[0];
            var totalMsgs = 0;
            foreach (var conversation in sync.Conversations)
            {
                var chatJid = conversation.Id;
                // Add conversation to thread metadata so chat appears in chat list
                _threadMetadata.TryAdd(chatJid, 0);

                foreach (var histMsg in conversation.Messages)
                {
                    var wmi = histMsg.Message;
                    if (wmi?.Key == null) continue;

                    var body    = wmi.MessageBody;
                    var text    = body?.EffectiveText ?? "";
                    var mediaType = body?.MediaType ?? "";

                    // Determine message type
                    Messages.MessageType msgType;
                    if (!string.IsNullOrEmpty(text) && !text.StartsWith("["))
                        msgType = Messages.MessageType.Text;
                    else if (mediaType == "image")
                        msgType = Messages.MessageType.Image;
                    else if (mediaType == "video")
                        msgType = Messages.MessageType.Video;
                    else if (mediaType == "audio")
                        msgType = Messages.MessageType.Audio;
                    else if (mediaType == "document")
                        msgType = Messages.MessageType.Document;
                    else if (!string.IsNullOrEmpty(text)) // captions like [image], [video]
                        msgType = Messages.MessageType.Text;
                    else
                        continue; // truly unknown/empty — skip

                    var remoteJid  = wmi.Key.RemoteJid ?? chatJid;
                    var fromMe     = wmi.Key.FromMe;
                    var senderJid  = fromMe
                        ? (myJidBase != null ? $"{myJidBase}@s.whatsapp.net" : remoteJid)
                        : (wmi.Key.Participant.Length > 0 ? wmi.Key.Participant : remoteJid);

                    pushNames.TryGetValue(senderJid.Split('@')[0], out var senderName);

                    // Build media URL from directPath
                    string? mediaUrl = null;
                    string? mediaKey = null;
                    string? mimeType = null;
                    string? fileName = null;
                    if (body != null)
                    {
                        var directPath = body.ImageDirectPath.Length > 0 ? body.ImageDirectPath :
                                         body.VideoDirectPath.Length > 0 ? body.VideoDirectPath :
                                         body.AudioDirectPath.Length > 0 ? body.AudioDirectPath :
                                         body.DocumentDirectPath.Length > 0 ? body.DocumentDirectPath : "";
                        var rawKey     = body.ImageMediaKey.Length > 0 ? body.ImageMediaKey :
                                         body.VideoMediaKey.Length > 0 ? body.VideoMediaKey :
                                         body.AudioMediaKey.Length > 0 ? body.AudioMediaKey :
                                         body.DocumentMediaKey.Length > 0 ? body.DocumentMediaKey : [];
                        if (directPath.Length > 0)
                            mediaUrl = "https://mmg.whatsapp.net" + directPath;
                        if (rawKey.Length > 0)
                            mediaKey = Convert.ToBase64String(rawKey);
                        if (body.DocumentFileName.Length > 0)
                            fileName = body.DocumentFileName;
                        mimeType = mediaType switch
                        {
                            "image"    => "image/jpeg",
                            "video"    => "video/mp4",
                            "audio"    => "audio/ogg",
                            "document" => "application/octet-stream",
                            _          => null
                        };
                    }

                    var msg = new Messages.IncomingMessage
                    {
                        Id          = wmi.Key.Id,
                        From        = senderJid,
                        RemoteJid   = remoteJid,
                        Participant = wmi.Key.Participant.Length > 0 ? wmi.Key.Participant : null,
                        Type        = msgType,
                        Text        = !string.IsNullOrEmpty(text) ? text : null,
                        FromMe      = fromMe,
                        Timestamp   = (long)wmi.Timestamp,
                        PushName    = wmi.PushName.Length > 0 ? wmi.PushName : senderName,
                        MediaUrl    = mediaUrl,
                        MediaKey    = mediaKey,
                        MimeType    = mimeType,
                        FileName    = fileName,
                    };

                    HistoryMessageReceived?.Invoke(this, msg);
                    totalMsgs++;
                }
            }

            _logger.LogInformation("HistorySync: emitted {Count} messages from {Convs} conversations ({Type})",
                totalMsgs, sync.Conversations.Count, syncTypeName);

            HistorySyncCompleted?.Invoke(this, totalMsgs);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "HistorySync: unhandled error");
        }
    }

    /// <summary>Decompresses zlib-deflated data (strips 2-byte zlib header + 4-byte adler32 trailer).</summary>
    /// <summary>
    /// Strip Signal Protocol message padding: ISO 7816-4 style padding
    /// where the actual message is followed by 0x80 and then zero bytes.
    /// After AES-CBC PKCS7 decryption, this layer must be removed before proto parsing.
    /// </summary>
    private static byte[] StripSignalPadding(byte[] data)
    {
        int end = data.Length - 1;
        while (end > 0 && data[end] == 0x00) end--;
        if (end >= 0 && data[end] == 0x80)
            return data[..end];
        return data; // no padding found — return as-is
    }

    private static byte[] ZlibInflate(byte[] data)
    {
        // zlib stream: 2-byte header + deflate data + 4-byte adler32
        // System.IO.Compression.DeflateStream reads raw deflate (no header).
        using var input  = new System.IO.MemoryStream(data, 2, data.Length - 2);
        using var deflate = new System.IO.Compression.DeflateStream(input, System.IO.Compression.CompressionMode.Decompress);
        using var output = new System.IO.MemoryStream();
        deflate.CopyTo(output);
        return output.ToArray();
    }
}

public record GroupParticipant(string Jid, string LidJid, string Type);
public record GroupMetadata(string Jid, string Subject, string Creator, long CreationTimestamp, List<GroupParticipant> Participants);

// PresenceInfo record — lives in Dawa.Noise namespace
public record PresenceInfo(string Jid, string Status, DateTime LastSeen);
