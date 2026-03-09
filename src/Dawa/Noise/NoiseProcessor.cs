using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dawa.Auth;
using Dawa.Binary;
using Dawa.Crypto;
using Dawa.Messages;
using Dawa.Proto;
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
    // WhatsApp prologue bytes: "WA" + protocol version
    private static readonly byte[] WA_PROLOGUE = [0x57, 0x41, 0x05, 0x02];

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

    public event EventHandler<string>? QRCodeGenerated;
    public event EventHandler<AuthState>? Authenticated;
    public event EventHandler<IncomingMessage>? MessageReceived;

    public NoiseProcessor(FrameSocket socket, AuthState auth, WhatsAppClientOptions options, ILogger logger)
    {
        _socket = socket;
        _auth = auth;
        _options = options;
        _logger = logger;

        (_ephemeralPriv, _ephemeralPub) = Curve25519Helper.GenerateKeyPair();
    }

    // ─── Handshake ───────────────────────────────────────────────────────────

    /// <summary>
    /// Performs the complete Noise XX handshake with the WhatsApp server.
    /// </summary>
    public async Task PerformHandshakeAsync(CancellationToken ct)
    {
        var noise = new NoiseState();

        // Mix prologue into hash
        noise.MixHash(WA_PROLOGUE);
        noise.MixHash(_auth.NoiseKeyPublic);  // static public key as part of prologue

        // ── Phase 1: Send ClientHello with our ephemeral key ──────────────────
        noise.MixHash(_ephemeralPub);

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

        _logger.LogInformation("Noise: Handshake complete. Transport keys established.");

        // Now handle the post-handshake authentication (QR or session restore)
        await HandlePostHandshakeAsync(ct);
    }

    // ─── Post-Handshake Auth ────────────────────────────────────────────────

    private async Task HandlePostHandshakeAsync(CancellationToken ct)
    {
        // The server will send us a "stream:features" or similar to start the session.
        // For a fresh connection, we need to request QR code or restore the session.

        if (_auth.IsFresh)
        {
            _logger.LogInformation("Fresh session — requesting QR code pairing.");
            await RequestPairingAsync(ct);
        }
        else
        {
            _logger.LogInformation("Restoring existing session for {Me}", _auth.Me?.Id);
            await RestoreSessionAsync(ct);
        }
    }

    private async Task RequestPairingAsync(CancellationToken ct)
    {
        // Send a "pair" IQ to get QR code ref from server
        var msgId = GenerateMessageId();
        var iqNode = new BinaryNode("iq", new()
        {
            ["id"] = msgId,
            ["type"] = "set",
            ["xmlns"] = "md",
            ["to"] = "@s.whatsapp.net",
        }, new List<BinaryNode>
        {
            new("pair-device", new()
            {
                ["ref-key"] = Convert.ToBase64String(_auth.AdvSecretKey),
            })
        });

        await SendNodeAsync(iqNode, ct);
        _logger.LogDebug("Sent pair-device IQ ({Id})", msgId);
    }

    private async Task RestoreSessionAsync(CancellationToken ct)
    {
        // Send passive connect to restore session
        var msgId = GenerateMessageId();
        var iqNode = new BinaryNode("iq", new()
        {
            ["id"] = msgId,
            ["type"] = "get",
            ["xmlns"] = "account",
            ["to"] = "s.whatsapp.net",
        });

        await SendNodeAsync(iqNode, ct);
    }

    // ─── Receive loop ───────────────────────────────────────────────────────

    /// <summary>
    /// Continuously reads and processes incoming frames. Call this on a background task.
    /// </summary>
    public async Task ReceiveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _socket.IsConnected)
        {
            try
            {
                var frame = await _socket.ReceiveFrameAsync(ct);
                if (frame == null) break;

                var decrypted = DecryptFrame(frame);
                var node = BinaryNodeDecoder.Decode(decrypted);
                _logger.LogDebug("Received node: {Tag}", node.Tag);

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
    }

    private async Task HandleNodeAsync(BinaryNode node, CancellationToken ct)
    {
        switch (node.Tag)
        {
            case "iq":
                await HandleIQAsync(node, ct);
                break;
            case "message":
                HandleMessageNode(node);
                break;
            case "notification":
                await HandleNotificationAsync(node, ct);
                break;
            case "success":
                _logger.LogInformation("Session authenticated successfully.");
                Authenticated?.Invoke(this, _auth);
                break;
            case "failure":
                _logger.LogWarning("Authentication failure: {Reason}", node.GetAttr("reason"));
                break;
            case "stream:error":
                _logger.LogError("Stream error: {Code}", node.GetAttr("code"));
                break;
            default:
                _logger.LogDebug("Unhandled node tag: {Tag}", node.Tag);
                break;
        }
    }

    private async Task HandleIQAsync(BinaryNode iq, CancellationToken ct)
    {
        var type = iq.GetAttr("type");
        if (type == "result")
        {
            // Check for pair-device result (QR code ref)
            var pairDevice = iq.FindChild("pair-device");
            if (pairDevice != null)
            {
                await HandlePairDeviceResultAsync(pairDevice, ct);
                return;
            }

            // Check for pair-success (phone scanned QR)
            var pairSuccess = iq.FindChild("pair-success");
            if (pairSuccess != null)
            {
                HandlePairSuccess(pairSuccess);
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
                    ["to"] = iq.GetAttr("from") ?? "s.whatsapp.net",
                });
                await SendNodeAsync(ack, ct);
            }
        }
    }

    private async Task HandlePairDeviceResultAsync(BinaryNode pairDevice, CancellationToken ct)
    {
        // Extract ref token from server
        var refNode = pairDevice.FindChild("ref");
        if (refNode?.Text == null) return;

        var ref_ = refNode.Text;
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

    private void HandlePairSuccess(BinaryNode pairSuccess)
    {
        _logger.LogInformation("Pairing successful! Extracting credentials.");

        var platform = pairSuccess.GetAttr("platform") ?? "UNKNOWN";
        _auth.Platform = platform;

        // In a full implementation: extract device ID, JID from the pair-success node,
        // then save them into auth state. This requires decrypting the device identity
        // proof which involves ADV (account data verification).

        // Simplified: extract JID if present
        var deviceNode = pairSuccess.FindChild("device");
        if (deviceNode != null)
        {
            var jid = deviceNode.GetAttr("jid");
            if (!string.IsNullOrEmpty(jid))
            {
                _auth.Me = new MeInfo { Id = jid };
                _logger.LogInformation("Paired as {Jid}", jid);
            }
        }

        Authenticated?.Invoke(this, _auth);
    }

    private void HandleMessageNode(BinaryNode node)
    {
        var from = node.GetAttr("from") ?? "";
        var id = node.GetAttr("id") ?? "";
        var participant = node.GetAttr("participant");
        var pushName = node.GetAttr("notify");
        var fromMe = node.GetAttr("fromMe") == "true" || node.GetAttr("from") == _auth.Me?.Id;

        if (!long.TryParse(node.GetAttr("t"), out var timestamp))
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Extract text content — walk the message body
        string? text = null;
        var body = node.FindChild("body");
        if (body?.Text != null)
            text = body.Text;

        if (string.IsNullOrEmpty(text))
            return; // Skip non-text messages for now

        var msg = new IncomingMessage
        {
            Id = id,
            From = participant ?? from,
            RemoteJid = from,
            Participant = participant,
            Text = text,
            FromMe = fromMe,
            Timestamp = timestamp,
        };

        MessageReceived?.Invoke(this, msg);
    }

    private async Task HandleNotificationAsync(BinaryNode notification, CancellationToken ct)
    {
        // ACK notifications
        var id = notification.GetAttr("id");
        var to = notification.GetAttr("from") ?? "s.whatsapp.net";
        var ack = new BinaryNode("ack", new()
        {
            ["id"] = id ?? "",
            ["to"] = to,
            ["type"] = "notification",
            ["class"] = notification.GetAttr("type") ?? "",
        });
        await SendNodeAsync(ack, ct);
    }

    // ─── Send message ───────────────────────────────────────────────────────

    /// <summary>Sends a text message to a JID.</summary>
    public async Task SendTextMessageAsync(string jid, string text, CancellationToken ct)
    {
        var msgId = GenerateMessageId();
        var msgContent = Encoding.UTF8.GetBytes(text);

        var msgNode = new BinaryNode("message", new()
        {
            ["id"] = msgId,
            ["type"] = "text",
            ["to"] = jid,
        }, new List<BinaryNode>
        {
            new("body", content: text),
        });

        await SendNodeAsync(msgNode, ct);
        _logger.LogInformation("Sent message to {Jid}: {Text}", jid, text.Length > 50 ? text[..50] + "…" : text);
    }

    // ─── Low-level send/receive ─────────────────────────────────────────────

    private async Task SendNodeAsync(BinaryNode node, CancellationToken ct)
    {
        var encoded = BinaryNodeEncoder.Encode(node);
        var encrypted = EncryptFrame(encoded);
        await _socket.SendFrameAsync(encrypted, ct);
    }

    private async Task SendHandshakeMessageAsync(HandshakeMessage msg, CancellationToken ct)
    {
        // During handshake, frames are NOT yet encrypted — send as-is
        var bytes = msg.ToByteArray();
        await _socket.SendFrameAsync(bytes, ct);
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

    private byte[] BuildClientPayload()
    {
        var payload = new ClientPayload
        {
            Passive = !_auth.IsFresh,
            UserAgent = new UserAgent
            {
                AppVersion = new AppVersion { Primary = 2, Secondary = 3000, Tertiary = 1017531287 },
                Platform = 14, // WEB
                OsVersion = "0.1",
                Device = "Desktop",
                Manufacturer = "",
                Mcc = "000",
                Mnc = "000",
                LocaleLanguageIso6391 = "en",
                LocaleCountryIso31661Alpha2 = "en",
            },
            WebInfo = new WebInfo { WebSubPlatform = 0 },
        };

        if (!_auth.IsFresh && _auth.Me != null)
        {
            if (ulong.TryParse(_auth.Me.Id.Split('@')[0], out var userId))
                payload.Username = userId;
        }

        return payload.ToByteArray();
    }

    private static string GenerateMessageId()
    {
        var bytes = RandomNumberGenerator.GetBytes(8);
        return BitConverter.ToString(bytes).Replace("-", "").ToUpper();
    }

    public async ValueTask DisposeAsync()
    {
        // Nothing to dispose here — socket is owned by the caller
        await ValueTask.CompletedTask;
    }
}
