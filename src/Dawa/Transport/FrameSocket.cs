using System.Net.WebSockets;
using Microsoft.Extensions.Logging;

namespace Dawa.Transport;

/// <summary>
/// WebSocket wrapper that adds WhatsApp's 3-byte big-endian length framing.
/// Each frame: [length: 3 bytes BE] [payload: N bytes]
///
/// A single WebSocket message may contain multiple WA frames back-to-back
/// (Baileys: noise-handler.ts processData drains all frames in a loop).
/// We buffer leftover bytes so each ReceiveFrameAsync call returns exactly one frame.
/// </summary>
public sealed class FrameSocket : IAsyncDisposable
{
    private readonly ILogger _logger;
    private ClientWebSocket? _ws;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    // Buffer for bytes received but not yet returned as a complete frame
    private byte[] _recvBuf = [];
    private int _recvLen = 0;

    // WhatsApp server URL
    private const string WA_URL = "wss://web.whatsapp.com/ws/chat";

    public FrameSocket(ILogger logger)
    {
        _logger = logger;
    }

    public bool IsConnected => _ws?.State == WebSocketState.Open;

    public async Task ConnectAsync(string? url = null, byte[]? routingInfo = null, CancellationToken ct = default)
    {
        _ws = new ClientWebSocket();
        _ws.Options.SetRequestHeader("Origin", "https://web.whatsapp.com");
        _ws.Options.SetRequestHeader("Host", "web.whatsapp.com");
        _ws.Options.SetRequestHeader("User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36");
        _ws.Options.SetRequestHeader("Accept-Language", "en-US,en;q=0.9");
        _ws.Options.SetRequestHeader("Cache-Control", "no-cache");
        _ws.Options.SetRequestHeader("Pragma", "no-cache");
        // Sub-protocol is required by WhatsApp's server
        _ws.Options.AddSubProtocol("chat");
        _ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(25);

        // When WhatsApp sends edge_routing, reconnect to the preferred edge server
        // by including the X-WA-Routing header (Baileys: socket.ts fetchOptions.headers)
        if (routingInfo != null && routingInfo.Length > 0)
        {
            _ws.Options.SetRequestHeader("X-WA-Routing", Convert.ToBase64String(routingInfo));
            _logger.LogInformation("FrameSocket: Connecting with X-WA-Routing ({Len} bytes).", routingInfo.Length);
        }

        await _ws.ConnectAsync(new Uri(url ?? WA_URL), ct);
        _logger.LogInformation("FrameSocket: WebSocket connected to {Url}", url ?? WA_URL);
    }

    /// <summary>Sends raw bytes directly to the WebSocket without any framing.</summary>
    public async Task SendRawAsync(byte[] data, CancellationToken ct = default)
    {
        if (_ws == null || _ws.State != WebSocketState.Open)
            throw new InvalidOperationException("WebSocket not connected.");

        await _sendLock.WaitAsync(ct);
        try
        {
            await _ws.SendAsync(data, WebSocketMessageType.Binary, true, ct);
        }
        finally
        {
            _sendLock.Release();
        }

        _logger.LogDebug("FrameSocket: Sent raw {Length} bytes", data.Length);
    }

    /// <summary>Sends a frame: 3-byte BE length + payload.</summary>
    public async Task SendFrameAsync(byte[] payload, CancellationToken ct = default)
    {
        if (_ws == null || _ws.State != WebSocketState.Open)
            throw new InvalidOperationException("WebSocket not connected.");

        var frame = new byte[3 + payload.Length];
        frame[0] = (byte)(payload.Length >> 16);
        frame[1] = (byte)(payload.Length >> 8);
        frame[2] = (byte)(payload.Length);
        payload.CopyTo(frame, 3);

        await _sendLock.WaitAsync(ct);
        try
        {
            await _ws.SendAsync(frame, WebSocketMessageType.Binary, true, ct);
        }
        finally
        {
            _sendLock.Release();
        }

        _logger.LogDebug("FrameSocket: Sent frame {Length} bytes", payload.Length);
    }

    /// <summary>
    /// Reads the next WA frame. If the receive buffer already contains a complete
    /// frame (leftover from a previous WebSocket message), returns it immediately
    /// without touching the network. Otherwise reads one WebSocket message and
    /// appends it to the buffer, then extracts the first complete frame.
    /// Matches Baileys noise-handler.ts processData drain-loop behaviour.
    /// </summary>
    public async Task<byte[]?> ReceiveFrameAsync(CancellationToken ct = default)
    {
        while (true)
        {
            // Try to extract a complete WA frame from the existing buffer
            if (_recvLen >= 3)
            {
                var length = (_recvBuf[0] << 16) | (_recvBuf[1] << 8) | _recvBuf[2];
                if (_recvLen >= 3 + length)
                {
                    var payload = _recvBuf[3..(3 + length)];
                    // Shift remaining bytes to the front
                    var remaining = _recvLen - (3 + length);
                    if (remaining > 0)
                        Buffer.BlockCopy(_recvBuf, 3 + length, _recvBuf, 0, remaining);
                    _recvLen = remaining;
                    _logger.LogDebug("FrameSocket: Extracted frame {Length} bytes (buf remaining={Rem})", length, remaining);
                    return payload;
                }
            }

            // Need more data — read one WebSocket message
            if (_ws == null || _ws.State != WebSocketState.Open)
                return null;

            using var ms = new MemoryStream();
            var wsBuffer = new byte[65536];
            WebSocketReceiveResult result;

            do
            {
                result = await _ws.ReceiveAsync(wsBuffer, ct);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    _logger.LogInformation("FrameSocket: Server sent close frame.");
                    return null;
                }
                ms.Write(wsBuffer, 0, result.Count);
            } while (!result.EndOfMessage);

            var incoming = ms.ToArray();
            _logger.LogInformation("FrameSocket: Raw receive {Length} bytes, type={Type}", incoming.Length, result.MessageType);

            // Append incoming to receive buffer
            EnsureCapacity(incoming.Length);
            Buffer.BlockCopy(incoming, 0, _recvBuf, _recvLen, incoming.Length);
            _recvLen += incoming.Length;
            // Loop back up to try extracting a frame
        }
    }

    private void EnsureCapacity(int additional)
    {
        var needed = _recvLen + additional;
        if (_recvBuf.Length < needed)
        {
            var newBuf = new byte[Math.Max(needed, _recvBuf.Length * 2 + additional)];
            if (_recvLen > 0)
                Buffer.BlockCopy(_recvBuf, 0, newBuf, 0, _recvLen);
            _recvBuf = newBuf;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_ws != null)
        {
            try
            {
                if (_ws.State == WebSocketState.Open)
                    await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
            }
            catch { /* ignore */ }
            _ws.Dispose();
        }
        _sendLock.Dispose();
    }
}
