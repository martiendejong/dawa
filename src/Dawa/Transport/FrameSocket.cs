using System.Net.WebSockets;
using Microsoft.Extensions.Logging;

namespace Dawa.Transport;

/// <summary>
/// WebSocket wrapper that adds WhatsApp's 3-byte big-endian length framing.
/// Each frame: [length: 3 bytes BE] [payload: N bytes]
/// </summary>
public sealed class FrameSocket : IAsyncDisposable
{
    private readonly ILogger _logger;
    private ClientWebSocket? _ws;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    // WhatsApp server URL
    private const string WA_URL = "wss://web.whatsapp.com/ws/chat";

    public FrameSocket(ILogger logger)
    {
        _logger = logger;
    }

    public bool IsConnected => _ws?.State == WebSocketState.Open;

    public async Task ConnectAsync(string? url = null, CancellationToken ct = default)
    {
        _ws = new ClientWebSocket();
        _ws.Options.SetRequestHeader("Origin", "https://web.whatsapp.com");
        _ws.Options.SetRequestHeader("Host", "web.whatsapp.com");
        _ws.Options.SetRequestHeader("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        _ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);

        await _ws.ConnectAsync(new Uri(url ?? WA_URL), ct);
        _logger.LogInformation("FrameSocket: WebSocket connected to {Url}", url ?? WA_URL);
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

    /// <summary>Reads the next frame from the WebSocket, stripping the 3-byte header.</summary>
    public async Task<byte[]?> ReceiveFrameAsync(CancellationToken ct = default)
    {
        if (_ws == null || _ws.State != WebSocketState.Open)
            return null;

        using var ms = new MemoryStream();
        var buffer = new byte[65536];
        WebSocketReceiveResult result;

        do
        {
            result = await _ws.ReceiveAsync(buffer, ct);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                _logger.LogInformation("FrameSocket: Server sent close frame.");
                return null;
            }
            ms.Write(buffer, 0, result.Count);
        } while (!result.EndOfMessage);

        var raw = ms.ToArray();
        if (raw.Length < 3) return null;

        var length = (raw[0] << 16) | (raw[1] << 8) | raw[2];
        if (raw.Length < 3 + length)
        {
            _logger.LogWarning("FrameSocket: Frame length mismatch: header says {Expected}, got {Actual}", length, raw.Length - 3);
            return null;
        }

        var payload = raw[3..(3 + length)];
        _logger.LogDebug("FrameSocket: Received frame {Length} bytes", length);
        return payload;
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
