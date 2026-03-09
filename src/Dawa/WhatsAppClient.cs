using Dawa.Auth;
using Dawa.Messages;
using Dawa.Models;
using Dawa.Noise;
using Dawa.Transport;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dawa;

/// <summary>
/// The main Dawa WhatsApp client. Connects to WhatsApp Web and allows
/// sending and receiving messages without a Node.js dependency.
///
/// Usage:
/// <code>
/// var client = WhatsAppClient.Create("./wa-session");
/// client.QRCodeReceived += (_, qr) => Console.WriteLine("Scan: " + qr);
/// client.MessageReceived += (_, msg) => Console.WriteLine(msg);
/// await client.ConnectAsync();
/// await client.WaitUntilConnectedAsync();
/// await client.SendMessageAsync("+31612345678", "Hello from Dawa!");
/// </code>
/// </summary>
public sealed class WhatsAppClient : IAsyncDisposable
{
    private readonly WhatsAppClientOptions _options;
    private readonly ILogger<WhatsAppClient> _logger;
    private readonly SessionStore _sessionStore;

    private FrameSocket? _frameSocket;
    private NoiseProcessor? _noiseProcessor;
    private ConnectionState _state = ConnectionState.Disconnected;
    private CancellationTokenSource? _cts;
    private TaskCompletionSource<bool>? _connectedTcs;

    // ─── Events ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Fired when a QR code is ready to be scanned.
    /// The string argument is the raw QR code data (pass to a QR renderer).
    /// </summary>
    public event EventHandler<string>? QRCodeReceived;

    /// <summary>Fired when the connection state changes.</summary>
    public event EventHandler<ConnectionState>? ConnectionStateChanged;

    /// <summary>Fired when a new message is received.</summary>
    public event EventHandler<IncomingMessage>? MessageReceived;

    /// <summary>Fired once the session is fully authenticated.</summary>
    public event EventHandler? Connected;

    /// <summary>Fired when the connection is lost.</summary>
    public event EventHandler? Disconnected;

    // ─── Properties ─────────────────────────────────────────────────────────

    public ConnectionState State => _state;
    public bool IsConnected => _state == ConnectionState.Connected;
    public string? MyJid => null; // Set after authentication

    // ─── Construction ────────────────────────────────────────────────────────

    public WhatsAppClient(WhatsAppClientOptions options, ILogger<WhatsAppClient>? logger = null)
    {
        _options = options;
        _logger = logger ?? NullLogger<WhatsAppClient>.Instance;
        _sessionStore = new SessionStore(options.SessionDirectory);
    }

    /// <summary>
    /// Creates a new WhatsApp client with default options.
    /// </summary>
    /// <param name="sessionDirectory">Directory to store session credentials.</param>
    public static WhatsAppClient Create(string sessionDirectory = "./whatsapp-session")
        => new(new WhatsAppClientOptions { SessionDirectory = sessionDirectory });

    /// <summary>
    /// Creates a client with a logger factory (e.g. from dependency injection).
    /// </summary>
    public static WhatsAppClient Create(string sessionDirectory, ILoggerFactory loggerFactory)
        => new(new WhatsAppClientOptions { SessionDirectory = sessionDirectory },
               loggerFactory.CreateLogger<WhatsAppClient>());

    // ─── Connection ──────────────────────────────────────────────────────────

    /// <summary>
    /// Connects to WhatsApp and starts the authentication flow.
    /// If a session exists it restores it; otherwise fires <see cref="QRCodeReceived"/>.
    /// </summary>
    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        if (_state != ConnectionState.Disconnected)
            throw new InvalidOperationException($"Client is already in state {_state}.");

        SetState(ConnectionState.Connecting);
        _connectedTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        try
        {
            var authState = await _sessionStore.LoadAsync(_cts.Token);

            _frameSocket = new FrameSocket(_logger);
            SetState(ConnectionState.Handshaking);
            await _frameSocket.ConnectAsync(ct: _cts.Token);

            _noiseProcessor = new NoiseProcessor(_frameSocket, authState, _options, _logger);
            _noiseProcessor.QRCodeGenerated += (_, qr) =>
            {
                SetState(ConnectionState.Authenticating);
                QRCodeReceived?.Invoke(this, qr);
            };
            _noiseProcessor.Authenticated += async (_, auth) =>
            {
                await _sessionStore.SaveAsync(auth, _cts!.Token);
                SetState(ConnectionState.Connected);
                _connectedTcs?.TrySetResult(true);
                Connected?.Invoke(this, EventArgs.Empty);
            };
            _noiseProcessor.MessageReceived += (_, msg) => MessageReceived?.Invoke(this, msg);

            await _noiseProcessor.PerformHandshakeAsync(_cts.Token);

            // Start background receive loop
            _ = Task.Run(() => RunReceiveLoopAsync(_cts.Token), _cts.Token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Connection failed.");
            SetState(ConnectionState.Disconnected);
            _connectedTcs?.TrySetException(ex);
            throw;
        }
    }

    /// <summary>
    /// Waits until the client is authenticated and connected.
    /// Throws if connection fails or the timeout is exceeded.
    /// </summary>
    public async Task WaitUntilConnectedAsync(TimeSpan? timeout = null)
    {
        if (_state == ConnectionState.Connected) return;
        if (_connectedTcs == null) throw new InvalidOperationException("Not connecting.");

        var cts = timeout.HasValue
            ? new CancellationTokenSource(timeout.Value)
            : new CancellationTokenSource(TimeSpan.FromMinutes(3));

        using (cts.Token.Register(() => _connectedTcs.TrySetCanceled()))
            await _connectedTcs.Task;
    }

    // ─── Messaging ───────────────────────────────────────────────────────────

    /// <summary>
    /// Sends a text message to a phone number or JID.
    /// </summary>
    /// <param name="to">Phone number ("31612345678") or full JID ("31612345678@s.whatsapp.net").</param>
    /// <param name="text">Message text.</param>
    public async Task SendMessageAsync(string to, string text, CancellationToken cancellationToken = default)
    {
        if (_noiseProcessor == null || _state != ConnectionState.Connected)
            throw new InvalidOperationException("Client is not connected.");

        // Normalize to JID
        var jid = to.Contains('@') ? to : $"{new string(to.Where(char.IsDigit).ToArray())}@s.whatsapp.net";
        await _noiseProcessor.SendTextMessageAsync(jid, text, cancellationToken);
    }

    // ─── Disconnection ───────────────────────────────────────────────────────

    /// <summary>Disconnects from WhatsApp and cleans up resources.</summary>
    public async Task DisconnectAsync()
    {
        _cts?.Cancel();
        if (_frameSocket != null)
        {
            await _frameSocket.DisposeAsync();
            _frameSocket = null;
        }
        _noiseProcessor = null;
        SetState(ConnectionState.Disconnected);
        Disconnected?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Deletes the saved session (forces QR code re-scan on next connect).</summary>
    public void Logout()
    {
        _sessionStore.Delete();
        _logger.LogInformation("Session deleted. QR scan required on next connection.");
    }

    public bool HasSavedSession => _sessionStore.HasSession;

    // ─── Private helpers ─────────────────────────────────────────────────────

    private async Task RunReceiveLoopAsync(CancellationToken ct)
    {
        try
        {
            await _noiseProcessor!.ReceiveLoopAsync(ct);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Receive loop crashed.");
        }
        finally
        {
            if (_state == ConnectionState.Connected)
            {
                SetState(ConnectionState.Disconnected);
                Disconnected?.Invoke(this, EventArgs.Empty);

                if (_options.AutoReconnect && !ct.IsCancellationRequested)
                {
                    _logger.LogInformation("Reconnecting in {Delay}…", _options.ReconnectDelay);
                    await Task.Delay(_options.ReconnectDelay, CancellationToken.None);
                    try { await ConnectAsync(CancellationToken.None); }
                    catch (Exception ex) { _logger.LogError(ex, "Reconnect failed."); }
                }
            }
        }
    }

    private void SetState(ConnectionState state)
    {
        if (_state == state) return;
        _state = state;
        _logger.LogDebug("State → {State}", state);
        ConnectionStateChanged?.Invoke(this, state);
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync();
        _cts?.Dispose();
    }
}
