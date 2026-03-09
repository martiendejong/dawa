using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Dawa.Auth;

/// <summary>
/// Persists AuthState to a JSON file in the session directory.
/// </summary>
public sealed class SessionStore
{
    private readonly string _directory;
    private readonly string _credsPath;
    private static readonly JsonSerializerOptions _jsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };

    public SessionStore(string directory)
    {
        _directory = directory;
        Directory.CreateDirectory(directory);
        _credsPath = Path.Combine(directory, "creds.json");
    }

    /// <summary>Loads a saved session, or creates a fresh AuthState if none exists.</summary>
    public async Task<AuthState> LoadAsync(CancellationToken ct = default)
    {
        if (File.Exists(_credsPath))
        {
            var json = await File.ReadAllTextAsync(_credsPath, ct);
            var state = JsonSerializer.Deserialize<AuthState>(json, _jsonOpts);
            if (state != null) return state;
        }
        return AuthState.CreateNew();
    }

    /// <summary>Saves the current auth state to disk.</summary>
    public async Task SaveAsync(AuthState state, CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(state, _jsonOpts);
        await File.WriteAllTextAsync(_credsPath, json, ct);
    }

    /// <summary>Deletes the session (forces re-authentication).</summary>
    public void Delete()
    {
        if (File.Exists(_credsPath)) File.Delete(_credsPath);
    }

    public bool HasSession => File.Exists(_credsPath);
}
