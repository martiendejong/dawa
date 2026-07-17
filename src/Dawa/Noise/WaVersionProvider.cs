using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Dawa.Noise;

/// <summary>
/// Provides the WhatsApp Web client version announced in the ClientPayload.
/// WhatsApp rejects fresh device registrations from outdated versions with
/// "Authentication failure: 405" (already-paired sessions keep working), so the
/// version must track WhatsApp's minimum. Baileys maintains the current value in
/// baileys-version.json; we fetch it before each connect (throttled) and fall back
/// to the compiled constant when offline. The active version is mirrored to
/// wa-version-active.json next to the app so external watchdogs can compare it
/// against the live upstream value.
/// </summary>
public static class WaVersionProvider
{
    public const uint Primary = 2;
    public const uint Secondary = 3000;

    // Last version verified working, 2026-07-14. Used when the fetch fails and no disk cache exists.
    private const uint FallbackTertiary = 1035194821;

    private const string SourceUrl =
        "https://raw.githubusercontent.com/WhiskeySockets/Baileys/master/src/Defaults/baileys-version.json";

    private static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(12);
    private static readonly TimeSpan RetryInterval = TimeSpan.FromHours(1);
    private static readonly SemaphoreSlim Gate = new(1, 1);

    private static uint _tertiary = FallbackTertiary;
    private static DateTime _nextFetchUtc = DateTime.MinValue;

    static WaVersionProvider() => TryReadCache();

    public static uint Tertiary => _tertiary;
    public static string VersionString => $"{Primary}.{Secondary}.{_tertiary}";

    /// <summary>
    /// Refreshes the version from upstream if the throttle window has passed.
    /// Never throws — on any failure the current (cached or fallback) value stays active.
    /// </summary>
    public static async Task RefreshAsync(ILogger? logger = null, CancellationToken ct = default)
    {
        if (DateTime.UtcNow < _nextFetchUtc) return;

        await Gate.WaitAsync(ct);
        try
        {
            if (DateTime.UtcNow < _nextFetchUtc) return;

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
            var json = await http.GetStringAsync(SourceUrl, ct);
            using var doc = JsonDocument.Parse(json);
            var arr = doc.RootElement.GetProperty("version");

            if (arr.GetArrayLength() == 3
                && arr[0].GetUInt32() == Primary
                && arr[1].GetUInt32() == Secondary)
            {
                var tertiary = arr[2].GetUInt32();
                if (tertiary != _tertiary)
                {
                    logger?.LogInformation("WA web version updated: {Old} -> {New}", _tertiary, tertiary);
                    _tertiary = tertiary;
                }
                _nextFetchUtc = DateTime.UtcNow + RefreshInterval;
                TryWriteCache();
            }
            else
            {
                // Major/minor changed upstream — a protocol shift beyond a tertiary bump.
                // Keep the known-good value; a human (or watchdog alert) must look at this.
                logger?.LogWarning("WA version upstream has unexpected shape: {Json} — keeping {Current}",
                    json.Trim(), VersionString);
                _nextFetchUtc = DateTime.UtcNow + RefreshInterval;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger?.LogWarning("WA version fetch failed ({Msg}) — using {Current}", ex.Message, VersionString);
            _nextFetchUtc = DateTime.UtcNow + RetryInterval;
        }
        finally
        {
            Gate.Release();
        }
    }

    private static string CachePath => Path.Combine(AppContext.BaseDirectory, "wa-version-active.json");

    private static void TryWriteCache()
    {
        try
        {
            File.WriteAllText(CachePath, JsonSerializer.Serialize(new
            {
                version = new[] { Primary, Secondary, _tertiary },
                fetchedUtc = DateTime.UtcNow,
            }));
        }
        catch
        {
            // Cache is best-effort; the in-memory value is what matters.
        }
    }

    private static void TryReadCache()
    {
        try
        {
            if (!File.Exists(CachePath)) return;
            using var doc = JsonDocument.Parse(File.ReadAllText(CachePath));
            var arr = doc.RootElement.GetProperty("version");
            if (arr.GetArrayLength() == 3
                && arr[0].GetUInt32() == Primary
                && arr[1].GetUInt32() == Secondary
                && arr[2].GetUInt32() > FallbackTertiary)
            {
                _tertiary = arr[2].GetUInt32();
            }
        }
        catch
        {
            // Corrupt cache — fall back to the compiled constant.
        }
    }
}
