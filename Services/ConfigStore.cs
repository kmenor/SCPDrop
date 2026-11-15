using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SCPDrop.Models;

namespace SCPDrop.Services;

public static class ConfigStore
{
    public static string Directory { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SCPDrop");

    public static string FilePath => Path.Combine(Directory, "config.json");

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static AppConfig Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(FilePath), Options) ?? new AppConfig();
        }
        catch (Exception)
        {
            // Keep the unreadable file for inspection rather than silently overwriting it later.
            try { File.Copy(FilePath, FilePath + ".bad", overwrite: true); } catch { /* ignore */ }
        }
        return new AppConfig();
    }

    public static void Save(AppConfig config)
    {
        System.IO.Directory.CreateDirectory(Directory);
        var tmp = FilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(config, Options));
        File.Move(tmp, FilePath, overwrite: true);
    }

    public static T DeepClone<T>(T value) =>
        JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value, Options), Options)!;
}

/// <summary>Encrypts secrets with Windows DPAPI, bound to the current Windows user.</summary>
public static class Secret
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SCPDrop.v1");

    public static string? Protect(string? plain) =>
        string.IsNullOrEmpty(plain)
            ? null
            : Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(plain), Entropy, DataProtectionScope.CurrentUser));

    /// <summary>
    /// Decrypts a saved secret. No saved secret gives true and "". A secret that is saved but can't be
    /// decrypted (saved by another Windows user or on another computer, or corrupted) gives false, so callers
    /// can tell it apart from an empty one instead of overwriting it.
    /// </summary>
    public static bool TryUnprotect(string? encrypted, out string plain)
    {
        plain = "";
        if (string.IsNullOrEmpty(encrypted)) return true;
        try
        {
            plain = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(encrypted), Entropy, DataProtectionScope.CurrentUser));
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return false;
        }
    }
}
