namespace SCPDrop.Models;

public enum AuthMethod
{
    Password,
    PrivateKey
}

public sealed class RemoteConnection
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "New connection";
    public string Host { get; set; } = "";
    public int Port { get; set; } = 22;
    public string Username { get; set; } = "";
    public AuthMethod Auth { get; set; } = AuthMethod.Password;

    /// <summary>DPAPI-encrypted (current Windows user), base64.</summary>
    public string? EncryptedPassword { get; set; }

    public string? PrivateKeyPath { get; set; }

    /// <summary>DPAPI-encrypted (current Windows user), base64.</summary>
    public string? EncryptedPassphrase { get; set; }

    /// <summary>Destination folder on the remote host. Absolute, or relative to the login's home dir (~/ allowed).</summary>
    public string RemoteFolder { get; set; } = "";

    /// <summary>Run "mkdir -p" on the remote folder before uploading.</summary>
    public bool CreateRemoteFolder { get; set; } = true;

    /// <summary>Trusted host key, e.g. "SHA256:abc...". Null until first trusted connection.</summary>
    public string? HostKeyFingerprint { get; set; }

    public string TargetDisplay =>
        $"{Username}@{Host}{(Port == 22 ? "" : ":" + Port)}:{(string.IsNullOrWhiteSpace(RemoteFolder) ? "~" : RemoteFolder)}";

    public override string ToString() => Name;
}

public sealed class AppConfig
{
    public List<RemoteConnection> Connections { get; set; } = new();
    public Guid? LastSelectedId { get; set; }
    public bool AlwaysOnTop { get; set; }
}
