using Renci.SshNet;
using Renci.SshNet.Common;
using SCPDrop.Models;

namespace SCPDrop.Services;

public sealed record UploadProgress(string CurrentFile, long BytesDone, long BytesTotal);

/// <summary>User interaction needed while connecting. Methods may be called from a background thread.</summary>
public interface IConnectionUi
{
    /// <summary>Unknown host key: return true to trust (and remember) it.</summary>
    bool TrustHostKey(RemoteConnection connection, string fingerprint, string keyType);

    /// <summary>Server asked a keyboard-interactive question we can't answer (2FA code, password retry, ...). Null = cancel.</summary>
    string? Ask(RemoteConnection connection, string instruction, string request, bool echo);
}

public static class ScpUploader
{
    public static Task UploadAsync(
        RemoteConnection conn,
        IReadOnlyList<string> localPaths,
        IProgress<UploadProgress> progress,
        IConnectionUi ui,
        Action<string> log,
        CancellationToken ct) => Task.Run(() =>
    {
        var sizes = localPaths.Select(GetSize).ToArray();
        long total = sizes.Sum();
        var auth = new AuthSession();

        SshClient? ssh = null;
        using var scp = new ScpClient(BuildConnectionInfo(conn, ui, auth), RemotePathTransformation.ShellQuote);
        var scpCheck = AttachHostKeyCheck(scp, conn, ui);

        using var reg = ct.Register(() =>
        {
            try { scp.Disconnect(); } catch { /* ignore */ }
            try { ssh?.Disconnect(); } catch { /* ignore */ }
        });

        // The shell connection is only opened if we need to run mkdir.
        SshClient Shell()
        {
            if (ssh != null) return ssh;
            ssh = new SshClient(BuildConnectionInfo(conn, ui, auth));
            var check = AttachHostKeyCheck(ssh, conn, ui);
            Connect(ssh, check, auth);
            return ssh;
        }

        try
        {
            var baseFolder = NormalizeRemoteFolder(conn.RemoteFolder);
            if (conn.CreateRemoteFolder && baseFolder.Length > 0)
                RunChecked(Shell(), $"mkdir -p {ShellQuote(baseFolder)}");

            Connect(scp, scpCheck, auth);

            long itemBase = 0, intraDone = 0, curSize = 0, curUploaded = 0;
            string? curName = null;
            scp.Uploading += (_, e) =>
            {
                if (e.Filename != curName || e.Uploaded < curUploaded)
                {
                    if (curName != null) intraDone += curSize;
                    curName = e.Filename;
                    curSize = e.Size;
                }
                curUploaded = e.Uploaded;
                progress.Report(new UploadProgress(e.Filename, Math.Min(total, itemBase + intraDone + e.Uploaded), total));
            };

            for (int i = 0; i < localPaths.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var local = localPaths[i];
                var name = Path.GetFileName(local.TrimEnd('\\', '/'));
                var remote = JoinRemote(baseFolder, name);
                intraDone = 0; curName = null; curSize = 0; curUploaded = 0;

                if (Directory.Exists(local))
                {
                    log($"Uploading folder {name} → {remote}/");
                    RunChecked(Shell(), $"mkdir -p {ShellQuote(remote)}");
                    scp.Upload(new DirectoryInfo(local), remote);
                }
                else if (File.Exists(local))
                {
                    log($"Uploading {name} ({FormatBytes(sizes[i])}) → {remote}");
                    scp.Upload(new FileInfo(local), remote);
                }
                else
                {
                    log($"Skipped (not found): {local}");
                }

                itemBase += sizes[i];
                progress.Report(new UploadProgress(name, itemBase, total));
            }
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            throw new OperationCanceledException(ct);
        }
        finally
        {
            if (scp.IsConnected) scp.Disconnect();
            if (ssh is { IsConnected: true }) ssh.Disconnect();
            ssh?.Dispose();
        }
    }, ct);

    /// <summary>Connects, verifies login and checks the remote folder. Returns a human-readable summary.</summary>
    public static string Test(RemoteConnection conn, IConnectionUi ui)
    {
        var auth = new AuthSession();
        using var ssh = new SshClient(BuildConnectionInfo(conn, ui, auth));
        var check = AttachHostKeyCheck(ssh, conn, ui);
        Connect(ssh, check, auth);
        try
        {
            var lines = new List<string> { $"Connected and authenticated to {conn.Host}:{conn.Port} as {conn.Username}." };
            if (auth.UserAnswered)
                lines.Add("Note: the server asked questions the saved settings couldn't answer (shown as pop-ups). " +
                          "If you typed a password, save it in the Password field.");
            var folder = NormalizeRemoteFolder(conn.RemoteFolder);
            if (folder.Length > 0)
            {
                var r = ssh.RunCommand($"test -d {ShellQuote(folder)} && echo EXISTS || echo MISSING");
                lines.Add(r.Result.Trim() switch
                {
                    "EXISTS" => $"Remote folder '{conn.RemoteFolder}' exists.",
                    "MISSING" => conn.CreateRemoteFolder
                        ? $"Remote folder '{conn.RemoteFolder}' does not exist yet (it will be created on upload)."
                        : $"WARNING: remote folder '{conn.RemoteFolder}' does not exist.",
                    _ => "Could not check the remote folder (non-POSIX shell?)."
                });
            }
            var scpCheck = ssh.RunCommand("command -v scp");
            lines.Add(string.IsNullOrWhiteSpace(scpCheck.Result)
                ? "WARNING: 'scp' was not found on the remote PATH; uploads may fail."
                : $"Remote scp: {scpCheck.Result.Trim()}");
            return string.Join(Environment.NewLine, lines);
        }
        finally
        {
            ssh.Disconnect();
        }
    }

    /// <summary>Shared across the connections of one operation so the user isn't asked the same thing twice.</summary>
    private sealed class AuthSession
    {
        public readonly object Lock = new();
        public readonly Dictionary<string, string> Answers = new();
        public readonly List<string> PromptsSeen = new();
        public bool UserCancelled;
        public bool UserAnswered;
    }

    /// <summary>Builds a fresh ConnectionInfo per client: auth state (e.g. "password already sent") is per connection.</summary>
    private static ConnectionInfo BuildConnectionInfo(RemoteConnection c, IConnectionUi ui, AuthSession session)
    {
        if (string.IsNullOrWhiteSpace(c.Host)) throw new InvalidOperationException("Host is not set.");
        if (string.IsNullOrWhiteSpace(c.Username)) throw new InvalidOperationException("Username is not set.");
        var user = c.Username.Trim();

        var methods = new List<AuthenticationMethod>();
        var pw = "";
        if (c.Auth == AuthMethod.PrivateKey)
        {
            var path = Environment.ExpandEnvironmentVariables(c.PrivateKeyPath ?? "");
            if (path.StartsWith("~"))
                path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + path[1..];
            if (!File.Exists(path)) throw new FileNotFoundException($"Private key file not found: {path}");
            var pass = Secret.Unprotect(c.EncryptedPassphrase);
            var key = pass.Length > 0 ? new PrivateKeyFile(path, pass) : new PrivateKeyFile(path);
            methods.Add(new PrivateKeyAuthenticationMethod(user, key));
        }
        else
        {
            pw = Secret.Unprotect(c.EncryptedPassword);
            if (pw.Length > 0) methods.Add(new PasswordAuthenticationMethod(user, pw));
        }

        // Keyboard-interactive: used by servers with PasswordAuthentication off, PAM, or 2FA (also after a public key).
        var kbd = new KeyboardInteractiveAuthenticationMethod(user);
        var passwordSent = false;
        var cachedUsed = new HashSet<string>();
        kbd.AuthenticationPrompt += (_, e) =>
        {
            foreach (var p in e.Prompts)
            {
                var request = (p.Request ?? "").Trim();
                lock (session.Lock) session.PromptsSeen.Add(request);

                // First hidden prompt that isn't obviously a one-time code gets the saved password, whatever its wording.
                if (!p.IsEchoed && !passwordSent && pw.Length > 0 && !LooksLikeOneTimeCode(request))
                {
                    passwordSent = true;
                    p.Response = pw;
                    continue;
                }

                string? cached;
                lock (session.Lock) session.Answers.TryGetValue(request, out cached);
                if (cached != null && cachedUsed.Add(request))
                {
                    p.Response = cached;
                    continue;
                }

                if (session.UserCancelled) { p.Response = ""; continue; }

                var answer = ui.Ask(c, e.Instruction ?? "", request, p.IsEchoed);
                lock (session.Lock)
                {
                    if (answer == null) session.UserCancelled = true;
                    else { session.Answers[request] = answer; session.UserAnswered = true; }
                }
                p.Response = answer ?? "";
            }
        };
        methods.Add(kbd);

        return new ConnectionInfo(c.Host.Trim(), c.Port, user, methods.ToArray())
        {
            Timeout = TimeSpan.FromSeconds(20)
        };
    }

    private static bool LooksLikeOneTimeCode(string request)
    {
        var r = request.ToLowerInvariant();
        return r.Contains("code") || r.Contains("token") || r.Contains("verification") || r.Contains("otp") || r.Contains("one-time");
    }

    private sealed class HostKeyCheck
    {
        public string? RejectedReason;
    }

    private static HostKeyCheck AttachHostKeyCheck(BaseClient client, RemoteConnection conn, IConnectionUi ui)
    {
        var check = new HostKeyCheck();
        client.HostKeyReceived += (_, e) =>
        {
            var fp = "SHA256:" + e.FingerPrintSHA256;
            if (string.IsNullOrEmpty(conn.HostKeyFingerprint))
            {
                e.CanTrust = ui.TrustHostKey(conn, fp, e.HostKeyName);
                if (!e.CanTrust) check.RejectedReason = "Host key was not trusted.";
            }
            else if (string.Equals(conn.HostKeyFingerprint, fp, StringComparison.Ordinal))
            {
                e.CanTrust = true;
            }
            else
            {
                e.CanTrust = false;
                check.RejectedReason =
                    $"HOST KEY MISMATCH for {conn.Host}! Expected {conn.HostKeyFingerprint} but server presented {fp}. " +
                    "If the server was legitimately reinstalled, clear the stored key in Manage Connections.";
            }
        };
        return check;
    }

    private static void Connect(BaseClient client, HostKeyCheck check, AuthSession auth)
    {
        try
        {
            client.Connect();
        }
        catch (SshConnectionException) when (check.RejectedReason != null)
        {
            throw new InvalidOperationException(check.RejectedReason);
        }
        catch (SshAuthenticationException ex)
        {
            if (auth.UserCancelled) throw new InvalidOperationException("Login cancelled.");
            string prompts;
            lock (auth.Lock)
                prompts = auth.PromptsSeen.Count == 0
                    ? "none"
                    : string.Join(", ", auth.PromptsSeen.Distinct().Select(p => $"\"{p}\""));
            throw new InvalidOperationException(
                $"Login rejected: {ex.Message} Server prompts: {prompts}. " +
                "Check the username and password/key. Note many servers refuse password logins for root " +
                "(PermitRootLogin prohibit-password) or for all users (PasswordAuthentication no) — use a private key then.",
                ex);
        }
    }

    private static void RunChecked(SshClient ssh, string command)
    {
        var r = ssh.RunCommand(command);
        if (r.ExitStatus != 0)
            throw new InvalidOperationException($"Remote command failed ({command}): {r.Error.Trim()}");
    }

    /// <summary>scp/ssh commands start in the login's home dir, so "~/x" becomes "x" (quoting would stop ~ expanding).</summary>
    private static string NormalizeRemoteFolder(string? folder)
    {
        var f = (folder ?? "").Trim();
        if (f == "~" || f == "~/") return "";
        if (f.StartsWith("~/")) f = f[2..];
        return f.Length > 1 ? f.TrimEnd('/') : f;
    }

    private static string JoinRemote(string folder, string name) =>
        folder.Length == 0 ? name : folder == "/" ? "/" + name : folder + "/" + name;

    private static string ShellQuote(string s) => "'" + s.Replace("'", "'\"'\"'") + "'";

    private static long GetSize(string path)
    {
        try
        {
            if (File.Exists(path)) return new FileInfo(path).Length;
            if (Directory.Exists(path))
                return new DirectoryInfo(path).EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length);
        }
        catch { /* best effort */ }
        return 0;
    }

    public static string FormatBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double v = bytes; int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? $"{bytes} B" : $"{v:0.0} {units[u]}";
    }
}
