using System.Text;
using Renci.SshNet;
using Renci.SshNet.Common;
using SCPDrop.Models;

namespace SCPDrop.Services;

public sealed record UploadProgress(string CurrentFile, long BytesDone, long BytesTotal);

/// <summary>
/// Outcome of an upload that ran to the end. Failures and cancellation are reported by exceptions instead.
/// </summary>
/// <param name="ItemsRequested">Items the user dropped or picked.</param>
/// <param name="ItemsUploaded">Of those, items that were sent (a folder counts once).</param>
/// <param name="FilesUploaded">Individual files sent, including those inside folders.</param>
/// <param name="Skipped">Everything left out, dropped items and links inside folders alike.</param>
public sealed record UploadResult(int ItemsRequested, int ItemsUploaded, int FilesUploaded, IReadOnlyList<string> Skipped)
{
    public bool Complete => Skipped.Count == 0 && ItemsUploaded == ItemsRequested;
    public bool NothingUploaded => ItemsUploaded == 0;
}

/// <summary>User interaction needed while connecting. Methods may be called from a background thread.</summary>
public interface IConnectionUi
{
    /// <summary>Unknown host key: return true to trust (and remember) it.</summary>
    bool TrustHostKey(RemoteConnection connection, string fingerprint, string keyType);

    /// <summary>Server asked a keyboard-interactive question we can't answer (2FA code, password retry, ...). Null = cancel.</summary>
    string? Ask(RemoteConnection connection, string instruction, string request, bool echo);

    /// <summary>Some destination files already exist on the server: return true to replace them.</summary>
    bool ConfirmOverwrite(RemoteConnection connection, IReadOnlyList<string> existingPaths);
}

public static class ScpUploader
{
    public static Task<UploadResult> UploadAsync(
        RemoteConnection conn,
        IReadOnlyList<string> localPaths,
        IProgress<UploadProgress> progress,
        IConnectionUi ui,
        Action<string> log,
        CancellationToken ct) => Task.Run(() =>
    {
        var baseFolder = NormalizeRemoteFolder(conn.RemoteFolder);
        var plan = BuildPlan(localPaths, baseFolder, ct);
        foreach (var skipped in plan.Skipped) log("Skipped " + skipped);
        foreach (var item in plan.Items) log("Uploading " + item);
        var result = new UploadResult(localPaths.Count, plan.Items.Count, plan.Files.Count, plan.Skipped);
        if (plan.Items.Count == 0) return result; // nothing left to send; don't connect at all
        long total = plan.Files.Sum(f => f.Size);
        var auth = new AuthSession();

        // The shell connection checks for existing files, creates folders and renames finished uploads.
        using var ssh = new SshClient(BuildConnectionInfo(conn, ui, auth));
        var sshCheck = AttachHostKeyCheck(ssh, conn, ui);
        using var scp = new ScpClient(BuildConnectionInfo(conn, ui, auth), RemotePathTransformation.ShellQuote)
        {
            OperationTimeout = ScpOperationTimeout
        };
        var scpCheck = AttachHostKeyCheck(scp, conn, ui);

        // SCP transfers have no cancellable API, so cancelling drops the SCP connection. Connecting and remote
        // commands take the token directly, which leaves the shell connection usable for deleting the
        // partial temp file.
        using var reg = ct.Register(() =>
        {
            try { scp.Disconnect(); } catch { /* ignore */ }
        });

        try
        {
            Connect(ssh, sshCheck, auth, ct);
            ConfirmDestinations(ssh, conn, plan, ui, ct);

            if (conn.CreateRemoteFolder && baseFolder.Length > 0)
                RunChecked(ssh, $"mkdir -p -- {ShellQuote(baseFolder)}", ct);
            if (plan.RemoteDirs.Count > 0)
                RunBatched(ssh, "mkdir -p --", plan.RemoteDirs, ct);
            RemoveStaleTempFiles(ssh, plan, ct);

            Connect(scp, scpCheck, auth, ct);

            // Files are sent one at a time from our own walk of the tree; SSH.NET's recursive directory
            // upload is not used because it would follow links out of the selected folder.
            long done = 0;
            var currentName = "";
            scp.Uploading += (_, e) =>
                progress.Report(new UploadProgress(currentName, Math.Min(total, done + e.Uploaded), total));

            foreach (var file in plan.Files)
            {
                ct.ThrowIfCancellationRequested();
                currentName = file.DisplayName;
                UploadViaTempFile(ssh, scp, file, ct);
                done += file.Size;
                progress.Report(new UploadProgress(file.DisplayName, done, total));
            }
            return result;
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            throw new OperationCanceledException(ct);
        }
        finally
        {
            if (scp.IsConnected) scp.Disconnect();
            if (ssh.IsConnected) ssh.Disconnect();
        }
    }, ct);

    private const string TempPrefix = ".scpdrop-";
    private const string TempSuffix = ".part";

    /// <summary>Longest wait for any single remote command (mkdir, existence check, rename, cleanup).</summary>
    private static readonly TimeSpan RemoteCommandTimeout = TimeSpan.FromMinutes(2);

    /// <summary>Longest wait for the remote scp to acknowledge a step; data transfer itself isn't limited.</summary>
    private static readonly TimeSpan ScpOperationTimeout = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Sends the file to a uniquely named temp file next to its destination, then renames it into place.
    /// The rename is atomic, so an interrupted transfer never leaves a truncated file under the real name.
    /// </summary>
    private static void UploadViaTempFile(SshClient ssh, ScpClient scp, PlannedFile file, CancellationToken ct)
    {
        var slash = file.RemotePath.LastIndexOf('/');
        var dirPrefix = slash < 0 ? "" : file.RemotePath[..(slash + 1)];
        var temp = $"{dirPrefix}{TempPrefix}{Guid.NewGuid():N}{TempSuffix}";
        try
        {
            scp.Upload(new FileInfo(file.LocalPath), temp);
            var target = ShellQuote(file.RemotePath);
            // mv into an existing directory would move the file *inside* it, so refuse that explicitly.
            RunChecked(ssh,
                $"if [ -d {target} ]; then echo 'a folder with this name exists' >&2; exit 1; fi; " +
                $"mv -f -- {ShellQuote(temp)} {target}", ct);
        }
        catch
        {
            try
            {
                // Not tied to the (possibly cancelled) token: this cleanup must still run after a cancel.
                if (ssh.IsConnected) Exec(ssh, $"rm -f -- {ShellQuote(temp)}", CancellationToken.None);
            }
            catch { /* best effort; stale temp files are also swept on later uploads */ }
            throw;
        }
    }

    /// <summary>
    /// Fails if a file would land on an existing folder (or a folder on an existing file), and asks before
    /// replacing existing files. Runs before anything is created or uploaded.
    /// </summary>
    private static void ConfirmDestinations(SshClient ssh, RemoteConnection conn, UploadPlan plan, IConnectionUi ui, CancellationToken ct)
    {
        var plannedDirs = new HashSet<string>(plan.RemoteDirs, StringComparer.Ordinal);
        var existing = FindExisting(ssh, plan.RemoteDirs.Concat(plan.Files.Select(f => f.RemotePath)), ct);

        var blocked = existing
            .Where(e => e.IsDirectory != plannedDirs.Contains(e.Path))
            .Select(e => e.IsDirectory ? $"{e.Path} (a folder exists there)" : $"{e.Path} (a file exists there)")
            .ToList();
        if (blocked.Count > 0)
            throw new InvalidOperationException(
                "Nothing was uploaded. These destinations already exist as the wrong type: " +
                string.Join(", ", blocked.Take(5)) + (blocked.Count > 5 ? $" and {blocked.Count - 5} more" : ""));

        var overwrites = existing.Where(e => !e.IsDirectory).Select(e => e.Path).ToList();
        if (overwrites.Count > 0 && !ui.ConfirmOverwrite(conn, overwrites))
            throw new InvalidOperationException(
                $"Nothing was uploaded: {overwrites.Count} file(s) already exist on the server and replacing them was declined.");
    }

    private static List<(string Path, bool IsDirectory)> FindExisting(SshClient ssh, IEnumerable<string> paths, CancellationToken ct)
    {
        var found = new List<(string, bool)>();
        foreach (var batch in QuotedBatches(paths))
        {
            // NUL-separated output so any file name round-trips.
            var r = Exec(ssh,
                $"for p in {batch}; do " +
                "if [ -d \"$p\" ]; then printf 'D%s\\0' \"$p\"; " +
                "elif [ -e \"$p\" ] || [ -L \"$p\" ]; then printf 'F%s\\0' \"$p\"; fi; done", ct);
            if (r.ExitStatus != 0)
                throw new InvalidOperationException($"Could not check the destination on the server: {r.Error.Trim()}");
            foreach (var entry in r.Output.Split('\0', StringSplitOptions.RemoveEmptyEntries))
                found.Add((entry[1..], entry[0] == 'D'));
        }
        return found;
    }

    /// <summary>
    /// Deletes temp files left by uploads that were killed outright (crash, power loss) in the folders we're
    /// about to write to. Only files older than a day are removed, so another upload in progress is untouched.
    /// </summary>
    private static void RemoveStaleTempFiles(SshClient ssh, UploadPlan plan, CancellationToken ct)
    {
        var dirs = plan.Files
            .Select(f => f.RemotePath.LastIndexOf('/') switch { < 0 => ".", 0 => "/", var i => f.RemotePath[..i] })
            .Distinct(StringComparer.Ordinal);
        foreach (var batch in QuotedBatches(dirs))
        {
            try
            {
                Exec(ssh,
                    $"for d in {batch}; do find \"$d\" -maxdepth 1 -type f -name '{TempPrefix}*{TempSuffix}' " +
                    "-mmin +1440 -exec rm -f -- {} + ; done 2>/dev/null; true", ct);
            }
            catch (Exception) when (!ct.IsCancellationRequested) { /* housekeeping only */ }
        }
    }

    /// <summary>Connects, verifies login and checks the remote folder. Returns a human-readable summary.</summary>
    public static string Test(RemoteConnection conn, IConnectionUi ui)
    {
        var auth = new AuthSession();
        using var ssh = new SshClient(BuildConnectionInfo(conn, ui, auth));
        var check = AttachHostKeyCheck(ssh, conn, ui);
        Connect(ssh, check, auth, CancellationToken.None);
        try
        {
            var lines = new List<string> { $"Connected and authenticated to {conn.Host}:{conn.Port} as {conn.Username}." };
            if (auth.UserAnswered)
                lines.Add("Note: the server asked questions the saved settings couldn't answer (shown as pop-ups). " +
                          "If you typed a password, save it in the Password field.");
            var folder = NormalizeRemoteFolder(conn.RemoteFolder);
            if (folder.Length > 0)
            {
                var r = Exec(ssh, $"test -d {ShellQuote(folder)} && echo EXISTS || echo MISSING", CancellationToken.None);
                lines.Add(r.Output.Trim() switch
                {
                    "EXISTS" => $"Remote folder '{conn.RemoteFolder}' exists.",
                    "MISSING" => conn.CreateRemoteFolder
                        ? $"Remote folder '{conn.RemoteFolder}' does not exist yet (it will be created on upload)."
                        : $"WARNING: remote folder '{conn.RemoteFolder}' does not exist.",
                    _ => "Could not check the remote folder (non-POSIX shell?)."
                });
            }
            var scpCheck = Exec(ssh, "command -v scp", CancellationToken.None);
            lines.Add(string.IsNullOrWhiteSpace(scpCheck.Output)
                ? "WARNING: 'scp' was not found on the remote PATH; uploads may fail."
                : $"Remote scp: {scpCheck.Output.Trim()}");
            return string.Join(Environment.NewLine, lines);
        }
        finally
        {
            ssh.Disconnect();
        }
    }

    /// <summary>Shared across the connections of one operation.</summary>
    private sealed class AuthSession
    {
        public readonly object Lock = new();

        /// <summary>Typed answers to password-style prompts, reused so the user isn't asked twice.</summary>
        public readonly Dictionary<string, string> Answers = new();

        /// <summary>Every prompt the user has answered, reusable or not.</summary>
        public readonly HashSet<string> Asked = new();
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
            var pass = ReadSecret(c, c.EncryptedPassphrase, "key passphrase");
            var key = pass.Length > 0 ? new PrivateKeyFile(path, pass) : new PrivateKeyFile(path);
            methods.Add(new PrivateKeyAuthenticationMethod(user, key));
        }
        else
        {
            pw = ReadSecret(c, c.EncryptedPassword, "password");
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

                // Only password-style answers are reused for the operation's other connection; anything else
                // (2FA codes, tokens, unknown challenges) may be single-use and is asked for again.
                var reusable = IsReusableSecretPrompt(request, p.IsEchoed);
                string? cached = null;
                if (reusable)
                    lock (session.Lock) session.Answers.TryGetValue(request, out cached);
                if (cached != null && cachedUsed.Add(request))
                {
                    p.Response = cached;
                    continue;
                }

                if (session.UserCancelled) { p.Response = ""; continue; }

                bool askedBefore;
                lock (session.Lock) askedBefore = session.Asked.Contains(request);
                var instruction = e.Instruction ?? "";
                if (askedBefore && !reusable)
                    instruction = "This upload logs in a second time, and one-time codes can't be reused. " +
                                  "Enter a new code." + (instruction.Length > 0 ? "\n\n" + instruction : "");

                var answer = ui.Ask(c, instruction, request, p.IsEchoed);
                lock (session.Lock)
                {
                    if (answer == null)
                    {
                        session.UserCancelled = true;
                    }
                    else
                    {
                        session.Asked.Add(request);
                        if (reusable) session.Answers[request] = answer;
                        session.UserAnswered = true;
                    }
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

    private static string ReadSecret(RemoteConnection c, string? encrypted, string what) =>
        Secret.TryUnprotect(encrypted, out var plain)
            ? plain
            : throw new InvalidOperationException(
                $"The saved {what} for '{c.Name}' can't be decrypted; it was probably saved by another Windows user " +
                "or on another computer. Enter it again in Manage Connections.");

    private static bool LooksLikeOneTimeCode(string request)
    {
        var r = request.ToLowerInvariant();
        return r.Contains("code") || r.Contains("token") || r.Contains("verification") || r.Contains("otp") || r.Contains("one-time");
    }

    /// <summary>A hidden prompt that asks for a password or passphrase, which stays valid for a second login.</summary>
    internal static bool IsReusableSecretPrompt(string request, bool echoed)
    {
        if (echoed || LooksLikeOneTimeCode(request)) return false;
        var r = request.ToLowerInvariant();
        return r.Contains("password") || r.Contains("passphrase");
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

    private static void Connect(BaseClient client, HostKeyCheck check, AuthSession auth, CancellationToken ct)
    {
        try
        {
            // Bounded by ConnectionInfo.Timeout, and abandoned promptly if the user cancels.
            client.ConnectAsync(ct).GetAwaiter().GetResult();
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

    internal sealed record PlannedFile(string LocalPath, string RemotePath, string DisplayName, long Size);

    internal sealed class UploadPlan
    {
        public List<PlannedFile> Files { get; } = new();

        /// <summary>Remote directories to create, parents before children.</summary>
        public List<string> RemoteDirs { get; } = new();

        /// <summary>One human-readable line per dropped item.</summary>
        public List<string> Items { get; } = new();

        public List<string> Skipped { get; } = new();
    }

    /// <summary>
    /// Expands the dropped items into the exact list of files and folders to send. Symbolic links and
    /// junctions are never followed, whether dropped directly or found inside a folder, so nothing outside
    /// the selected tree is uploaded and link cycles can't occur.
    /// </summary>
    internal static UploadPlan BuildPlan(IReadOnlyList<string> localPaths, string baseFolder, CancellationToken ct)
    {
        var plan = new UploadPlan();
        var targets = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in localPaths)
        {
            ct.ThrowIfCancellationRequested();
            var local = Path.TrimEndingDirectorySeparator(raw);
            FileSystemInfo entry = Directory.Exists(local) ? new DirectoryInfo(local) : new FileInfo(local);
            if (!entry.Exists) { plan.Skipped.Add($"(not found): {raw}"); continue; }
            if (IsLink(entry)) { plan.Skipped.Add($"(link not followed): {raw}"); continue; }
            if (entry is DirectoryInfo { Parent: null }) { plan.Skipped.Add($"(drive root): {raw}"); continue; }

            var remote = JoinRemote(baseFolder, entry.Name);
            if (targets.TryGetValue(remote, out var other))
                throw new InvalidOperationException(
                    $"Nothing was uploaded: \"{other}\" and \"{entry.FullName}\" would both be uploaded to {remote}. " +
                    "Upload them separately or rename one.");
            targets[remote] = entry.FullName;

            if (entry is DirectoryInfo dir)
            {
                var firstFile = plan.Files.Count;
                AddDirectory(plan, dir, remote, dir.Name, ct);
                var added = plan.Files.Skip(firstFile).ToList();
                plan.Items.Add($"folder {dir.Name} → {remote}/ ({added.Count} files, {FormatBytes(added.Sum(f => f.Size))})");
            }
            else
            {
                var file = (FileInfo)entry;
                plan.Files.Add(new PlannedFile(file.FullName, remote, file.Name, file.Length));
                plan.Items.Add($"{file.Name} ({FormatBytes(file.Length)}) → {remote}");
            }
        }
        return plan;
    }

    private static void AddDirectory(UploadPlan plan, DirectoryInfo dir, string remote, string display, CancellationToken ct)
    {
        plan.RemoteDirs.Add(remote);
        foreach (var entry in dir.EnumerateFileSystemInfos())
        {
            ct.ThrowIfCancellationRequested();
            if (IsLink(entry)) { plan.Skipped.Add($"(link not followed): {entry.FullName}"); continue; }
            var childRemote = remote + "/" + entry.Name;
            var childDisplay = display + "/" + entry.Name;
            if (entry is DirectoryInfo sub) AddDirectory(plan, sub, childRemote, childDisplay, ct);
            else if (entry is FileInfo file) plan.Files.Add(new PlannedFile(file.FullName, childRemote, childDisplay, file.Length));
        }
    }

    /// <summary>
    /// Symbolic links and junctions. Cloud placeholders (e.g. OneDrive) are reparse points too but have no
    /// link target, so they are treated as ordinary files.
    /// </summary>
    private static bool IsLink(FileSystemInfo entry) => entry.LinkTarget != null;

    private sealed record CommandResult(int? ExitStatus, string Output, string Error);

    /// <summary>
    /// Runs a remote command with a finite timeout. Cancelling the token signals the remote command to stop
    /// and throws <see cref="OperationCanceledException"/>.
    /// </summary>
    private static CommandResult Exec(SshClient ssh, string command, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var cmd = ssh.CreateCommand(command);
        cmd.CommandTimeout = RemoteCommandTimeout;
        try
        {
            cmd.ExecuteAsync(ct).GetAwaiter().GetResult();
        }
        catch (SshOperationTimeoutException)
        {
            throw new TimeoutException(
                $"The server did not finish ({Shorten(command)}) within {RemoteCommandTimeout.TotalMinutes:0} minutes.");
        }
        return new CommandResult(cmd.ExitStatus, cmd.Result, cmd.Error);
    }

    private static void RunChecked(SshClient ssh, string command, CancellationToken ct)
    {
        var r = Exec(ssh, command, ct);
        if (r.ExitStatus != 0)
            throw new InvalidOperationException($"Remote command failed ({Shorten(command)}): {r.Error.Trim()}");
    }

    private static string Shorten(string command) => command.Length > 200 ? command[..200] + "…" : command;

    /// <summary>Runs "command arg1 arg2 ..." in as few invocations as the command-line length allows.</summary>
    private static void RunBatched(SshClient ssh, string command, IEnumerable<string> args, CancellationToken ct)
    {
        foreach (var batch in QuotedBatches(args))
            RunChecked(ssh, $"{command} {batch}", ct);
    }

    /// <summary>Shell-quotes the arguments and joins them into space-separated chunks of bounded length.</summary>
    private static IEnumerable<string> QuotedBatches(IEnumerable<string> args)
    {
        const int maxLength = 16 * 1024;
        var batch = new StringBuilder();
        foreach (var arg in args)
        {
            var quoted = ShellQuote(arg);
            if (batch.Length > 0 && batch.Length + 1 + quoted.Length > maxLength)
            {
                yield return batch.ToString();
                batch.Clear();
            }
            if (batch.Length > 0) batch.Append(' ');
            batch.Append(quoted);
        }
        if (batch.Length > 0) yield return batch.ToString();
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

    public static string FormatBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double v = bytes; int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? $"{bytes} B" : $"{v:0.0} {units[u]}";
    }
}
