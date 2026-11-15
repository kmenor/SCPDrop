using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;

namespace SCPDrop.Services;

/// <summary>
/// Keeps one SCP Drop process per Windows user, so a single process owns config.json. Later launches
/// (e.g. from the Send To menu) forward their command-line paths to it over a named pipe and exit.
/// </summary>
public sealed class SingleInstance : IDisposable
{
    private static readonly string Key =
        "SCPDrop-" + (WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName);

    private static string PipeName => Key;

    private const int MaxMessageBytes = 1024 * 1024;

    private readonly Mutex _mutex;
    private readonly CancellationTokenSource _listening = new();

    private SingleInstance(Mutex mutex) => _mutex = mutex;

    /// <summary>
    /// Returns the instance guard if this is the first process for the current user, otherwise null.
    /// The mutex is in the Global namespace so other sessions (e.g. RDP) of the same user count too.
    /// </summary>
    public static SingleInstance? TryAcquire()
    {
        Mutex mutex;
        bool created;
        try
        {
            mutex = new Mutex(initiallyOwned: true, @"Global\" + Key, out created);
        }
        catch (UnauthorizedAccessException)
        {
            mutex = new Mutex(initiallyOwned: true, @"Local\" + Key, out created);
        }
        if (created) return new SingleInstance(mutex);
        mutex.Dispose();
        return null;
    }

    /// <summary>Sends paths to the running instance. False if it couldn't be reached.</summary>
    public static bool TrySend(IReadOnlyList<string> args)
    {
        try
        {
            // CurrentUserOnly also verifies the pipe's server runs as this user, so paths can't be handed to
            // a pipe someone else created under the same name.
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out, PipeOptions.CurrentUserOnly);
            client.Connect(TimeSpan.FromSeconds(5));
            client.Write(JsonSerializer.SerializeToUtf8Bytes(args));
            client.Flush();
            return true;
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Accepts forwarded paths until disposed. <paramref name="onArgs"/> runs on the caller's context.</summary>
    public async Task ListenAsync(Action<string[]> onArgs)
    {
        var ct = _listening.Token;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(PipeName, PipeDirection.In, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await server.WaitForConnectionAsync(ct);

                using var buffer = new MemoryStream();
                var chunk = new byte[64 * 1024];
                int read;
                while ((read = await server.ReadAsync(chunk, ct)) > 0)
                {
                    buffer.Write(chunk, 0, read);
                    if (buffer.Length > MaxMessageBytes) throw new InvalidDataException("Message too large.");
                }
                onArgs(JsonSerializer.Deserialize<string[]>(buffer.ToArray()) ?? []);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException)
            {
                // A broken or malformed message: drop it and keep listening.
            }
        }
    }

    public void Dispose()
    {
        _listening.Cancel();
        _listening.Dispose();
        _mutex.ReleaseMutex();
        _mutex.Dispose();
    }
}
