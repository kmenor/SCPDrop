# SCP Drop

A small Windows (WPF / .NET 10) app: drop files or folders onto the window and they are copied via SCP to a
preconfigured `user@host:/folder`.

## Run / build

```powershell
dotnet run                     # debug run
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish
# -> publish\SCPDrop.exe
```

## Usage

1. **Manage…** → **Add** a connection: name, host/IP, port, username, password *or* private key (+ optional
   passphrase), remote folder.
2. **Test connection** verifies login, checks the remote folder exists, and checks `scp` is on the remote PATH.
3. Pick the connection in **Send to:** and drop files/folders onto the drop zone (or use the Browse buttons).
   Folders are copied recursively as `<remote folder>/<folder name>/...`. Multiple drops queue up and run in order.

**Remote folder**: absolute (`/srv/drop`) or home-relative (`uploads`, `~/uploads`); blank = home directory.
With "Create remote folder" checked, `mkdir -p` runs before upload.

**Send To menu** (optional): paths passed on the command line are uploaded to the last-selected connection on
start. Put a shortcut to `SCPDrop.exe` in `shell:sendto` to get *Right-click → Send to → SCP Drop*.

## Security

- Config lives in `%APPDATA%\SCPDrop\config.json`. Passwords/passphrases are encrypted with Windows DPAPI
  (only your Windows account on this machine can decrypt them).
- Host keys are trust-on-first-use: you're shown the SHA256 fingerprint on first connect, and later connections
  are refused if the key changes. Use **Forget** in Manage Connections if a server was legitimately rebuilt.
  Changing a connection's host or port also forgets the stored key.

## Notes

- Uses [SSH.NET](https://github.com/sshnet/SSH.NET). The remote must have `scp` installed and a POSIX shell
  (folder creation uses `mkdir -p`) — i.e. a normal Linux/macOS/BSD server.
- Password auth also answers keyboard-interactive password prompts.
