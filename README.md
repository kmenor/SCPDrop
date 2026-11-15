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

**How files are written**
- Symbolic links and junctions are never followed (dropped directly or inside a folder); they're skipped and
  logged, so nothing outside the selected folder is sent.
- Each file is uploaded as a hidden `.scpdrop-<id>.part` temp file in its destination folder and renamed into
  place only once complete, so a failed or cancelled transfer never leaves a truncated file under the real name.
  Leftover temp files older than a day are cleaned up on later uploads to the same folder.
- If any destination files already exist you're asked once whether to replace them; declining uploads nothing.
  A replaced file gets the uploaded file's permissions (0644), not the old file's.
- Dropping two items with the same name (e.g. `a\report.txt` and `b\report.txt`) is refused up front.

**Remote folder**: absolute (`/srv/drop`) or home-relative (`uploads`, `~/uploads`); blank = home directory.
With "Create remote folder" checked, `mkdir -p` creates the remote folder if needed. Unchecked, an upload stops
before changing anything if the remote folder doesn't exist. Either way, folders you drop are always created inside
it.

**Send To menu** (optional): paths passed on the command line are uploaded to the last-selected connection on
start. Put a shortcut to `SCPDrop.exe` in `shell:sendto` to get *Right-click → Send to → SCP Drop*.

Only one SCP Drop runs per Windows user. Launching it again (including via Send To) hands the paths to the
window that's already open, where they join the upload queue, and the new launch exits.

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
