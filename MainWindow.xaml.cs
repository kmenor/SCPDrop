using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using SCPDrop.Models;
using SCPDrop.Services;

namespace SCPDrop;

public partial class MainWindow : Window
{
    private AppConfig _config;
    private readonly SemaphoreSlim _uploadGate = new(1, 1);
    private CancellationTokenSource? _cts;
    private Task? _cancelling;
    private int _queued;
    private bool _loading;
    private bool _managing;
    private readonly List<string> _pendingExternal = new();

    public MainWindow()
    {
        InitializeComponent();
        _config = ConfigStore.Load();
        _loading = true;
        TopmostCheck.IsChecked = _config.AlwaysOnTop;
        Topmost = _config.AlwaysOnTop;
        _loading = false;
        RefreshConnections();
        Log($"Config: {ConfigStore.FilePath}");
    }

    /// <summary>
    /// Paths from this process's command line or forwarded from a later launch (e.g. the Send To menu).
    /// Brings the window forward and queues them for upload.
    /// </summary>
    public void HandleExternalPaths(string[] args)
    {
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();

        var paths = args.Where(a => File.Exists(a) || Directory.Exists(a)).ToArray();
        if (paths.Length == 0) return;
        if (_managing)
        {
            // Connections are being edited; start once the editor closes so the upload uses the saved profile.
            _pendingExternal.AddRange(paths);
            Log($"Received {paths.Length} item(s); they'll upload when Manage Connections is closed.");
            return;
        }
        _ = UploadAsync(paths);
    }

    private RemoteConnection? Selected => ConnectionCombo.SelectedItem as RemoteConnection;

    private void RefreshConnections()
    {
        _loading = true;
        ConnectionCombo.ItemsSource = null;
        ConnectionCombo.ItemsSource = _config.Connections;
        ConnectionCombo.SelectedItem =
            _config.Connections.FirstOrDefault(c => c.Id == _config.LastSelectedId) ?? _config.Connections.FirstOrDefault();
        _loading = false;
        UpdateTarget();
    }

    private void UpdateTarget()
    {
        var c = Selected;
        TargetText.Text = c?.TargetDisplay ?? "No connection configured — click Manage… to add one.";
        var enabled = c != null;
        DropZone.Opacity = enabled ? 1.0 : 0.6;
        BrowseFilesButton.IsEnabled = BrowseFolderButton.IsEnabled = enabled;
    }

    private void ConnectionCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_loading) return;
        _config.LastSelectedId = Selected?.Id;
        SaveConfig();
        UpdateTarget();
    }

    private void Manage_Click(object sender, RoutedEventArgs e)
    {
        var win = new ConnectionsWindow(_config.Connections, Selected?.Id) { Owner = this };
        _managing = true;
        bool saved;
        try { saved = win.ShowDialog() == true; }
        finally { _managing = false; }
        if (saved)
        {
            _config.Connections = win.Connections;
            if (win.SelectedId != null) _config.LastSelectedId = win.SelectedId;
            SaveConfig();
            RefreshConnections();
        }

        if (_pendingExternal.Count > 0)
        {
            var pending = _pendingExternal.ToArray();
            _pendingExternal.Clear();
            _ = UploadAsync(pending);
        }
    }

    // ---- Drag & drop ----

    private void DropZone_DragOver(object sender, DragEventArgs e)
    {
        var ok = e.Data.GetDataPresent(DataFormats.FileDrop) && Selected != null;
        e.Effects = ok ? DragDropEffects.Copy : DragDropEffects.None;
        if (ok)
        {
            DropZone.Background = new SolidColorBrush(Color.FromRgb(0xE3, 0xEE, 0xFB));
            DropBorder.Stroke = new SolidColorBrush(Color.FromRgb(0x2F, 0x6F, 0xC9));
        }
        e.Handled = true;
    }

    private void DropZone_DragLeave(object sender, DragEventArgs e) => ResetDropZone();

    private void ResetDropZone()
    {
        DropZone.Background = new SolidColorBrush(Color.FromRgb(0xF7, 0xF9, 0xFC));
        DropBorder.Stroke = new SolidColorBrush(Color.FromRgb(0x8A, 0xA4, 0xC8));
    }

    private async void DropZone_Drop(object sender, DragEventArgs e)
    {
        ResetDropZone();
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
            await UploadAsync(paths);
    }

    private async void BrowseFiles_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Multiselect = true, Title = "Select files to upload" };
        if (dlg.ShowDialog(this) == true) await UploadAsync(dlg.FileNames);
    }

    private async void BrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Multiselect = true, Title = "Select folders to upload" };
        if (dlg.ShowDialog(this) == true) await UploadAsync(dlg.FolderNames);
    }

    // ---- Upload ----

    private async Task UploadAsync(IReadOnlyList<string> paths)
    {
        var conn = Selected;
        if (conn == null)
        {
            MessageBox.Show(this, "Add a connection first (Manage…).", "SCP Drop", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var label = paths.Count == 1 ? Path.GetFileName(paths[0].TrimEnd('\\')) : $"{paths.Count} items";
        if (Interlocked.Increment(ref _queued) > 1) Log($"Queued {label} for {conn.Name}");

        await _uploadGate.WaitAsync();
        _cts = new CancellationTokenSource();
        SetBusy(true);
        var started = DateTime.Now;
        try
        {
            Log($"Sending {label} to {conn.Name} ({conn.TargetDisplay})");
            StatusText.Text = $"Connecting to {conn.Host}…";
            Progress.Value = 0;

            var progress = new Progress<UploadProgress>(p =>
            {
                Progress.Value = p.BytesTotal > 0 ? 100.0 * p.BytesDone / p.BytesTotal : 0;
                StatusText.Text = $"{p.CurrentFile} — {ScpUploader.FormatBytes(p.BytesDone)} / {ScpUploader.FormatBytes(p.BytesTotal)}";
            });

            var ui = new WpfConnectionUi(this, SaveConfig);
            var result = await ScpUploader.UploadAsync(conn, paths, progress, ui, msg => Dispatcher.Invoke(() => Log(msg)), _cts.Token);

            var secs = (DateTime.Now - started).TotalSeconds;
            var files = $"{result.FilesUploaded} file{(result.FilesUploaded == 1 ? "" : "s")}";
            if (result.NothingUploaded)
            {
                Progress.Value = 0;
                StatusText.Text = $"Nothing uploaded: {label} (see log)";
                Log($"✖ Nothing uploaded: all {result.ItemsRequested} item(s) were skipped");
            }
            else if (!result.Complete)
            {
                Progress.Value = 100;
                StatusText.Text = $"Partly done: {result.ItemsUploaded} of {result.ItemsRequested} item(s) → {conn.Name}, " +
                                  $"{result.Skipped.Count} skipped (see log)";
                Log($"⚠ Partly completed {label} in {secs:0.0}s: {files} uploaded, {result.Skipped.Count} skipped");
            }
            else
            {
                Progress.Value = 100;
                StatusText.Text = $"Done: {label} → {conn.Name}";
                Log($"✔ Completed {label} in {secs:0.0}s ({files})");
            }
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Cancelled.";
            Log("✖ Cancelled");
        }
        catch (Exception ex)
        {
            StatusText.Text = "Failed: " + ex.Message;
            Log("✖ Error: " + ex.Message);
        }
        finally
        {
            // The source can only be disposed once its cancellation callbacks have finished.
            if (_cancelling != null) await _cancelling;
            _cancelling = null;
            _cts.Dispose();
            _cts = null;
            Interlocked.Decrement(ref _queued);
            SetBusy(_queued > 0);
            _uploadGate.Release();
        }
    }

    private void SetBusy(bool busy)
    {
        CancelButton.IsEnabled = busy;
        ManageButton.IsEnabled = !busy;
        ConnectionCombo.IsEnabled = !busy;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if (_cts == null || _cts.IsCancellationRequested) return;
        StatusText.Text = "Cancelling…";
        CancelButton.IsEnabled = false;
        // CancelAsync runs the cancellation callbacks (dropping the SCP connection etc.) off the UI thread.
        _cancelling = _cts.CancelAsync();
    }

    // ---- Misc ----

    private void Topmost_Changed(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        Topmost = _config.AlwaysOnTop = TopmostCheck.IsChecked == true;
        SaveConfig();
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e) => LogBox.Clear();

    private void Log(string message)
    {
        LogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        LogBox.ScrollToEnd();
    }

    private void SaveConfig()
    {
        try { ConfigStore.Save(_config); }
        catch (Exception ex) { Log("Could not save config: " + ex.Message); }
    }
}
