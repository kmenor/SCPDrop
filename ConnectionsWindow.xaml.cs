using System.Globalization;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using SCPDrop.Models;
using SCPDrop.Services;

namespace SCPDrop;

public partial class ConnectionsWindow : Window
{
    /// <summary>Working copy; only handed back to the caller when the user clicks Save.</summary>
    public List<RemoteConnection> Connections { get; }
    public Guid? SelectedId => _current?.Id;

    private RemoteConnection? _current;
    private bool _loading;
    private bool _passwordEdited;
    private bool _passphraseEdited;

    public ConnectionsWindow(List<RemoteConnection> connections, Guid? selectId)
    {
        InitializeComponent();
        Connections = ConfigStore.DeepClone(connections);
        ConnectionList.ItemsSource = Connections;
        ConnectionList.SelectedItem = Connections.FirstOrDefault(c => c.Id == selectId) ?? Connections.FirstOrDefault();
        if (ConnectionList.SelectedItem == null) LoadForm(null);
    }

    private void ConnectionList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_loading) return;
        if (!PortIsValid())
        {
            // Stay on the connection with the bad port rather than silently keeping or replacing it.
            _loading = true;
            ConnectionList.SelectedItem = _current;
            _loading = false;
            return;
        }
        Commit();
        _current = ConnectionList.SelectedItem as RemoteConnection;
        LoadForm(_current);
    }

    private static bool TryParsePort(string text, out int port) =>
        int.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port) && RemoteConnection.IsValidPort(port);

    /// <summary>
    /// Checks the port field of the connection being edited. Shows an error and returns false if it isn't
    /// a whole number from 1 to 65535, so the caller can refuse to test, save or leave the connection.
    /// </summary>
    private bool PortIsValid()
    {
        if (_current == null || TryParsePort(PortBox.Text, out _)) return true;
        MessageBox.Show(this, $"\"{PortBox.Text.Trim()}\" isn't a valid port. Enter a whole number from 1 to 65535 (SSH is usually 22).",
            "Invalid port", MessageBoxButton.OK, MessageBoxImage.Warning);
        PortBox.Focus();
        PortBox.SelectAll();
        return false;
    }

    private void LoadForm(RemoteConnection? c)
    {
        _loading = true;
        FormPanel.IsEnabled = c != null;
        c ??= new RemoteConnection { Name = "" };
        NameBox.Text = c.Name;
        HostBox.Text = c.Host;
        PortBox.Text = c.Port.ToString();
        UserBox.Text = c.Username;
        PasswordRadio.IsChecked = c.Auth == AuthMethod.Password;
        KeyRadio.IsChecked = c.Auth == AuthMethod.PrivateKey;
        // A secret that can't be decrypted is shown as empty with a warning, and left untouched on save
        // unless the user types a replacement or removes it.
        PasswordWarning.Visibility = Secret.TryUnprotect(c.EncryptedPassword, out var password) ? Visibility.Collapsed : Visibility.Visible;
        PasswordBox.Password = password;
        _passwordEdited = false;
        KeyPathBox.Text = c.PrivateKeyPath ?? "";
        PassphraseWarning.Visibility = Secret.TryUnprotect(c.EncryptedPassphrase, out var passphrase) ? Visibility.Collapsed : Visibility.Visible;
        PassphraseBox.Password = passphrase;
        _passphraseEdited = false;
        FolderBox.Text = c.RemoteFolder;
        CreateFolderCheck.IsChecked = c.CreateRemoteFolder;
        HostKeyBox.Text = c.HostKeyFingerprint ?? "(not yet trusted — you'll be asked on first connect)";
        TestResultText.Text = "";
        UpdateAuthPanels();
        _loading = false;
    }

    /// <summary>Copy the form fields back into the currently selected connection.</summary>
    private void Commit()
    {
        var c = _current;
        if (c == null) return;
        c.Name = NameBox.Text.Trim();
        var newHost = HostBox.Text.Trim();
        // Callers check PortIsValid() first; an invalid entry never replaces the stored port.
        var newPort = TryParsePort(PortBox.Text, out var port) ? port : c.Port;
        if (!string.Equals(newHost, c.Host, StringComparison.OrdinalIgnoreCase) || newPort != c.Port)
        {
            // A different server means the previously trusted key no longer applies.
            if (c.Host.Length > 0) c.HostKeyFingerprint = null;
            c.Host = newHost;
            c.Port = newPort;
        }
        c.Username = UserBox.Text.Trim();
        c.Auth = KeyRadio.IsChecked == true ? AuthMethod.PrivateKey : AuthMethod.Password;
        // Secrets are only re-encrypted when the user actually changed them.
        if (_passwordEdited) c.EncryptedPassword = Secret.Protect(PasswordBox.Password);
        c.PrivateKeyPath = string.IsNullOrWhiteSpace(KeyPathBox.Text) ? null : KeyPathBox.Text.Trim();
        if (_passphraseEdited) c.EncryptedPassphrase = Secret.Protect(PassphraseBox.Password);
        c.RemoteFolder = FolderBox.Text.Trim();
        c.CreateRemoteFolder = CreateFolderCheck.IsChecked == true;
    }

    private void NameBox_LostFocus(object sender, RoutedEventArgs e)
    {
        if (_loading || _current == null) return;
        _current.Name = NameBox.Text.Trim();
        _loading = true;
        ConnectionList.Items.Refresh();
        _loading = false;
    }

    private void Auth_Changed(object sender, RoutedEventArgs e) => UpdateAuthPanels();

    private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        _passwordEdited = true;
        PasswordWarning.Visibility = Visibility.Collapsed;
    }

    private void PassphraseBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        _passphraseEdited = true;
        PassphraseWarning.Visibility = Visibility.Collapsed;
    }

    private void RemovePassword_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null) return;
        _current.EncryptedPassword = null;
        PasswordWarning.Visibility = Visibility.Collapsed;
    }

    private void RemovePassphrase_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null) return;
        _current.EncryptedPassphrase = null;
        PassphraseWarning.Visibility = Visibility.Collapsed;
    }

    private void UpdateAuthPanels()
    {
        var key = KeyRadio.IsChecked == true;
        KeyPanel.Visibility = key ? Visibility.Visible : Visibility.Collapsed;
        PasswordPanel.Visibility = key ? Visibility.Collapsed : Visibility.Visible;
    }

    private void Add_Click(object sender, RoutedEventArgs e) => AddAndSelect(new RemoteConnection());

    private void Duplicate_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null || !PortIsValid()) return;
        Commit();
        var copy = ConfigStore.DeepClone(_current);
        copy.Id = Guid.NewGuid();
        copy.Name += " (copy)";
        AddAndSelect(copy);
    }

    private void AddAndSelect(RemoteConnection c)
    {
        if (!PortIsValid()) return;
        Commit();
        Connections.Add(c);
        ConnectionList.Items.Refresh();
        ConnectionList.SelectedItem = c;
        NameBox.Focus();
        NameBox.SelectAll();
    }

    private void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null) return;
        if (MessageBox.Show(this, $"Delete connection '{_current.Name}'?", "Delete", MessageBoxButton.YesNo,
                MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        var idx = Connections.IndexOf(_current);
        Connections.Remove(_current);
        _current = null;
        ConnectionList.Items.Refresh();
        ConnectionList.SelectedItem = Connections.Count == 0 ? null : Connections[Math.Min(idx, Connections.Count - 1)];
        if (Connections.Count == 0) LoadForm(null);
    }

    private void BrowseKey_Click(object sender, RoutedEventArgs e)
    {
        var sshDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
        var dlg = new OpenFileDialog
        {
            Title = "Select private key",
            Filter = "All files (*.*)|*.*",
            InitialDirectory = Directory.Exists(sshDir) ? sshDir : null
        };
        if (dlg.ShowDialog(this) == true) KeyPathBox.Text = dlg.FileName;
    }

    private void ClearHostKey_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null) return;
        _current.HostKeyFingerprint = null;
        HostKeyBox.Text = "(not yet trusted — you'll be asked on first connect)";
    }

    private async void Test_Click(object sender, RoutedEventArgs e)
    {
        if (!PortIsValid()) return;
        Commit();
        var live = _current;
        if (live == null) return;

        // Test a frozen copy so the background connection never sees edits made meanwhile, and a host key
        // trusted during the test can't be stored on a profile that now points somewhere else.
        var snapshot = ConfigStore.DeepClone(live);
        SetTesting(true);
        TestResultText.Foreground = Brushes.Black;
        TestResultText.Text = $"Connecting to {snapshot.Host}:{snapshot.Port}…";
        Brush color;
        string text;
        try
        {
            var result = await Task.Run(() => ScpUploader.Test(snapshot, new WpfConnectionUi(this)));
            color = Brushes.DarkGreen;
            text = "✔ " + result;
        }
        catch (Exception ex)
        {
            color = Brushes.Firebrick;
            text = "✖ " + ex.Message;
        }

        if (snapshot.HostKeyFingerprint != null && live.HostKeyFingerprint == null && SameEndpoint(live, snapshot))
            live.HostKeyFingerprint = snapshot.HostKeyFingerprint;
        SetTesting(false);

        // Only show the result against the profile that was actually tested.
        if (_current == live && SameEndpoint(live, snapshot))
        {
            TestResultText.Foreground = color;
            TestResultText.Text = text;
            HostKeyBox.Text = live.HostKeyFingerprint ?? "(not yet trusted — you'll be asked on first connect)";
        }
    }

    /// <summary>Locks selection, editing and Save while a connection test is running.</summary>
    private void SetTesting(bool testing)
    {
        ListPanel.IsEnabled = !testing;
        FormPanel.IsEnabled = !testing && _current != null;
        SaveButton.IsEnabled = !testing;
    }

    private static bool SameEndpoint(RemoteConnection a, RemoteConnection b) =>
        string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase) && a.Port == b.Port;

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (!PortIsValid()) return;
        Commit();
        foreach (var c in Connections)
        {
            string? problem = string.IsNullOrWhiteSpace(c.Name) ? "a name"
                : string.IsNullOrWhiteSpace(c.Host) ? "a host"
                : string.IsNullOrWhiteSpace(c.Username) ? "a username"
                : c.Auth == AuthMethod.PrivateKey && string.IsNullOrWhiteSpace(c.PrivateKeyPath) ? "a private key file"
                : null;
            if (problem == null) continue;
            ConnectionList.SelectedItem = c;
            MessageBox.Show(this, $"Connection '{(c.Name.Length > 0 ? c.Name : "(unnamed)")}' needs {problem}.",
                "Incomplete connection", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        DialogResult = true;
    }
}
