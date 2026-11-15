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
        Commit();
        _current = ConnectionList.SelectedItem as RemoteConnection;
        LoadForm(_current);
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
        PasswordBox.Password = Secret.Unprotect(c.EncryptedPassword);
        KeyPathBox.Text = c.PrivateKeyPath ?? "";
        PassphraseBox.Password = Secret.Unprotect(c.EncryptedPassphrase);
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
        var newPort = int.TryParse(PortBox.Text.Trim(), out var port) && port is > 0 and < 65536 ? port : 22;
        if (!string.Equals(newHost, c.Host, StringComparison.OrdinalIgnoreCase) || newPort != c.Port)
        {
            // A different server means the previously trusted key no longer applies.
            if (c.Host.Length > 0) c.HostKeyFingerprint = null;
            c.Host = newHost;
            c.Port = newPort;
        }
        c.Username = UserBox.Text.Trim();
        c.Auth = KeyRadio.IsChecked == true ? AuthMethod.PrivateKey : AuthMethod.Password;
        c.EncryptedPassword = Secret.Protect(PasswordBox.Password);
        c.PrivateKeyPath = string.IsNullOrWhiteSpace(KeyPathBox.Text) ? null : KeyPathBox.Text.Trim();
        c.EncryptedPassphrase = Secret.Protect(PassphraseBox.Password);
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

    private void UpdateAuthPanels()
    {
        var key = KeyRadio.IsChecked == true;
        KeyPanel.Visibility = key ? Visibility.Visible : Visibility.Collapsed;
        PasswordPanel.Visibility = key ? Visibility.Collapsed : Visibility.Visible;
    }

    private void Add_Click(object sender, RoutedEventArgs e) => AddAndSelect(new RemoteConnection());

    private void Duplicate_Click(object sender, RoutedEventArgs e)
    {
        if (_current == null) return;
        Commit();
        var copy = ConfigStore.DeepClone(_current);
        copy.Id = Guid.NewGuid();
        copy.Name += " (copy)";
        AddAndSelect(copy);
    }

    private void AddAndSelect(RemoteConnection c)
    {
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
        Commit();
        var c = _current;
        if (c == null) return;
        TestButton.IsEnabled = false;
        TestResultText.Foreground = Brushes.Black;
        TestResultText.Text = $"Connecting to {c.Host}:{c.Port}…";
        try
        {
            var result = await Task.Run(() => ScpUploader.Test(c, new WpfConnectionUi(this)));
            TestResultText.Foreground = Brushes.DarkGreen;
            TestResultText.Text = "✔ " + result;
        }
        catch (Exception ex)
        {
            TestResultText.Foreground = Brushes.Firebrick;
            TestResultText.Text = "✖ " + ex.Message;
        }
        finally
        {
            HostKeyBox.Text = c.HostKeyFingerprint ?? "(not yet trusted — you'll be asked on first connect)";
            TestButton.IsEnabled = true;
        }
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
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
