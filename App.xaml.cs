using System.Windows;
using System.Windows.Controls;
using SCPDrop.Models;
using SCPDrop.Services;

namespace SCPDrop;

public partial class App : Application
{
}

/// <summary>Shows host-key and keyboard-interactive prompts over a window; safe to call from any thread.</summary>
public sealed class WpfConnectionUi(Window owner, Action? onHostKeyTrusted = null) : IConnectionUi
{
    public bool TrustHostKey(RemoteConnection conn, string fingerprint, string keyType) =>
        owner.Dispatcher.Invoke(() =>
        {
            var answer = MessageBox.Show(owner,
                $"This is the first connection to {conn.Host}:{conn.Port}.\n\n" +
                $"Host key ({keyType}):\n{fingerprint}\n\n" +
                "Verify this fingerprint with the server administrator (ssh-keygen -lf /etc/ssh/ssh_host_*.pub).\n\n" +
                "Trust this host and remember its key?",
                "Verify host key", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes) return false;
            conn.HostKeyFingerprint = fingerprint;
            onHostKeyTrusted?.Invoke();
            return true;
        });

    public string? Ask(RemoteConnection conn, string instruction, string request, bool echo) =>
        owner.Dispatcher.Invoke(() => PromptDialog.Ask(owner, $"{conn.Username}@{conn.Host}", instruction, request, echo));
}

/// <summary>Minimal input dialog for keyboard-interactive prompts (password retry, 2FA code, ...).</summary>
public sealed class PromptDialog : Window
{
    private readonly TextBox _text = new() { Padding = new Thickness(3) };
    private readonly PasswordBox _password = new() { Padding = new Thickness(3) };

    private PromptDialog(string title, string instruction, string request, bool echo)
    {
        Title = title;
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;

        var panel = new StackPanel { Margin = new Thickness(14), Width = 360 };
        panel.Children.Add(new TextBlock
        {
            Text = "The server is asking:",
            Foreground = System.Windows.Media.Brushes.Gray,
            Margin = new Thickness(0, 0, 0, 6)
        });
        if (!string.IsNullOrWhiteSpace(instruction))
            panel.Children.Add(new TextBlock { Text = instruction.Trim(), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6) });
        panel.Children.Add(new TextBlock
        {
            Text = string.IsNullOrWhiteSpace(request) ? "Response:" : request,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 4)
        });
        Control input = echo ? _text : _password;
        panel.Children.Add(input);

        var ok = new Button { Content = "OK", IsDefault = true, Margin = new Thickness(0, 0, 8, 0) };
        ok.Click += (_, _) => DialogResult = true;
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        panel.Children.Add(buttons);

        Content = panel;
        Loaded += (_, _) => input.Focus();
    }

    public static string? Ask(Window owner, string title, string instruction, string request, bool echo)
    {
        var dlg = new PromptDialog(title, instruction, request, echo) { Owner = owner, Topmost = owner.Topmost };
        return dlg.ShowDialog() == true ? (echo ? dlg._text.Text : dlg._password.Password) : null;
    }
}
