using System.Windows;
using System.Windows.Controls;
using SplitVpn.App.Services;
using SplitVpn.Core.Ipc;
using Wpf.Ui.Controls;
using TextBlock = System.Windows.Controls.TextBlock;

namespace SplitVpn.App.Views;

/// <summary>Окно, которое служба закрывает сама, когда запрос входа перестаёт быть актуальным.</summary>
public interface ISignInWindow
{
    Guid RequestId { get; }

    void CloseByService();
}

/// <summary>
/// Форма шлюза AnyConnect (группа, логин, пароль, одноразовый код). Поля строятся по описанию шлюза; значения
/// уходят службе одним секретным запросом и нигде не сохраняются.
/// </summary>
public sealed class SignInFormWindow : FluentWindow, ISignInWindow
{
    private readonly ServiceConnection _service;
    private readonly Guid _profileId;
    private readonly SignInPromptDto _prompt;
    private readonly List<(AuthFieldDto Field, Control Input)> _inputs = [];
    private readonly Wpf.Ui.Controls.Button _submit;
    private bool _closedByService;
    private bool _submitted;
    private bool _closed;

    public SignInFormWindow(ServiceConnection service, Guid profileId, string tunnelName, SignInPromptDto prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        _service = service;
        _profileId = profileId;
        _prompt = prompt;
        Title = $"Вход в «{tunnelName}»";
        Width = 440;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/Assets/app.ico"));

        var panel = new StackPanel { Margin = new Thickness(24) };
        panel.Children.Add(new TextBlock { Text = prompt.Title ?? "Вход на шлюзе", FontSize = 18, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(Muted($"{tunnelName} · {prompt.GatewayHost}"));
        if (!string.IsNullOrWhiteSpace(prompt.Message))
        {
            panel.Children.Add(new TextBlock { Text = prompt.Message, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 12, 0, 0) });
        }

        if (!string.IsNullOrWhiteSpace(prompt.Error))
        {
            panel.Children.Add(new InfoBar { Title = "Шлюз", Message = prompt.Error, Severity = InfoBarSeverity.Error, IsClosable = false, IsOpen = true, Margin = new Thickness(0, 12, 0, 0) });
        }

        foreach (var field in prompt.Fields)
        {
            panel.Children.Add(new TextBlock { Text = field.Label, Margin = new Thickness(0, 14, 0, 4) });
            var input = CreateInput(field);
            System.Windows.Automation.AutomationProperties.SetName(input, field.Label);
            panel.Children.Add(input);
            _inputs.Add((field, input));
        }

        _submit = new Wpf.Ui.Controls.Button { Content = "Войти", Appearance = ControlAppearance.Primary, IsDefault = true, Margin = new Thickness(0, 0, 8, 0) };
        _submit.Click += async (_, _) => await SubmitAsync();
        var cancel = new Wpf.Ui.Controls.Button { Content = "Отмена", IsCancel = true };
        cancel.Click += (_, _) => Close();
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
        buttons.Children.Add(_submit);
        buttons.Children.Add(cancel);
        panel.Children.Add(buttons);
        Content = panel;
        Loaded += (_, _) => _inputs.FirstOrDefault().Input?.Focus();
    }

    public Guid RequestId => _prompt.RequestId;

    public void CloseByService()
    {
        _closedByService = true;
        Close();
    }

    protected override void OnClosed(EventArgs e)
    {
        _closed = true;
        base.OnClosed(e);
        if (!_closedByService && !_submitted)
        {
            _ = SendAsync(new SubmitAuthFormRequest(_profileId, RequestId, new Dictionary<string, string>(), Cancel: true));
        }
    }

    private static Control CreateInput(AuthFieldDto field) => field.Kind switch
    {
        AuthFieldKind.Password => new Wpf.Ui.Controls.PasswordBox(),
        AuthFieldKind.Select => new ComboBox
        {
            ItemsSource = field.Choices,
            DisplayMemberPath = nameof(AuthChoiceDto.Label),
            SelectedValuePath = nameof(AuthChoiceDto.Name),
            SelectedValue = field.Value ?? (field.Choices.Count > 0 ? field.Choices[0].Name : null),
        },
        _ => new Wpf.Ui.Controls.TextBox { Text = field.Value ?? "" },
    };

    private static TextBlock Muted(string text) => new()
    {
        Text = text,
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 4, 0, 0),
        Foreground = (System.Windows.Media.Brush)Application.Current.FindResource("TextFillColorSecondaryBrush"),
    };

    private async Task SubmitAsync()
    {
        var values = _inputs.ToDictionary(i => i.Field.Name, i => i.Input switch
        {
            Wpf.Ui.Controls.PasswordBox password => password.Password,
            ComboBox select => select.SelectedValue as string ?? "",
            Wpf.Ui.Controls.TextBox text => text.Text,
            _ => "",
        });
        _submit.IsEnabled = false;
        if (await SendAsync(new SubmitAuthFormRequest(_profileId, RequestId, values, Cancel: false)))
        {
            _submitted = true;
            if (!_closed)
            {
                Close();
            }
        }
        else if (!_closed)
        {
            _submit.IsEnabled = true;
        }
    }

    private async Task<bool> SendAsync(IpcRequest request)
    {
        try
        {
            return (await _service.SendAsync(request)).Ok;
        }
        catch (ServiceUnavailableException)
        {
            return false;
        }
    }
}
