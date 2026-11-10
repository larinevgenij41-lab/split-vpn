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
    private const string SubmitText = "Войти";
    private const string SubmittingText = "Выполняется вход…";

    private readonly ServiceConnection _service;
    private readonly Guid _profileId;
    private readonly SignInPromptDto _prompt;
    private readonly List<(AuthFieldDto Field, Control Input)> _inputs = [];
    private readonly Wpf.Ui.Controls.Button _submit;
    private readonly InfoBar _problem;
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
        // Высокая форма (много полей, длинное сообщение шлюза, крупный шрифт) не должна выходить за рабочую область:
        // поля прокручиваются, а кнопки остаются на виду.
        MaxHeight = SystemParameters.WorkArea.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri("pack://application:,,,/Assets/app.ico"));

        var panel = new StackPanel { Margin = new Thickness(24, 24, 24, 0) };
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

        // Отказ при отправке формы: без него окно просто снова разблокировало бы кнопку, не объяснив почему.
        _problem = new InfoBar { Severity = InfoBarSeverity.Error, IsClosable = false, IsOpen = false, Margin = new Thickness(0, 12, 0, 0) };
        System.Windows.Automation.AutomationProperties.SetLiveSetting(_problem, System.Windows.Automation.AutomationLiveSetting.Assertive);

        _submit = new Wpf.Ui.Controls.Button { Content = SubmitText, Appearance = ControlAppearance.Primary, IsDefault = true, Margin = new Thickness(0, 0, 8, 0) };
        _submit.Click += async (_, _) => await SubmitAsync();
        var cancel = new Wpf.Ui.Controls.Button { Content = "Отмена", IsCancel = true };
        cancel.Click += (_, _) => Close();
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
        buttons.Children.Add(_submit);
        buttons.Children.Add(cancel);

        // Отказ и кнопки лежат вне прокрутки, под полями.
        var footer = new StackPanel { Margin = new Thickness(24, 0, 24, 24) };
        footer.Children.Add(_problem);
        footer.Children.Add(buttons);
        var layout = new Grid();
        layout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = panel };
        Grid.SetRow(footer, 1);
        layout.Children.Add(scroll);
        layout.Children.Add(footer);
        Content = layout;
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

    private static TextBlock Muted(string text)
    {
        var block = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0) };
        // Ссылка на ресурс, а не разовое значение: подзаголовок следует за сменой темы, пока форма открыта.
        block.SetResourceReference(TextBlock.ForegroundProperty, "TextFillColorSecondaryBrush");
        return block;
    }

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
        // Ответ шлюза может идти несколько секунд: серая кнопка без подписи выглядит как зависшее окно.
        _submit.Content = SubmittingText;
        System.Windows.Automation.AutomationProperties.SetName(_submit, SubmittingText);
        _problem.IsOpen = false;
        LiveRegion.SetValue(_problem, null);
        string? problem;
        try
        {
            var response = await _service.SendAsync(new SubmitAuthFormRequest(_profileId, RequestId, values, Cancel: false));
            problem = response.Ok ? null : response.ErrorMessage ?? response.ErrorCode ?? "Служба отклонила данные входа.";
        }
        catch (ServiceUnavailableException ex)
        {
            problem = ex.Message;
        }

        if (problem is null)
        {
            _submitted = true;
            if (!_closed)
            {
                Close();
            }
        }
        else if (!_closed)
        {
            _problem.Message = problem;
            _problem.IsOpen = true;
            LiveRegion.SetValue(_problem, problem);
            _submit.Content = SubmitText;
            System.Windows.Automation.AutomationProperties.SetName(_submit, SubmitText);
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
