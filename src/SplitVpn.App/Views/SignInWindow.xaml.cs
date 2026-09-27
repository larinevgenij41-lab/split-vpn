using System.IO;
using Microsoft.Web.WebView2.Core;
using SplitVpn.App.Services;
using SplitVpn.Core.Ipc;
using Wpf.Ui.Controls;

namespace SplitVpn.App.Views;

/// <summary>
/// Встроенный браузер для SAML SSO шлюза AnyConnect. После каждой загрузки страницы служба получает адрес и cookie —
/// только хоста шлюза: среди них токен входа. Профиль браузера постоянный, поэтому организация может помнить вход.
/// </summary>
public partial class SignInWindow : FluentWindow, ISignInWindow
{
    private static readonly string UserDataFolder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SplitVpn", "WebView2");

    private readonly ServiceConnection _service;
    private readonly Guid _profileId;
    private readonly SignInPromptDto _prompt;
    private bool _closedByService;

    public SignInWindow(ServiceConnection service, Guid profileId, string tunnelName, SignInPromptDto prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        InitializeComponent();
        _service = service;
        _profileId = profileId;
        _prompt = prompt;
        Title = $"Вход в «{tunnelName}» — {prompt.GatewayHost}";
        TitleBar.Title = Title;
        Loaded += async (_, _) => await StartAsync();
    }

    public Guid RequestId => _prompt.RequestId;

    /// <summary>Служба больше не ждёт этот вход (принят, отменён, сеанс завершён): закрыть без отмены.</summary>
    public void CloseByService()
    {
        _closedByService = true;
        Close();
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
        Browser.Dispose();
        if (!_closedByService)
        {
            _ = SendQuietlyAsync(new CancelSignInRequest(_profileId, RequestId));
        }
    }

    /// <summary>
    /// Запуск встроенного браузера. Любая ошибка WebView2 (нет рантайма, занят профиль, отказ создания окружения)
    /// показывается в самом окне: иначе пользователь видит белое окно без объяснения.
    /// </summary>
    private async Task StartAsync()
    {
        try
        {
            var environment = await CoreWebView2Environment.CreateAsync(null, UserDataFolder);
            await Browser.EnsureCoreWebView2Async(environment);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            ShowProblem("Не найден компонент Microsoft Edge WebView2 Runtime: установите его с сайта Microsoft и нажмите «Войти» снова.");
            return;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ShowProblem("Встроенный браузер не запустился: " + ex.Message + " Закройте окно и нажмите «Войти» ещё раз.");
            return;
        }

        try
        {
            var core = Browser.CoreWebView2;
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.IsPasswordAutosaveEnabled = false;
            core.NavigationStarting += (_, e) =>
            {
                if (!e.Uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    e.Cancel = true;
                    ShowProblem("Переход на страницу без HTTPS отменён: вход возможен только по защищённому соединению.");
                }
            };
            // Всплывающие окна организации открываются здесь же: отдельное окно не передало бы результат шлюзу.
            core.NewWindowRequested += (_, e) =>
            {
                e.Handled = true;
                if (e.Uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    core.Navigate(e.Uri);
                }
            };
            core.NavigationCompleted += async (_, e) =>
            {
                if (!e.IsSuccess)
                {
                    ShowProblem($"Страница входа не открылась ({e.WebErrorStatus}). Проверьте в «Проверить адрес», доступен ли сайт организации.");
                    return;
                }

                await ReportNavigationAsync(core);
            };
            core.Navigate(_prompt.Uri);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ShowProblem("Страница входа не открылась: " + ex.Message);
        }
    }

    private async Task ReportNavigationAsync(CoreWebView2 core)
    {
        try
        {
            var uri = core.Source;
            IReadOnlyList<SsoCookie> cookies = [];
            if (Uri.TryCreate(uri, UriKind.Absolute, out var page) && string.Equals(page.Host, _prompt.GatewayHost, StringComparison.OrdinalIgnoreCase))
            {
                cookies = (await core.CookieManager.GetCookiesAsync(uri)).Select(c => new SsoCookie(c.Name, c.Value)).ToList();
            }

            var response = await _service.SendAsync(new SsoNavigationRequest(_profileId, RequestId, uri, cookies));
            if (!response.Ok && response.ErrorCode == IpcErrorCodes.NotFound)
            {
                // Служба уже не ждёт этот вход: окно закроет опрос состояния.
                ShowProblem(response.ErrorMessage ?? "Запрос входа устарел.");
            }
        }
        catch (ServiceUnavailableException ex)
        {
            ShowProblem(ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Ошибка браузера (окно уже закрывается, cookie недоступны): вход можно повторить кнопкой «Войти».
            ShowProblem("Результат входа не удалось передать службе: " + ex.Message);
        }
    }

    private void ShowProblem(string text)
    {
        Problem.Message = text;
        Problem.IsOpen = true;
    }

    private async Task SendQuietlyAsync(IpcRequest request)
    {
        try
        {
            await _service.SendAsync(request);
        }
        catch (ServiceUnavailableException)
        {
            // Служба недоступна: помощник сам завершит вход по таймауту.
        }
    }
}
