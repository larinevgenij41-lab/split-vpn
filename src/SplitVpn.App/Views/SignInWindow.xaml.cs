using Microsoft.Web.WebView2.Core;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;
using Wpf.Ui.Controls;

namespace SplitVpn.App.Views;

/// <summary>
/// Встроенный браузер для SAML SSO шлюза AnyConnect. После каждой загрузки страницы служба получает адрес и cookie —
/// только хоста шлюза: среди них токен входа. Профиль браузера постоянный, поэтому организация может помнить вход.
/// У каждого подключения AnyConnect свой профиль браузера: вход одной организации (её cookie и учётная запись SSO)
/// не подставляется при входе в другую.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "Время жизни ресурса ограничено окном: OnClosed отменяет операции и освобождает источник.")]
public partial class SignInWindow : FluentWindow, ISignInWindow
{
    private readonly ServiceConnection _service;
    private readonly Guid _profileId;
    private readonly SignInPromptDto _prompt;
    private readonly SignInRetryPolicy _retry = new();
    private readonly CancellationTokenSource _lifetime = new();
    private bool _closedByService;
    private bool _closed;


    /// <summary>Номер последнего начатого перехода: отложенный повтор относится только к нему.</summary>
    private ulong _navigation;

    /// <summary>Переход, отменённый самим окном (страница без HTTPS): его причина уже показана.</summary>
    private ulong? _cancelledNavigation;

    /// <summary>
    /// При этой загрузке страницы не открыт фрейм (<see cref="SignInBrowserPolicy.FrameBlockedProblem"/>): панель с
    /// объяснением не закрывается успешной загрузкой страницы. Сбрасывается при переходе основной страницы.
    /// </summary>
    private string? _frameNotice;

    public SignInWindow(ServiceConnection service, Guid profileId, string tunnelName, SignInPromptDto prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);
        InitializeComponent();
        WindowFit.Apply(this);
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
        _closed = true;
        _lifetime.Cancel();
        _lifetime.Dispose();
        base.OnClosed(e);
        Browser.Dispose();
        if (!_closedByService)
        {
            _ = SendQuietlyAsync(new CancelSignInRequest(_profileId, RequestId));
        }
    }

    /// <summary>
    /// Запуск встроенного браузера. Любая ошибка WebView2 (нет рантайма, занят профиль, отказ создания окружения)
    /// показывается в самом окне: иначе пользователь видит белое окно без объяснения. Окно могла закрыть служба, пока
    /// шли подготовка профиля и запуск браузера: тогда запуск молча прекращается, а освобождённый браузер — не сбой.
    /// </summary>
    private async Task StartAsync()
    {
        try
        {
            // Подготовка профиля удаляет и переносит каталоги в тысячи файлов: вне потока интерфейса.
            var userDataFolder = await SignInProfileWork.RunAsync(profiles => profiles.Prepare(_profileId, _prompt.GatewayHost));
            if (_closed) { return; }
            var environment = await CoreWebView2Environment.CreateAsync(null, userDataFolder);
            if (_closed) { return; }
            Verbose.Write("SignIn", $"браузер: WebView2 {environment.BrowserVersionString}, профиль {userDataFolder}");
            await Browser.EnsureCoreWebView2Async(environment);
            if (_closed) { return; }
        }
        catch (WebView2RuntimeNotFoundException)
        {
            if (!_closed)
            {
                ShowProblem("Не найден компонент Microsoft Edge WebView2 Runtime: установите его с сайта Microsoft и нажмите «Войти» снова.");
            }

            return;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Окно закрыто посреди запуска (браузер освобождён): это не «браузер не запустился».
            LogError("браузер не запустился", ex, persist: !_closed);
            if (!_closed)
            {
                ShowProblem($"Встроенный браузер не запустился (код 0x{ex.HResult:X8}). Закройте окно и нажмите «Войти» ещё раз;"
                    + " если не поможет, перезапустите компьютер или переустановите Microsoft Edge WebView2 Runtime.");
            }

            return;
        }

        try
        {
            var core = Browser.CoreWebView2;
            Guard(core, () => _closed);
            core.ProcessFailed += (_, e) =>
            {
                Verbose.Write("SignIn", $"процесс браузера упал: {e.ProcessFailedKind}, {e.Reason}, код {e.ExitCode}");
                if (e.ProcessFailedKind == CoreWebView2ProcessFailedKind.RenderProcessExited)
                {
                    // Страница погибла, браузер жив: достаточно перезагрузить её.
                    ShowProblem("Страница входа аварийно завершилась и загружается заново. Если вход не откроется, закройте окно и повторите.");
                    try
                    {
                        core.Reload();
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        LogError("перезагрузка страницы после сбоя", ex);
                    }
                }
                else
                {
                    // Браузер больше не работает или завис: без объяснения остаётся мёртвое окно.
                    ShowProblem("Встроенный браузер прекратил работу. Закройте окно и нажмите «Войти» ещё раз.");
                }
            };
            core.NavigationStarting += (_, e) =>
            {
                Verbose.Write("SignIn", "переход: " + LogText.UrlForLog(e.Uri));
                _navigation = e.NavigationId;
                _frameNotice = null;
                if (!SignInBrowserPolicy.MainNavigationAllowed(e.Uri))
                {
                    e.Cancel = true;
                    _cancelledNavigation = e.NavigationId;
                    ShowProblem("Переход на страницу без HTTPS отменён: вход возможен только по защищённому соединению.");
                }
            };
            core.NewWindowRequested += OpenPopupAsync;
            core.NavigationCompleted += async (_, e) =>
            {
                Verbose.Write("SignIn", $"страница загружена: {LogText.UrlForLog(core.Source)} — {(e.IsSuccess ? "ok" : e.WebErrorStatus.ToString())}, HTTP {e.HttpStatusCode}");
                if (!e.IsSuccess)
                {
                    if (_cancelledNavigation == e.NavigationId)
                    {
                        // Переход отменило само окно и уже объяснило почему: общий текст «не открылась» причину бы затёр.
                        _cancelledNavigation = null;
                        return;
                    }

                    if (SignInBrowserPolicy.IsCertificateError(e.WebErrorStatus.ToString()))
                    {
                        // Тот же текст, что у ServerCertificateErrorDetected: какое из событий придёт позже, неважно.
                        ShowProblem(SignInBrowserPolicy.CertificateProblem(core.Source));
                        return;
                    }

                    if (_retry.NextAttempt(e.WebErrorStatus.ToString()) is { } attempt)
                    {
                        await RetryLoadAsync(core, e.WebErrorStatus, attempt, e.NavigationId);
                        return;
                    }

                    ShowProblem($"Страница входа не открылась: {UiText.WebError(e.WebErrorStatus)}. Проверьте в «Проверить адрес», доступен ли сайт организации.");
                    return;
                }

                _retry.Succeeded();

                HideProblem();

                // Токен — только у открытого окна: OnClosed освобождает источник, и обращение к нему бросило бы
                // ObjectDisposedException из обработчика события.
                if (_closed) { return; }
                await ReportNavigationAsync(core, () => _closed, _lifetime.Token);
            };
            core.Navigate(_prompt.Uri);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogError("открытие страницы входа", ex, persist: !_closed);
            if (!_closed)
            {
                ShowProblem("Страница входа не открылась: встроенный браузер не справился с ней. Закройте окно и нажмите «Войти» ещё раз.");
            }
        }
    }

    /// <summary>
    /// Защита браузера окна входа — основного и каждого всплывающего (<see cref="SignInBrowserPolicy"/>): ошибка
    /// сертификата отменяет запрос без страницы-предупреждения с «Продолжить», загрузки отменяются, запросы
    /// разрешений (камера, микрофон, место, уведомления, буфер обмена) отклоняются, фрейм без HTTPS не открывается.
    /// </summary>
    /// <param name="closed">Окно этого браузера закрыто: событие опоздало, сообщать не о чем.</param>
    private void Guard(CoreWebView2 core, Func<bool> closed)
    {
        core.Settings.AreDevToolsEnabled = false;
        core.Settings.IsPasswordAutosaveEnabled = false;
        string? mainDocument = null;
        string? frameDocument = null;
        var frameReported = false;
        core.NavigationStarting += (_, e) =>
        {
            mainDocument = e.Uri;
            frameReported = false;
        };
        core.FrameNavigationStarting += (_, e) =>
        {
            frameDocument = e.Uri;
            if (!SignInBrowserPolicy.FrameNavigationAllowed(e.Uri))
            {
                // Неоткрытый фрейм может быть и формой входа: молча осталось бы пустое место. Панель — один раз на
                // загрузку страницы, сколько бы фреймов ни было отменено.
                e.Cancel = true;
                Verbose.Write("SignIn", "фрейм без HTTPS не открыт: " + LogText.UrlForLog(e.Uri));
                if (!frameReported && !closed())
                {
                    frameReported = true;
                    _frameNotice = SignInBrowserPolicy.FrameBlockedProblem;
                    ShowProblem(SignInBrowserPolicy.FrameBlockedProblem);
                }
            }
        };
        core.PermissionRequested += (_, e) =>
        {
            e.State = CoreWebView2PermissionState.Deny;
            Verbose.Write("SignIn", $"запрос разрешения отклонён: {e.PermissionKind}");
        };

        // ServerCertificateErrorDetected — ICoreWebView2_14 (среда выполнения 106 и новее), DownloadStarting —
        // ICoreWebView2_4: на более старой среде подписка бросает NotImplementedException, окно входа работает дальше.
        Subscribe("ошибки сертификата", () => core.ServerCertificateErrorDetected += (_, e) =>
        {
            // Отмена, а не «по умолчанию»: страница-предупреждение WebView2 позволяет нажать «Продолжить», и пароль ушёл бы
            // на подменённый сайт, а cookie — службе.
            e.Action = CoreWebView2ServerCertificateErrorAction.Cancel;
            Verbose.Write("SignIn", $"ошибка сертификата {e.ErrorStatus}: запрос отменён — {LogText.UrlForLog(e.RequestUri)}");
            if (!closed() && SignInBrowserPolicy.IsDocumentRequest(e.RequestUri, mainDocument, frameDocument))
            {
                ShowProblem(SignInBrowserPolicy.CertificateProblem(e.RequestUri));
            }
        });
        Subscribe("загрузки", () => core.DownloadStarting += (_, e) =>
        {
            e.Cancel = true;
            e.Handled = true;
            Verbose.Write("SignIn", "загрузка файла отменена: " + LogText.UrlForLog(e.DownloadOperation.Uri));
            if (!closed())
            {
                ShowProblem("Страница входа начала загрузку файла — она отменена: окно входа файлы не скачивает.");
            }
        });
    }

    private static void Subscribe(string what, Action subscribe)
    {
        try
        {
            subscribe();
        }
        catch (Exception ex) when (ex is NotImplementedException or InvalidCastException)
        {
            // Устаревшая среда выполнения WebView2 обычно обновляется сама; запись нужна, чтобы разобрать обращение.
            LogError("среда выполнения WebView2 не перехватывает " + what, ex, persist: true);
        }
    }

    /// <summary>
    /// Сетевая ошибка загрузки: страница организации открывается через опорный VPN, а он может ещё подниматься. Окно
    /// повторяет загрузку само, не заставляя закрывать его и входить заново (<see cref="SignInRetryPolicy"/>).
    /// </summary>
    private async Task RetryLoadAsync(CoreWebView2 core, CoreWebView2WebErrorStatus status, int attempt, ulong failedNavigation)
    {

        ShowProblem($"Страница входа пока не открывается ({UiText.WebError(status)}): обычно это значит, что VPN ещё подключается."
            + $" Повтор через {SignInRetryPolicy.Delay.TotalSeconds:F0} с (попытка {attempt} из {SignInRetryPolicy.MaxAttempts}).");
        await Task.Delay(SignInRetryPolicy.Delay);
        if (_closed)
        {
            return;
        }

        if (_navigation != failedNavigation)
        {
            // За время паузы начался другой переход (страница перешла дальше сама или по действию пользователя):
            // перезагрузка сбросила бы уже открытую страницу входа вместе с введёнными данными.
            Verbose.Write("SignIn", $"повтор загрузки {attempt} отменён: начат другой переход");
            return;
        }

        try
        {
            Verbose.Write("SignIn", $"повтор загрузки {attempt} из {SignInRetryPolicy.MaxAttempts}");
            core.Reload();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Окно закрывается или браузер уже не работает: повтор не нужен, причину покажет панель.
            LogError("повтор загрузки", ex);
            ShowProblem("Страница входа не открылась. Закройте окно и нажмите «Войти» ещё раз.");
        }
    }

    private async void OpenPopupAsync(object? sender, CoreWebView2NewWindowRequestedEventArgs e)
    {
        using var deferral = e.GetDeferral();
        e.Handled = true;
        if (_closed || !SignInBrowserPolicy.PopupNavigationAllowed(e.Uri)) { return; }

        var browser = new Microsoft.Web.WebView2.Wpf.WebView2();
        var popup = new System.Windows.Window { Owner = this, Title = Title, Content = browser, Width = 800, Height = 640 };
        // Своё время жизни у всплывающего окна: OAuth закрывает его сам (window.close()) сразу после адреса возврата,
        // и передача его результата, прерванная закрытием, — не сбой входа.
        var popupLifetime = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        var popupToken = popupLifetime.Token;
        var popupClosed = false;
        bool Closed() => popupClosed || _closed;
        popup.Closed += (_, _) =>
        {
            popupClosed = true;
            popupLifetime.Cancel();
            popupLifetime.Dispose();
            browser.Dispose();
        };
        try
        {
            popup.Show();
            await browser.EnsureCoreWebView2Async(Browser.CoreWebView2.Environment);
            if (Closed()) { return; }
            var child = browser.CoreWebView2;
            Guard(child, Closed);
            child.NavigationStarting += (_, args) => args.Cancel = !SignInBrowserPolicy.PopupNavigationAllowed(args.Uri);
            child.NavigationCompleted += async (_, args) =>
            {
                if (args.IsSuccess && !Closed()) { await ReportNavigationAsync(child, Closed, popupToken); }
            };
            child.NewWindowRequested += OpenPopupAsync;
            child.WindowCloseRequested += (_, _) => popup.Close();
            e.NewWindow = child;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var closed = Closed();
            if (popup.IsVisible) { popup.Close(); }
            LogError("дополнительное окно входа", ex, persist: !closed);
            if (!closed)
            {
                ShowProblem($"Дополнительное окно входа не открылось (код 0x{ex.HResult:X8}). Закройте окно и нажмите «Войти» ещё раз.");
            }
        }
    }

    /// <param name="closed">Закрыто окно этого браузера (для всплывающего — оно само или основное).</param>
    /// <param name="token">Время жизни этого окна: взято до закрытия, источник после него освобождён.</param>
    private async Task ReportNavigationAsync(CoreWebView2 core, Func<bool> closed, CancellationToken token)
    {
        if (closed()) { return; }
        try
        {
            var uri = core.Source;
            List<SsoCookie> cookies = [];
            if (Uri.TryCreate(uri, UriKind.Absolute, out var page) && string.Equals(page.Host, _prompt.GatewayHost, StringComparison.OrdinalIgnoreCase))
            {
                cookies = (await core.CookieManager.GetCookiesAsync(uri)).Select(c => new SsoCookie(c.Name, c.Value)).ToList();
                // Окно закрыли, пока браузер отдавал cookie: передавать нечего, браузер уже освобождён.
                if (closed()) { return; }
            }

            Verbose.Write("SignIn", $"службе передан адрес {LogText.UrlForLog(uri)} и cookie шлюза: {cookies.Count} шт.");
            var request = new SsoNavigationRequest(_profileId, RequestId, uri, cookies);
            while (!token.IsCancellationRequested && core.Source == uri)
            {
                try
                {
                    var response = await _service.SendAsync(request, token);
                    if (!response.Ok) { ShowProblem(UiText.ServiceRejected(response, "Служба отклонила результат входа.")); }
                    else { HideProblem(); }
                    break;
                }
                catch (ServiceUnavailableException ex) when (ex.Reason is ServiceUnavailableReason.Timeout or ServiceUnavailableReason.NotRunning)
                {
                    ShowProblem(ex.Message + " Передача результата будет повторена.");
                    await Task.Delay(TimeSpan.FromSeconds(3), token);
                }
            }
        }
        catch (OperationCanceledException) when (closed()) { }
        catch (ServiceUnavailableException ex)
        {
            ShowProblem(ex.Message);
        }
        catch (ServiceCommandException ex)
        {
            // Запрос не ушёл (например, слишком большой): текст уже русский и объясняет причину.
            ShowProblem(ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Ошибка браузера (окно уже закрывается, cookie недоступны): вход можно повторить кнопкой «Войти».
            // Окно уже закрыто (браузер освобождён посреди передачи — у всплывающего OAuth это обычный конец) — это не
            // сбой входа: в постоянный журнал не пишется, панель не показывается.
            var wasClosed = closed();
            LogError("передача результата входа", ex, persist: !wasClosed);
            if (!wasClosed)
            {
                ShowProblem($"Результат входа не передан службе (код 0x{ex.HResult:X8}). Закройте окно и нажмите «Войти» ещё раз.");
            }
        }
    }

    /// <summary>
    /// Сообщение WebView2 и COM английское и техническое: оно — только в журнал, пользователю — фраза по смыслу места.
    /// persist — ещё и в постоянный журнал ошибок интерфейса: подробный журнал обычно выключен, а пустое окно входа
    /// без записи не разобрать.
    /// </summary>
    private static void LogError(string where, Exception ex, bool persist = false)
    {
        Verbose.Write("SignIn", $"{where}: {ex.GetType().Name} 0x{ex.HResult:X8} «{ex.Message}»");
        if (persist)
        {
            App.RecordHandled(new InvalidOperationException("Окно входа: " + where, ex));
        }
    }

    /// <summary>Убирает панель после успеха; объяснение о неоткрытом фрейме этой загрузки остаётся.</summary>
    private void HideProblem()
    {
        if (_frameNotice is { } notice)
        {
            Problem.Message = notice;
            Problem.IsOpen = true;
            return;
        }

        Problem.IsOpen = false;
    }

    private void ShowProblem(string text)
    {
        if (_closed) { return; }
        Verbose.Write("SignIn", "в окне входа: " + text);
        Problem.Message = text;
        Problem.IsOpen = true;
        // LiveSetting один не объявляет смену текста: событие поднимает LiveRegion.
        LiveRegion.SetValue(Problem, text);
    }

    private async Task SendQuietlyAsync(IpcRequest request)
    {
        try
        {
            await _service.SendAsync(request);
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
        {
            // Служба недоступна: помощник сам завершит вход по таймауту.
        }
    }
}
