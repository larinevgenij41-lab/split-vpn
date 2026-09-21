using System.Windows;
using SplitVpn.App.Views;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;

namespace SplitVpn.App.Services;

/// <summary>
/// Вход в туннели AnyConnect по состоянию службы: окно браузера или формы открывается, когда служба его ждёт,
/// и закрывается, когда перестаёт ждать. Если туннель ждёт входа, а VPN включён, вход начинается сам — один раз
/// до следующего подключения: закрытое пользователем окно не открывается снова до кнопки «Войти».
/// </summary>
public sealed class SignInCoordinator(ServiceConnection service)
{
    private readonly Dictionary<Guid, Window> _windows = [];
    private readonly HashSet<Guid> _autoStarted = [];

    /// <summary>Запросы входа, окна которых уже показывались: закрытое или отправленное окно опрос не открывает снова.</summary>
    private readonly Dictionary<Guid, HashSet<Guid>> _shown = [];

    public void OnStatus(StatusDto? status)
    {
        if (status is null)
        {
            return;
        }

        var connectedIntent = status is { Intent: Intent.Connected, ProtectionSuspended: false };
        foreach (var tunnel in status.Tunnels)
        {
            SyncTunnel(tunnel, connectedIntent);
        }

        foreach (var gone in _windows.Keys.Where(id => status.Tunnels.All(t => t.ProfileId != id)).ToList())
        {
            CloseWindow(gone);
        }

        foreach (var gone in _shown.Keys.Where(id => status.Tunnels.All(t => t.ProfileId != id)).ToList())
        {
            _shown.Remove(gone);
        }
    }

    private void SyncTunnel(TunnelStatusDto tunnel, bool connectedIntent)
    {
        var prompt = tunnel.SignIn;
        if (_windows.TryGetValue(tunnel.ProfileId, out var open)
            && (prompt is null || prompt.Kind == SignInKind.Required || ((ISignInWindow)open).RequestId != prompt.RequestId))
        {
            CloseWindow(tunnel.ProfileId);
        }

        if (tunnel.State == ConnectionState.Connected)
        {
            _autoStarted.Remove(tunnel.ProfileId);
            _shown.Remove(tunnel.ProfileId);
        }

        if (prompt is null)
        {
            return;
        }

        if (prompt.Kind == SignInKind.Required)
        {
            if (connectedIntent && _autoStarted.Add(tunnel.ProfileId))
            {
                _ = BeginQuietlyAsync(tunnel.ProfileId);
            }

            return;
        }

        if (_windows.ContainsKey(tunnel.ProfileId))
        {
            return;
        }

        if (!_shown.TryGetValue(tunnel.ProfileId, out var shown))
        {
            _shown[tunnel.ProfileId] = shown = [];
        }

        if (!shown.Add(prompt.RequestId))
        {
            // Окно этого запроса уже было: пользователь его закрыл или отправил форму. Служба ещё не успела
            // убрать запрос из статуса — второй раз окно не открываем, вход начинается кнопкой «Войти».
            return;
        }

        Window window = prompt.Kind == SignInKind.Browser
            ? new SignInWindow(service, tunnel.ProfileId, tunnel.Name, prompt)
            : new SignInFormWindow(service, tunnel.ProfileId, tunnel.Name, prompt);
        var profileId = tunnel.ProfileId;
        window.Closed += (_, _) =>
        {
            if (_windows.GetValueOrDefault(profileId) == window)
            {
                _windows.Remove(profileId);
            }
        };
        _windows[profileId] = window;
        window.Show();
        window.Activate();
    }

    private void CloseWindow(Guid profileId)
    {
        if (_windows.Remove(profileId, out var window))
        {
            ((ISignInWindow)window).CloseByService();
        }
    }

    private async Task BeginQuietlyAsync(Guid profileId)
    {
        try
        {
            await service.SendAsync(new BeginSignInRequest(profileId));
        }
        catch (ServiceUnavailableException)
        {
            // Служба недоступна: кнопка «Войти» на главной остаётся.
        }
    }
}
