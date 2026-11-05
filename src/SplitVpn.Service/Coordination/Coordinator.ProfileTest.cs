using System.Globalization;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    private static readonly TimeSpan ProfileTestDialTimeout = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Проверка профиля: (а) этот профиль подключён — отчёт по сеансу; (б) VPN и защита сняты — пробный
    /// дозвон и классификация ошибки; (в) иначе — просьба отключить VPN. Пробный дозвон идёт вне очереди
    /// актора и не мешает опросу состояния.
    /// </summary>
    internal Task<IpcResponse> BeginProfileTest(Guid profileId)
    {
        var profile = _settings.Profile(profileId);
        if (profile is null)
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.NotFound, "Подключение не найдено."));
        }

        if (Facts.Tunnels.GetValueOrDefault(profileId) is { IsUp: true } connected)
        {
            return Task.FromResult(IpcResponse.Success(SessionReport(connected)));
        }

        if (profile.Protocol == VpnProtocol.AnyConnect)
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.InvalidSettings,
                "Пробного подключения AnyConnect нет: вход идёт во встроенном браузере — нажмите «Подключить»."));
        }

        var busy = _state.Intent != Intent.Off
            || Facts.Tunnels.Values.Any(t => t.HasSession || t.Dialing)
            || Facts.ProfileTestRunning;
        if (busy)
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Busy,
                "Для пробного подключения отключите VPN и снимите защиту («Отключить и восстановить обычный интернет»)."));
        }

        var password = LoadPassword(profile);
        if (password is null)
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Сначала сохраните пароль этого подключения."));
        }

        // Запись RAS готовится под проверяемый профиль; обычный дозвон потом перепишет её заново.
        var entryName = EntryNameFor(profile);
        var tunnel = Facts.Tunnels.GetValueOrDefault(profileId) ?? new TunnelFacts(profile.Id, entryName) { Name = profile.Name };
        try
        {
            PrepareEntry(tunnel, profile);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Windows.Native.NativeCallException)
        {
            Array.Clear(password);
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.InvalidSettings, ex.Message));
        }

        Facts.ProfileTestRunning = true;
        Journal("Сведения", $"Пробное подключение «{profile.Name}».");
        return Task.Run(() => RunProfileTestAsync(entryName, profile.Name, profile.UserName, profile.Domain, password));
    }

    private async Task<IpcResponse> RunProfileTestAsync(string entryName, string name, string userName, string? domain, char[] password)
    {
        var started = _deps.Time.GetUtcNow();
        try
        {
            using var timeout = new CancellationTokenSource(ProfileTestDialTimeout);
            var result = await _deps.Ras.DialAsync(entryName, userName, password, domain, timeout.Token);
            if (!result.Success || result.Handle is not { } handle)
            {
                var info = RasErrorClassifier.Classify((int)result.ErrorCode);
                return IpcResponse.Success(new ProfileTestDto(false,
                    $"«{name}»: {RasErrorClassifier.CategoryText(info.Category)}. {result.ErrorText} (код {result.ErrorCode})."));
            }

            var elapsed = _deps.Time.GetUtcNow() - started;
            RasProjection projection;
            try { projection = _deps.Ras.GetProjection(handle); }
            finally { await _deps.Ras.HangUpAsync(handle, CancellationToken.None); }
            return IpcResponse.Success(new ProfileTestDto(true, string.Create(CultureInfo.InvariantCulture,
                $"«{name}»: подключение успешно за {elapsed.TotalSeconds:0.0} с, адрес в VPN {Ipv4.Format(projection.ClientAddress)}. Пробное соединение разорвано.")));
        }
        catch (OperationCanceledException)
        {
            return IpcResponse.Success(new ProfileTestDto(false, $"«{name}»: сервер не ответил за {ProfileTestDialTimeout.TotalSeconds:0} с."));
        }
        finally
        {
            Array.Clear(password);
            try
            {
                _deps.Ras.DeleteEntry(entryName);
            }
            finally
            {
                Facts.ProfileTestRunning = false;
            }
        }
    }

    private ProfileTestDto SessionReport(TunnelFacts tunnel)
    {
        var address = tunnel.Adapter is { Addresses.Count: > 0 } adapter ? Ipv4.Format(adapter.Addresses[0]) : "—";
        var duration = tunnel.SessionStartedUtc is { } start ? _deps.Time.GetUtcNow() - start : TimeSpan.Zero;
        var stats = tunnel.Statistics;
        return new ProfileTestDto(tunnel.Verified, string.Create(CultureInfo.InvariantCulture,
            $"«{tunnel.Name}» подключено: адрес в VPN {address}, сервер {string.Join(", ", tunnel.ServerAddresses.Select(Ipv4.Format))}, сеанс {duration:hh\\:mm\\:ss}, " +
            $"отправлено {stats?.BytesSent ?? 0} Б, получено {stats?.BytesReceived ?? 0} Б. Проверка маршрутов: {(tunnel.Verified ? "пройдена" : "не пройдена")}."));
    }
}
