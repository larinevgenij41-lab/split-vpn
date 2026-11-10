using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    internal async Task<IpcResponse> HandleRequestAsync(IpcRequest request, CancellationToken cancellationToken) => request switch
    {
        _ when request.ContractVersion != IpcNames.ContractVersion => IpcResponse.Failure(IpcErrorCodes.BadRequest, "Версия приложения несовместима со службой. Обновите оба компонента."),
        GetStatusRequest => IpcResponse.Success(BuildStatus()),
        GetEventsRequest events => IpcResponse.Success(_deps.Journal.Since(events.SinceId)),
        GetAdaptersRequest => IpcResponse.Success(Adapters()),
        GetSettingsRequest => IpcResponse.Success(_settings),
        SaveSettingsRequest save => await SaveSettingsAsync(save.Settings, cancellationToken),
        SaveConnectionRequest save => await SaveConnectionAsync(save, cancellationToken),
        SetPasswordRequest password => SetPassword(password.ProfileId, password.Password),
        SetPreSharedKeyRequest key => await SetPreSharedKeyAsync(key, cancellationToken),
        ConnectRequest connect => await ConnectAsync(connect, cancellationToken),
        DisconnectRequest disconnect => await ChangeIntentAsync(disconnect.KeepProtection ? Intent.Protected : Intent.Off, cancellationToken),
        SetProfileRoleRequest role => await SetProfileRoleAsync(role.ProfileId, role.Role, cancellationToken),
        SetTunnelPausedRequest paused => await SetTunnelPausedAsync(paused.ProfileId, paused.Paused, cancellationToken),
        SetProfileOrderRequest order => await SetProfileOrderAsync(order.Order, cancellationToken),
        RecoverNetworkRequest => await ChangeIntentAsync(Intent.Off, cancellationToken),
        CheckAddressRequest check => IpcResponse.Success(await CheckAddressAsync(check.Query, cancellationToken)),
        GeoUpdateNowRequest list => await List(list).BeginUpdateNowAsync(this, cancellationToken),
        GeoImportRequest import => await List(import).ImportAsync(this, import.Content, cancellationToken),
        GeoRollbackRequest list => await List(list).RollbackAsync(this, cancellationToken),
        GeoAcceptPendingRequest list => await List(list).AcceptPendingAsync(this, cancellationToken),
        GeoRejectPendingRequest list => List(list).RejectPending(),
        GeoClearSkippedRequest list => List(list).ClearSkipped(),
        CheckUpdateRequest => await _update.BeginCheckAsync(this, cancellationToken),
        DownloadUpdateRequest download => await _update.BeginDownloadAsync(this, download.Version, cancellationToken),
        InstallUpdateRequest install => await _update.BeginInstallAsync(this, install.Version, cancellationToken),
        UpdateStartedRequest started => _update.InstallStarted(this, started.ProcessId),
        SkipUpdateRequest skip => _update.SkipVersion(this, skip.Version),
        ExportReportRequest report => IpcResponse.Success(ExportReport(report.MaskPersonalData)),
        SetVerboseLoggingRequest verbose => SetVerboseLogging(verbose.Minutes),
        CollectDiagnosticsRequest => CollectDiagnostics(cancellationToken),
        ReadDiagnosticsChunkRequest chunk => ReadDiagnosticsChunk(chunk),
        TestProfileRequest test => await BeginProfileTest(test.ProfileId),
        BeginSignInRequest begin => await BeginSignInAsync(begin.ProfileId, cancellationToken),
        CancelSignInRequest cancel => CancelSignIn(cancel),
        SsoNavigationRequest navigation => ForwardSsoNavigation(navigation),
        SubmitAuthFormRequest form => SubmitAuthForm(form),
        _ => IpcResponse.Failure(IpcErrorCodes.BadRequest, "Неизвестная команда."),
    };

    private const uint SoftwareLoopbackIfType = 24;

    private List<AdapterDto> Adapters()
    {
        var tunnelLuids = TunnelLuids();
        return (_snapshot?.Adapters ?? []).Where(a => a.IsUp && a.Addresses.Count > 0 && a.IfType != SoftwareLoopbackIfType && !tunnelLuids.Contains(a.Luid))
            .Select(a => new AdapterDto(a.InterfaceGuid, a.Name, a.Description, a.TypeName, a.IsUp, a.IsHardware,
                a.DefaultGateway is { } g ? Ipv4.Format(g) : null, a.Luid == Facts.Primary?.Luid, a.IsOverlay, IsTrusted(a)))
            .ToList();
    }

    private async Task<IpcResponse> SaveSettingsAsync(AppSettings settings, CancellationToken cancellationToken, bool reconcile = true)
    {
        if (Facts.Tunnels.Values.Any(t => t.Dialing) || Facts.ProfileTestRunning)
        {
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Дождитесь завершения дозвона перед изменением настроек.");
        }

        // Проверяется и сохраняется одна и та же нормализованная модель: «null» из канала управления не попадает в файл.
        settings = SettingsSerializer.Normalize(settings);
        var validation = SettingsValidator.Validate(settings);
        if (!validation.IsValid)
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, string.Join(Environment.NewLine, validation.Errors));
        }

        var connected =Facts.Tunnels.Values.Where(t => t.IsUp).ToList();
        if (connected.Find(t => settings.Profiles.All(p => p.Id != t.ProfileId)) is { } removed)
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, $"Нельзя удалить подключение «{removed.Name}»: оно сейчас активно.");
        }

        var previous = _settings;

        // Секреты удаляются до записи файла, а их копии держатся до её успеха: сбой удаления или записи
        // возвращает удалённое, и прежние настройки остаются и в файле, и в памяти вместе со своими паролями.
        // Пароль, привязанный к прежнему серверу, к новому не переходит: настройки с новым сервером
        // появляются только после того, как пароль удалён.
        var outdated = OutdatedSecrets(previous, settings);
        var backups = new List<SecretBackup>();
        try
        {
            try
            {
                DeleteSecrets(outdated.Secrets, backups);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                RestoreSecrets(backups);
                Journal("Ошибка", "Настройки не сохранены: не удалось удалить сохранённый пароль или ключ IPsec — " + ex.Message);
                return IpcResponse.Failure(IpcErrorCodes.Failed, "Настройки не сохранены: не удалось удалить сохранённый пароль или ключ IPsec. " + ex.Message);
            }

            try
            {
                _deps.Stores.SaveSettings(settings);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                RestoreSecrets(backups);
                Journal("Ошибка", "Настройки не сохранены: не удалось записать файл настроек - " + ex.Message);
                return IpcResponse.Failure(IpcErrorCodes.Failed, "Настройки не сохранены: не удалось записать файл настроек (диск заполнен, файл занят или нет доступа). " + ex.Message);
            }
        }
        finally
        {
            foreach (var secret in backups)
            {
                Array.Clear(secret.Value);
            }
        }

        _settings = settings;
        foreach (var profileId in outdated.MemoryPasswords)
        {
            ForgetMemoryPassword(profileId);
        }

        foreach (var note in outdated.Notes)
        {
            Journal("Сведения", note);
        }

        RememberPersonalValues(previous);
        Journal("Сведения", "Настройки сохранены.");
        if (reconcile)
        {
            await ReconnectChangedEndpointsAsync(previous, cancellationToken);
            await ReconcileAsync(cancellationToken);
        }

        return IpcResponse.Success(validation.Warnings);
    }

    /// <summary>Секрет, который нужно удалить при сохранении настроек: профиль, вид и название для журнала.</summary>
    private readonly record struct OutdatedSecret(Guid ProfileId, SecretKind Kind, string ProfileName);

    /// <summary>Копия секрета для восстановления при сбое удаления или записи настроек.</summary>
    private readonly record struct SecretBackup(Guid ProfileId, SecretKind Kind, string ProfileName, char[] Value);

    /// <summary>
    /// Секреты, которые не переходят к новым настройкам: ключ IPsec и пароль после смены сервера, протокола,
    /// способа входа или учётной записи; пароль удалённого профиля или профиля, где его больше не сохраняют.
    /// Только вычисляет: удаление, забывание паролей в памяти и записи журнала идут при сохранении.
    /// </summary>
    private (List<OutdatedSecret> Secrets, List<Guid> MemoryPasswords, List<string> Notes) OutdatedSecrets(AppSettings previous, AppSettings settings)
    {
        var secrets = new List<OutdatedSecret>();
        var memory = new List<Guid>();
        var notes = new List<string>();
        foreach (var old in previous.Profiles)
        {
            var next = settings.Profiles.FirstOrDefault(p => p.Id == old.Id);
            if (next is null || !VpnProtocols.NeedsPreSharedKey(next) || ConnectionEdits.PreSharedKeyBindingChanged(old, next))
            {
                if (next is not null && VpnProtocols.NeedsPreSharedKey(next) && _deps.Secrets.Contains(old.Id, SecretKind.PreSharedKey))
                {
                    notes.Add($"Ключ IPsec «{old.Name}» удалён: изменились сервер или протокол — введите ключ заново.");
                }

                secrets.Add(new OutdatedSecret(old.Id, SecretKind.PreSharedKey, old.Name));
            }

            // Пароль не переходит к другому серверу, протоколу, способу входа или учётной записи.
            var bindingChanged = next is null || ConnectionEdits.PasswordBindingChanged(old, next) || !VpnProtocols.NeedsPassword(next.AuthMethod);
            var stillNeeded = next is not null && VpnProtocols.NeedsPassword(next.AuthMethod);
            var noLongerSaved = next is not { SavePassword: true };
            var passwordSaved = (noLongerSaved || (bindingChanged && stillNeeded)) && _deps.Secrets.Contains(old.Id);
            if (bindingChanged)
            {
                if (stillNeeded && passwordSaved)
                {
                    notes.Add($"Сохранённый пароль «{old.Name}» удалён: изменились сервер, протокол, способ входа или учётная запись — введите пароль заново.");
                }

                memory.Add(old.Id);
            }

            if (noLongerSaved && passwordSaved)
            {
                notes.Add($"Сохранённый пароль «{old.Name}» удалён: профиль удалён или пароль больше не сохраняется.");
            }

            if (bindingChanged || (noLongerSaved && passwordSaved))
            {
                secrets.Add(new OutdatedSecret(old.Id, SecretKind.Password, old.Name));
            }
        }

        return (secrets, memory, notes);
    }

    /// <summary>
    /// Удаляет секреты, оставляя копии в <paramref name="backups"/>. Секрет, который не прочитать (его нет или
    /// он не расшифровывается), удаляется без копии: возвращать нечего.
    /// </summary>
    private void DeleteSecrets(List<OutdatedSecret> secrets, List<SecretBackup> backups)
    {
        foreach (var secret in secrets)
        {
            var value = _deps.Secrets.TryLoad(secret.ProfileId, secret.Kind);
            if (value is not null)
            {
                // Удаление может завершиться ошибкой уже после записи основного файла.
                backups.Add(new SecretBackup(secret.ProfileId, secret.Kind, secret.ProfileName, value));
            }

            _deps.Secrets.Delete(secret.ProfileId, secret.Kind);
        }
    }

    /// <summary>
    /// Возвращает удалённые секреты: настройки не сохранены, и профиль остался прежним вместе со своим сервером.
    /// Что вернуть не удалось, попадает в журнал - пароль или ключ придётся ввести заново.
    /// </summary>
    private void RestoreSecrets(List<SecretBackup> backups)
    {
        foreach (var secret in backups)
        {
            try
            {
                _deps.Secrets.Save(secret.ProfileId, secret.Value, secret.Kind);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                var what = secret.Kind == SecretKind.PreSharedKey ? "ключ IPsec" : "сохранённый пароль";
                Journal("Ошибка", $"Не удалось вернуть {what} «{secret.ProfileName}» после сбоя сохранения настроек - введите его заново: {ex.Message}");
            }
        }
    }

    /// <summary>Сохраняет профиль и его секреты одним действием актора, до запуска дозвона.</summary>
    private async Task<IpcResponse> SaveConnectionAsync(SaveConnectionRequest request, CancellationToken cancellationToken)
    {
        var profile = request.Settings.Profiles.FirstOrDefault(p => p.Id == request.ProfileId);
        if (profile is null || request.Password is { Length: > 256 } || request.PreSharedKey is { Length: > 256 }
            || request.Password?.Contains('\0') == true || request.PreSharedKey?.Contains('\0') == true
            || (request.Password is not null && !VpnProtocols.NeedsPassword(profile.AuthMethod))
            || (request.PreSharedKey is not null && !VpnProtocols.NeedsPreSharedKey(profile)))
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Недопустимые параметры входа или ключа IPsec.");
        }

        var previous = _settings;
        var result = await SaveSettingsAsync(request.Settings, cancellationToken, reconcile: false);
        if (!result.Ok)
        {
            return result;
        }

        // Настройки уже записаны: сбой записи секрета не должен отменять переподключение туннелей, у которых
        // сменился сервер, иначе туннель остался бы на старом сервере (следующее сохранение разницы уже не увидит).
        // Ошибка секрета возвращается в конце, чтобы интерфейс показал, что вход не сохранён.
        IpcResponse? secretFailure = null;
        if (request.Password is { } password && SetPassword(profile.Id, password) is { Ok: false } refused)
        {
            secretFailure = refused;
        }

        if (request.PreSharedKey is { } key)
        {
            try
            {
                if (key.Length == 0)
                {
                    _deps.Secrets.Delete(profile.Id, SecretKind.PreSharedKey);
                }
                else
                {
                    _deps.Secrets.Save(profile.Id, key, SecretKind.PreSharedKey);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
            {
                _deps.Logger.LogWarning(ex, "Ключ IPsec для {Name} не сохранён", profile.Name);
                secretFailure ??= IpcResponse.Failure(IpcErrorCodes.Failed, $"Не удалось сохранить ключ IPsec для «{profile.Name}»: {ex.Message}");
            }
        }

        // Новые данные входа применяются только после переподключения этого туннеля.
        if (secretFailure is null && (request.PreSharedKey is not null || request.Password is not null)
            && Facts.Tunnels.GetValueOrDefault(profile.Id) is { } tunnel)
        {
            if (tunnel.HasSession)
            {
                tunnel.ReconnectRequired = true;
                await HangUpAsync(tunnel, "изменены данные входа", cancellationToken);
                tunnel.ReconnectRequired = false;
            }

            tunnel.BlockingError = ErrorCategory.None;
            tunnel.NextDialAt = _deps.Time.GetUtcNow();
            RetryFromScratch(tunnel);
        }

        await ReconnectChangedEndpointsAsync(previous, cancellationToken);
        await ReconcileAsync(cancellationToken);
        return secretFailure ?? result;
    }

    /// <summary>Переподключает туннели, у которых изменились адрес сервера или учётные данные.</summary>
    private async Task ReconnectChangedEndpointsAsync(AppSettings previous, CancellationToken cancellationToken)
    {
        ForgetChangedServers(previous);
        var changed = Facts.Tunnels.Values.Where(tunnel =>
        {
            var before = previous.Profile(tunnel.ProfileId);
            var after = _settings.Profile(tunnel.ProfileId);
            return before is null || after is null || VpnProtocols.ConnectionKey(before) != VpnProtocols.ConnectionKey(after);
        }).ToList();

        // Сначала отмечаются все: сбой разрыва одного не должен оставить другой на прежних параметрах.
        // Флаг ReconnectRequired остаётся у того, чей разрыв не удался, и сверка повторит разрыв.
        foreach (var tunnel in changed)
        {
            tunnel.BlockingError = ErrorCategory.None;
            tunnel.ServerAddresses = [];
            RetryFromScratch(tunnel);
            tunnel.ReconnectRequired |= tunnel.HasSession;
        }

        ExceptionDispatchInfo? failure = null;
        foreach (var tunnel in changed.Where(t => t.HasSession))
        {
            try
            {
                await HangUpAsync(tunnel, "изменены параметры подключения", cancellationToken);
                tunnel.ReconnectRequired = false;
                tunnel.NextDialAt = _deps.Time.GetUtcNow();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _deps.Logger.LogWarning(ex, "Изменены параметры подключения {Name}: соединение не разорвано, повтор при сверке", tunnel.Name);
                failure ??= ExceptionDispatchInfo.Capture(ex);
            }
        }

        failure?.Throw();
    }

    /// <summary>Кеш привязан к прежнему серверу, даже если профиль сейчас выключен и TunnelFacts уже нет.</summary>
    private void ForgetChangedServers(AppSettings previous)
    {
        var changed = previous.Profiles
            .Where(p => _settings.Profile(p.Id) is not { } current || p.Server != current.Server || p.Protocol != current.Protocol)
            .Select(p => p.Id).ToHashSet();
        if (changed.Count == 0)
        {
            return;
        }

        _state = _state with { Servers = _state.Servers.Where(s => !changed.Contains(s.ProfileId)).ToList() };
        try
        {
            _deps.Stores.SaveState(_state);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Состояние в памяти уже без прежних адресов; файл перепишет следующая запись.
            _deps.Logger.LogWarning(ex, "Кеш адресов сменённых серверов не сохранён в файл состояния");
        }
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => changed.Contains(t.ProfileId)))
        {
            tunnel.ServerAddresses = [];
            tunnel.ServerResolvedUtc = default;
            tunnel.NextServerResolveAt = default;
            tunnel.ServerResolveStartedUtc = null;
            tunnel.FailedDialsSinceResolve = 0;
            // Обрыв был на прежнем сервере: новый его сеанс не держит, и ждать его незачем.
            tunnel.UncleanDropUtc = null;
            tunnel.ServerCertificate = null;
            tunnel.RevocationHosts = [];
            tunnel.RevocationRetryUsed = false;
            tunnel.CertificateProbeGeneration = 0;
            tunnel.CertificateProbeRunning = false;
            tunnel.LastCertificateProbeUtc = default;
        }
    }

    private IpcResponse SetPassword(Guid profileId, string password)
    {
        if (password.Length > 256 || password.Contains('\0', StringComparison.Ordinal))
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Недопустимая длина или символы пароля RAS.");
        }

        var profile = _settings.Profile(profileId);
        if (profile is null)
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Подключение не найдено.");
        }

        if (!VpnProtocols.NeedsPassword(profile.AuthMethod))
        {
            // Пустой пароль вместе с подключением профиля без пароля — просто «нечего сохранять».
            return password.Length == 0
                ? IpcResponse.Success()
                : IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Для этого способа входа пароль не используется.");
        }

        if (profile.SavePassword)
        {
            try
            {
                _deps.Secrets.Save(profileId, password);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
            {
                _deps.Logger.LogWarning(ex, "Пароль для {Name} не сохранён", profile.Name);
                return IpcResponse.Failure(IpcErrorCodes.Failed, $"Не удалось сохранить пароль для «{profile.Name}»: {ex.Message}");
            }

            ForgetMemoryPassword(profileId);
        }
        else
        {
            RememberPassword(profileId, password);
        }

        if (Facts.Tunnels.GetValueOrDefault(profileId) is { } tunnel)
        {
            tunnel.PasswordRequired = false;
            tunnel.BlockingError = tunnel.BlockingError == ErrorCategory.Authentication ? ErrorCategory.None : tunnel.BlockingError;
        }

        Journal("Сведения", $"Пароль для «{profile.Name}» {(profile.SavePassword ? "сохранён" : "запомнен до перезапуска службы")}.");
        return IpcResponse.Success();
    }

    private async Task<IpcResponse> SetPreSharedKeyAsync(SetPreSharedKeyRequest request, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.Values.Any(t => t.Dialing) || Facts.ProfileTestRunning)
        {
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Дождитесь завершения дозвона перед изменением ключа.");
        }

        if (_settings.Profile(request.ProfileId) is not { } profile)
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Подключение не найдено.");
        }

        if (!VpnProtocols.NeedsPreSharedKey(profile) || request.Key.Length > 256 || request.Key.Contains('\0', StringComparison.Ordinal))
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings,
                "Ключ PSK допустим только для L2TP/IPsec и должен содержать не более 256 символов без нулевого символа.");
        }

        if (request.Key.Length == 0)
        {
            _deps.Secrets.Delete(profile.Id, SecretKind.PreSharedKey);
        }
        else
        {
            _deps.Secrets.Save(profile.Id, request.Key, SecretKind.PreSharedKey);
        }

        if (Facts.Tunnels.GetValueOrDefault(profile.Id) is { } tunnel)
        {
            // Новый ключ уже записан: повторная сверка должна применить его даже после отказа RAS.
            tunnel.ReconnectRequired = true;
            if (tunnel.HasSession)
            {
                await HangUpAsync(tunnel, "изменён ключ IPsec", cancellationToken);
            }

            _deps.Ras.DeleteEntry(tunnel.EntryName);
            tunnel.AppliedEntryServer = null;
            tunnel.ReconnectRequired = false;
            tunnel.BlockingError = ErrorCategory.None;
            tunnel.NextDialAt = _deps.Time.GetUtcNow();
            RetryFromScratch(tunnel);
            await ReconcileAsync(cancellationToken);
        }

        Journal("Сведения", request.Key.Length == 0 ? "Ключ IPsec удалён." : "Ключ IPsec сохранён.");
        return IpcResponse.Success();
    }

    private void RememberPassword(Guid profileId, string password)
    {
        ForgetMemoryPassword(profileId);
        Facts.MemoryPasswords[profileId] = password.ToCharArray();
    }

    /// <summary>Затирает запомненный пароль профиля: копия в памяти не должна пережить сам пароль.</summary>
    private void ForgetMemoryPassword(Guid profileId)
    {
        if (Facts.MemoryPasswords.Remove(profileId, out var old))
        {
            Array.Clear(old);
        }
    }

    private async Task<IpcResponse> ConnectAsync(ConnectRequest request, CancellationToken cancellationToken)
    {
        if (Facts.ProfileTestRunning)
        {
            // Пробный дозвон занимает запись RAS проверяемого профиля: обычный дозвон столкнулся бы с ним.
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Идёт пробное подключение: дождитесь его завершения.");
        }

        if (request.ProfileId is { } id)
        {
            if (_settings.Profile(id) is null)
            {
                return IpcResponse.Failure(IpcErrorCodes.NotFound, "Подключение не найдено.");
            }

            // AnyConnect не бывает опорным: включается дополнительным.
            var anyConnect = _settings.Profile(id)!.Protocol == VpnProtocol.AnyConnect;
            if (anyConnect)
            {
                Facts.SignInApproved.Add(id);
            }

            if (_settings.Profile(id)!.Role == ProfileRole.Off)
            {
                var assigned = await SetProfileRoleAsync(id, anyConnect ? ProfileRole.Secondary : ProfileRole.Primary, cancellationToken);
                if (!assigned.Ok)
                {
                    return assigned;
                }
            }

            if (request.Password is { } profilePassword && SetPassword(id, profilePassword) is { Ok: false } refused)
            {
                // Неверный пароль не должен молча уйти в дозвон со старым или пустым паролем.
                return refused;
            }
        }
        else
        {
            if (request.Password is { } password && PasswordRecipient() is { } recipient
                && SetPassword(recipient.Id, password) is { Ok: false } refused)
            {
                return refused;
            }

            Facts.SignInApproved.UnionWith(ActiveProfiles.Where(p => p.Protocol == VpnProtocol.AnyConnect).Select(p => p.Id));
        }

        if (ActiveProfiles.Count == 0)
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Не включено ни одно подключение.");
        }

        var now = _deps.Time.GetUtcNow();
        foreach (var tunnel in Facts.Tunnels.Values)
        {
            tunnel.BlockingError = ErrorCategory.None;
            tunnel.NextDialAt = now;
            tunnel.DialSettled = false;
            tunnel.DialStartedUtc = null;
            // «Подключить» - действие пользователя: повтор после открытия адресов проверки отзыва даётся заново.
            tunnel.RevocationRetryUsed = false;
            // Общее «Подключить» поднимает всё, что было положено вручную. Но «Подключить» с паролем для
            // одного профиля (ввод пароля на главной) не должен молча поднимать чужие положенные туннели.
            if (request.ProfileId is null || request.ProfileId == tunnel.ProfileId)
            {
                tunnel.Paused = false;
            }

            RetryFromScratch(tunnel);
        }

        return await ChangeIntentAsync(Intent.Connected, cancellationToken);
    }

    /// <summary>
    /// Команда пользователя («Подключить», новые данные входа, смена сервера): счётчики повторов начинаются
    /// заново, и на первой же неудачной проверке снова запускается детектор конфликтов.
    /// </summary>
    private static void RetryFromScratch(TunnelFacts tunnel)
    {
        tunnel.ResetRetries();
        tunnel.LastConflictProbeUtc = default;
    }

    /// <summary>
    /// Кладёт или поднимает один туннель, не меняя настроек. Запрета «дождитесь дозвона» здесь нет,
    /// в отличие от смены роли: положить туннель надо и посреди дозвона, иначе кнопка обманывает.
    /// Дозвон, начатый до нажатия, отбрасывается в <see cref="OnDialFinishedAsync"/> по флагу.
    /// </summary>
    private async Task<IpcResponse> SetTunnelPausedAsync(Guid profileId, bool paused, CancellationToken cancellationToken)
    {
        if (_settings.Profile(profileId) is not { } profile)
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Подключение не найдено.");
        }

        if (profile.Role == ProfileRole.Off)
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings,
                $"«{profile.Name}» выключено совсем: включите его на странице «Подключения».");
        }

        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { } tunnel)
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Подключение ещё не готово: повторите через секунду.");
        }

        if (tunnel.Paused == paused)
        {
            return IpcResponse.Success(BuildStatus());
        }

        tunnel.Paused = paused;
        if (paused)
        {
            try
            {
                await HangUpAsync(tunnel, "отключено вами", cancellationToken);
            }
            catch when (tunnel.HasSession)
            {
                // Разрыв не состоялся: туннель жив и несёт трафик — отметка «отключено» была бы ложью.
                tunnel.Paused = false;
                throw;
            }

            Journal("Сведения", $"«{tunnel.Name}» отключено вами. Назначенный ему трафик заблокирован до включения.");
        }
        else
        {
            // Включение — явное намерение пользователя: снимаем и отказ, и отметку «разорвано извне».
            tunnel.BlockingError = ErrorCategory.None;
            tunnel.ExternallyDisconnected = false;
            tunnel.NextDialAt = _deps.Time.GetUtcNow();
            RetryFromScratch(tunnel);
            Journal("Сведения", $"«{tunnel.Name}» включено вами.");
        }

        await ReconcileAsync(cancellationToken);
        return IpcResponse.Success(BuildStatus());
    }

    /// <summary>
    /// Переставляет подключения. Отдельный запрос, а не сохранение настроек целиком: порядок не должен
    /// затирать чужие правки, а запрет сохранения во время дозвона для перестановки лишний.
    /// </summary>
    private async Task<IpcResponse> SetProfileOrderAsync(IReadOnlyList<Guid> order, CancellationToken cancellationToken)
    {
        if (!ConnectionEdits.IsSameSet(_settings.Profiles, order))
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Порядок подключений не совпадает со списком.");
        }

        var settings = ConnectionEdits.Reorder(_settings, order);
        _deps.Stores.SaveSettings(settings);
        _settings = settings;
        await ReconcileAsync(cancellationToken);
        return IpcResponse.Success(BuildStatus());
    }

    /// <summary>
    /// Кому отдать пароль без явного профиля (прежний интерфейс): туннелю, который ждёт пароль, а если такого
    /// нет — опорному. Иначе пароль дополнительного туннеля затёр бы сохранённый пароль опорного.
    /// </summary>
    private ConnectionProfile? PasswordRecipient() =>
        ActiveProfiles.FirstOrDefault(p => Facts.Tunnels.GetValueOrDefault(p.Id)?.PasswordRequired == true)
        ?? _settings.PrimaryProfile;

    /// <summary>
    /// Смена роли подключения. Новое опорное подключение снимает эту роль с прежнего; выключение
    /// подключения, на которое что-то направлено, отклоняется валидатором настроек.
    /// </summary>
    private async Task<IpcResponse> SetProfileRoleAsync(Guid profileId, ProfileRole role, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.Values.Any(t => t.Dialing) || Facts.ProfileTestRunning)
        {
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Дождитесь завершения дозвона перед сменой роли подключения.");
        }

        if (_settings.Profile(profileId) is null)
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Подключение не найдено.");
        }

        var profiles = _settings.Profiles.Select(p => p.Id == profileId
            ? p with { Role = role }
            : role == ProfileRole.Primary && p.Role == ProfileRole.Primary ? p with { Role = ProfileRole.Secondary } : p).ToList();
        var settings = _settings with { Profiles = profiles };

        // Первое включённое подключение забирает «остальной интернет»: иначе VPN поднимется, но никуда не поведёт.
        // Осознанное «Напрямую» при раздельной маршрутизации остаётся (AppSettings.DefaultFollowsNewPrimary).
        if (role == ProfileRole.Primary && _settings.Profile(profileId)!.Role != ProfileRole.Primary && settings.DefaultFollowsNewPrimary())
        {
            settings = settings with { DefaultTarget = RouteTarget.Tunnel(profileId) };
        }

        var validation = SettingsValidator.Validate(settings);
        if (!validation.IsValid)
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, string.Join(Environment.NewLine, validation.Errors));
        }

        var previous = _settings;
        _deps.Stores.SaveSettings(settings);
        _settings = settings;
        Journal("Сведения", $"«{settings.Profile(profileId)!.Name}»: роль — {RoleName(role)}.");
        await ReconnectChangedEndpointsAsync(previous, cancellationToken);
        await ReconcileAsync(cancellationToken);
        return IpcResponse.Success(BuildStatus());
    }

    private static string RoleName(ProfileRole role) => role switch
    {
        ProfileRole.Primary => "опорное",
        ProfileRole.Secondary => "дополнительное",
        _ => "выключено",
    };

    internal async Task<IpcResponse> ChangeIntentAsync(Intent intent, CancellationToken cancellationToken)
    {
        if (intent != _state.Intent || _state.ProtectionSuspended)
        {
            Journal("Сведения", intent switch
            {
                Intent.Connected => "Команда: подключить VPN.",
                Intent.Protected => "Команда: отключить VPN, сохранить защиту.",
                _ => "Команда: отключить VPN и восстановить обычный интернет.",
            });
        }

        // Сначала запись, потом состояние в памяти: не сохранённая команда (файл занят, диск полон) возвращает
        // ошибку и не должна менять сеть — иначе клиент видит отказ, а после перезапуска действует прежнее намерение.
        var next = _state with { Intent = intent, ProtectionSuspended = false };
        _deps.Stores.SaveState(next);

        foreach (var tunnel in Facts.Tunnels.Values)
        {
            tunnel.ExternallyDisconnected = false;
        }

        if (intent != Intent.Connected)
        {
            Facts.SignInApproved.Clear();
        }

        _state = next;
        await ReconcileAsync(cancellationToken);
        return IpcResponse.Success(BuildStatus());
    }

    private async Task<AddressCheckDto> CheckAddressAsync(string query, CancellationToken cancellationToken) =>
        AddressCheck(query, await ResolveForCheckAsync(query.Trim(), cancellationToken));

    /// <summary>
    /// Проверка адреса из IPC: имя разрешается системным резолвером вне очереди актора. Запрос идёт через
    /// наш DNS-посредник, а тот для домена с правилом ставит закрепление в ту же очередь и ждёт его —
    /// разрешение внутри очереди ждало бы само себя до таймаута закрепления и отвечало «не удалось».
    /// </summary>
    private async Task<IpcResponse> CheckAddressOutsideQueueAsync(CheckAddressRequest check, CancellationToken cancellationToken)
    {
        var addresses = await ResolveForCheckAsync(check.Query.Trim(), cancellationToken);
        var result = await EnqueueResultAsync("CheckAddress", () => AddressCheck(check.Query, addresses), cancellationToken);
        return IpcResponse.Success(result);
    }

    private AddressCheckDto AddressCheck(string query, IReadOnlyList<uint> addresses)
    {
        var items = addresses.Select(a => DescribeAddress(a, query.Trim())).ToList();
        var note = addresses.Count > 1 ? "У домена несколько адресов: при CDN разные адреса могут идти разными путями." : null;
        return new AddressCheckDto(query, items, addresses.Count == 0 ? "Не удалось получить IPv4-адреса." : note);
    }

    private static async Task<IReadOnlyList<uint>> ResolveForCheckAsync(string query, CancellationToken cancellationToken)
    {
        if (Ipv4.TryParse(query, out var literal))
        {
            return [literal];
        }

        try
        {
            var resolved = await Dns.GetHostAddressesAsync(query, AddressFamily.InterNetwork, cancellationToken);
            return resolved.Select(Ipv4.ToUInt).Distinct().ToList();
        }
        catch (SocketException)
        {
            return [];
        }
    }

    private AddressCheckItem DescribeAddress(uint address, string query)
    {
        var classification = Facts.Policy?.Classify(address) ?? PolicyCompiler.Label(_settings.DefaultTarget, DecisionSource.Default);
        var domain = MatchingDomainRule(query);
        var expected = classification.Decision switch
        {
            Decision.Direct or Decision.Server => Facts.Primary?.Name ?? "основной адаптер",
            Decision.Local => "локальная сеть",
            Decision.Block => "заблокировано правилом",
            _ => Facts.Tunnels.GetValueOrDefault(classification.Tunnel)?.Adapter?.Name ?? TunnelName(classification.Tunnel),
        };
        var route = _deps.Probes.FindBestRoute(address);
        var actual = route is null ? null : (_snapshot?.Adapters.FirstOrDefault(a => a.Luid == route.InterfaceLuid)?.Name ?? route.InterfaceLuid.ToString(CultureInfo.InvariantCulture));
        var blocked = classification.Decision == Decision.Block
            || (classification.Decision == Decision.Vpn && Facts.Tunnels.GetValueOrDefault(classification.Tunnel)?.IsUp != true
                && _state.Intent != Intent.Off && !DirectOnOutage(classification.Tunnel));
        return new AddressCheckItem(
            Ipv4.Format(address),
            classification.Decision.ToString(),
            classification.Source.ToString(),
            TargetNameFor(classification),
            expected,
            actual,
            blocked,
            Explain(classification, domain, address));
    }

    /// <summary>Правило для домена с самым длинным подходящим суффиксом.</summary>
    private DomainRuleSetting? MatchingDomainRule(string query)
    {
        if (Ipv4.TryParse(query, out _))
        {
            return null;
        }

        // Тот же вид, что у суффиксов правил (IDNA ASCII): «пример.рф» и «xn--e1afmkfd.xn--p1ai» — одно имя.
        var name = SettingsSerializer.NormalizeSuffix(query);
        return _settings.DomainRules
            .Select(r => (Rule: r, Suffix: SettingsSerializer.NormalizeSuffix(r.Suffix)))
            .Where(r => r.Suffix.Length > 0 && (name == r.Suffix || name.EndsWith("." + r.Suffix, StringComparison.Ordinal)))
            .OrderByDescending(r => r.Suffix.Length)
            .Select(r => r.Rule)
            .FirstOrDefault();
    }

    private string TargetNameFor(Classification classification) => classification.Decision switch
    {
        Decision.Vpn => _settings.TargetName(RouteTarget.Tunnel(classification.Tunnel)) is var name && name.Contains("неизвестное", StringComparison.Ordinal)
            ? _settings.TargetName(RouteTarget.Group(classification.Tunnel))
            : name,
        Decision.Block => "блокировать",
        Decision.Local => "локальная сеть",
        Decision.Server => "сервер VPN, напрямую",
        _ => "напрямую",
    };

    private string TunnelName(Guid id) =>
        _settings.Profile(id)?.Name ?? _settings.Group(id)?.Name ?? "VPN";

    /// <summary>
    /// Пояснение к решению. Правило для домена называется причиной, только когда решение и правда принято им:
    /// адрес может быть ещё не закреплён или его путь задаёт более сильное правило, и тогда пояснение «по правилу
    /// для домена» противоречило бы показанному пути.
    /// </summary>
    private string Explain(Classification classification, DomainRuleSetting? domain, uint address)
    {
        if (domain is not null && classification.Source == DecisionSource.DomainRule)
        {
            return $"Правило для домена «{domain.Suffix}» ({_settings.TargetName(domain.Target)}); маршрут ставится на время TTL ответа DNS.";
        }

        var reason = ExplainSource(classification, address);
        return domain is null
            ? reason
            : reason + $" Правило для домена «{domain.Suffix}» к этому адресу не применено: адрес ещё не закреплён или его путь задаёт правило сильнее.";
    }

    private string ExplainSource(Classification classification, uint address)
    {
        return classification.Source switch
        {
            DecisionSource.Geo => "Адрес есть в RU-базе — " + _settings.TargetName(_settings.GeoTarget) + ".",
            DecisionSource.Bypass => (_bypass.ActiveSet.Contains(address)
                ? "Адрес есть в списке обхода блокировок — "
                : $"Адрес в подсети /{_settings.BypassAggregatePrefix} с адресами из списка обхода блокировок (свёртка списка) — ")
                + _settings.TargetName(BypassTarget) + ".",
            DecisionSource.UserRule => $"Пользовательское правило {classification.Rule?.Cidr} ({_settings.TargetName(classification.Rule!.Target)}).",
            DecisionSource.DomainRule => "Адрес закреплён правилом для домена — " + TargetNameFor(classification) + ".",
            DecisionSource.LocalNetwork => "Локальная сеть — по настройке «Локальный доступ».",
            DecisionSource.OnLink => "Сеть одного из интерфейсов — по настройке «Локальный доступ».",
            DecisionSource.Loopback => "Loopback — всегда локально.",
            DecisionSource.Reserved => "Зарезервированный диапазон: не классифицируется по стране.",
            DecisionSource.Server => "Адрес VPN-сервера — транспорт через основной адаптер.",
            DecisionSource.ServiceDns => "DNS для начального разрешения — только для службы.",
            DecisionSource.ServerNetwork => "Сеть, присланная шлюзом AnyConnect, — по карточке «Сети шлюза».",
            DecisionSource.TunnelInfrastructure => "Служебный адрес туннеля (его DNS) — всегда через свой туннель.",
            _ => "Адреса нет ни в одном правиле — " + _settings.TargetName(_settings.DefaultTarget) + ".",
        };
    }

    private string ExportReport(bool mask) => ExportReport(mask, BuildStatus(), Adapters());

    /// <summary>
    /// Отчёт по готовым состоянию и адаптерам: вне очереди актора он собирается из последнего снимка — журнал
    /// событий потокобезопасен, настройки заменяются целиком.
    /// </summary>
    private string ExportReport(bool mask, StatusDto status, IReadOnlyList<AdapterDto> adapters)
    {
        var settings = _settings;
        var report = JsonSerializer.Serialize(new
        {
            generatedUtc = _deps.Time.GetUtcNow(),
            status = WithoutUrlSecrets(status),
            adapters,
            events = _deps.Journal.Since(0),
        }, JsonDefaults.Options);
        // Маскирование идёт по строковым значениям разобранного JSON, а не по тексту: кавычка или косая черта
        // в названии профиля не ломают структуру. Названия профилей, групп и адаптеров тоже личные. Журнал
        // событий помнит и прежние названия и серверы — они маскируются по настройкам, бывшим с запуска службы.
        var personal = PersonalValues(settings)
            .Concat(_formerPersonalValues.Keys)
            .Concat(status.Tunnels.SelectMany(TunnelPersonalNames))
            .Concat(_gatewayNodeHosts.Keys)
            .Concat(adapters.Select(a => a.Name))
            .Concat(adapters.Select(a => a.Description))
            .OfType<string>()
            .Where(s => s.Length > 0)
            .ToList();
        return mask ? Redactor.RedactJson(report, personal) : report;
    }

    /// <summary>
    /// Личные значения настроек, сменённых с запуска службы (названия, серверы, учётные записи): журнал событий
    /// хранит записи о переименованных и удалённых подключениях, и отчёт маскирует их и после смены настроек.
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> _formerPersonalValues = new(StringComparer.Ordinal);

    private void RememberPersonalValues(AppSettings settings)
    {
        foreach (var value in PersonalValues(settings))
        {
            _formerPersonalValues.TryAdd(value, 0);
        }
    }

    /// <summary>Личные значения настроек: учётные записи, серверы и их хосты, домены, названия подключений и групп.</summary>
    private static IEnumerable<string> PersonalValues(AppSettings settings) =>
        settings.Profiles.SelectMany(p => new[] { p.UserName, p.Server, p.Domain, p.Name, ServerHost(p) })
            .Concat(settings.Groups.Select(g => g.Name))
            .OfType<string>()
            .Where(s => s.Length > 0);

    /// <summary>Подробный журнал на срок или выключить. Состояние актора не меняется — идёт без очереди.</summary>
    private IpcResponse SetVerboseLogging(int minutes)
    {
        if (_deps.Verbose is not { } verbose)
        {
            return IpcResponse.Failure(IpcErrorCodes.Failed, "Подробный журнал недоступен.");
        }

        if (minutes < 0 || minutes > Core.Diagnostics.VerboseRegistry.MaxDuration.TotalMinutes)
        {
            return IpcResponse.Failure(IpcErrorCodes.BadRequest, "Срок подробного журнала — от минуты до суток.");
        }

        if (minutes == 0)
        {
            return verbose.Disable("выключен вручную")
                ? IpcResponse.Success<DateTimeOffset?>(null)
                : IpcResponse.Failure(IpcErrorCodes.Failed, "Подробный журнал выключен, но срок не удалён из реестра: после перезапуска службы он включится снова. Повторите выключение.");
        }

        try
        {
            return IpcResponse.Success<DateTimeOffset?>(verbose.Enable(TimeSpan.FromMinutes(minutes)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return IpcResponse.Failure(IpcErrorCodes.Failed, "Срок подробного журнала не записан в реестр: " + ex.Message);
        }
    }

    /// <summary>
    /// Часть службы для архива разбора. Вне очереди актора: состояние и адаптеры — из последнего снимка,
    /// журнал событий потокобезопасен, настройки заменяются целиком (паролей в них нет).
    /// </summary>
    private IpcResponse CollectDiagnostics(CancellationToken cancellationToken)
    {
        if (_deps.DiagnosticsCollector is not { } collector || _deps.DiagnosticsPackages is not { } packages)
        {
            return IpcResponse.Failure(IpcErrorCodes.Failed, "Сбор архива недоступен.");
        }

        var snapshot = _readSnapshot;
        var settings = _settings;
        var dnsProxy = _deps.DnsProxy;
        var parts = new List<Diagnostics.DiagnosticsPart>
        {
            new("status.json", () => JsonSerializer.Serialize(WithoutUrlSecrets((snapshot?.Status ?? new StatusDto()) with { VerboseUntilUtc = _deps.Verbose?.UntilUtc }), JsonDefaults.Options)),
            new("adapters.json", () => JsonSerializer.Serialize(snapshot?.Adapters ?? [], JsonDefaults.Options)),
            // Адреса зеркал и источников — без логина, пароля и параметров: в них бывают токены доступа.
            new("settings.json", () => LogText.StripUrls(SettingsSerializer.Serialize(settings))),
            new("events.json", () => JsonSerializer.Serialize(_deps.Journal.Since(0), JsonDefaults.Options)),
            new("net/dns-proxy.txt", () => DescribeDnsProxy(dnsProxy)),
        };

        _deps.Logger.LogInformation("Собирается архив для разбора");
        DiagnosticsPackageDto? package;
        try
        {
            package = packages.Create(stream => collector.Write(stream, parts, cancellationToken));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Нет места на диске, каталог недоступен: клиент получает причину, а не обрыв канала.
            _deps.Logger.LogWarning(ex, "Архив для разбора не собран");
            return IpcResponse.Failure(IpcErrorCodes.Failed, "Архив не собран: " + ex.Message);
        }

        return package is null
            ? IpcResponse.Failure(IpcErrorCodes.Busy, "Архив уже собирается: дождитесь окончания.")
            : IpcResponse.Success(package);
    }

    /// <summary>
    /// Состояние для архива: адрес входа (SSO) и PAC шлюза режутся до пути — в query бывают токены SAML,
    /// значения полей формы входа не берутся вовсе.
    /// </summary>
    internal static StatusDto WithoutUrlSecrets(StatusDto status) => status with
    {
        Tunnels = [.. status.Tunnels.Select(t => t with
        {
            SignIn = t.SignIn is null ? null : t.SignIn with
            {
                Uri = t.SignIn.Uri is null ? null : LogText.UrlForLog(t.SignIn.Uri),
                Fields = [.. t.SignIn.Fields.Select(f => f with { Value = null })],
            },
            ServerNetworks = t.ServerNetworks is { ProxyPac: { } pac } networks ? networks with { ProxyPac = LogText.UrlForLog(pac) } : t.ServerNetworks,
        })],
    };

    private IpcResponse ReadDiagnosticsChunk(ReadDiagnosticsChunkRequest request) =>
        _deps.DiagnosticsPackages?.Read(request.Token, request.Offset) is { } chunk
            ? IpcResponse.Success(chunk)
            : IpcResponse.Failure(IpcErrorCodes.NotFound, "Архив не найден: соберите его заново.");

    private static string DescribeDnsProxy(Windows.Operations.IDnsProxy proxy)
    {
        var configuration = proxy.Configuration;
        var stats = proxy.Stats;
        var text = new System.Text.StringBuilder();
        text.AppendLine(CultureInfo.InvariantCulture, $"Работает: {(proxy.IsRunning ? "да" : "нет")}; режим {configuration.Mode}");
        text.AppendLine(CultureInfo.InvariantCulture, $"Запросов {stats.Queries}, из кеша {stats.CacheHits}, закреплённых {stats.Pinned}, переслано {stats.Forwarded}, отказов {stats.Failures}");
        text.AppendLine("Туннель: " + DescribeRoute(configuration.Tunnel));
        text.AppendLine("Напрямую: " + DescribeRoute(configuration.Direct));
        text.AppendLine("Локальный: " + DescribeRoute(configuration.Local) + "; суффиксы " + string.Join(", ", configuration.LocalSuffixes));
        text.AppendLine("Правила для доменов:");
        foreach (var rule in configuration.DomainRoutes)
        {
            text.AppendLine(CultureInfo.InvariantCulture,
                $"  {(rule.ExactName ? "" : "*.")}{rule.Suffix} → {rule.Target}; путь {DescribeRoute(rule.Route)}{(rule.Unavailable ? "; недоступен" : "")}{(rule.PinAddresses ? "; закрепление" : "")}");
        }

        return text.ToString();
    }

    private static string DescribeRoute(Windows.Dns.DnsRoute? route) =>
        route is null ? "нет" : string.Create(CultureInfo.InvariantCulture, $"if{route.InterfaceIndex?.ToString(CultureInfo.InvariantCulture) ?? "—"} {string.Join(",", route.Servers)}");

    /// <summary>Хост сервера или шлюза без схемы и порта: в журнале он встречается отдельно от строки профиля.</summary>
    private static string? ServerHost(ConnectionProfile profile) =>
        TryParseServer(profile, out var server) ? server.Host : null;

    /// <summary>
    /// Имена, которые туннель узнал от сервера: хост входа, суффиксы DNS шлюза, имена из сертификата. Имена
    /// из одной метки («corp», «local») не маскируются: они совпали бы с частями слов по всему отчёту.
    /// </summary>
    private static IEnumerable<string?> TunnelPersonalNames(TunnelStatusDto tunnel)
    {
        yield return tunnel.SignIn?.GatewayHost;
        var names = (tunnel.ServerNetworks?.DnsSuffixes ?? [])
            .Concat(tunnel.ServerCertificate is { } certificate ? [certificate.Subject, .. certificate.Names] : [])
            .Select(name => name.TrimStart('*').Trim('.'))
            .Where(name => name.Contains('.', StringComparison.Ordinal));
        foreach (var name in names)
        {
            yield return name;
        }
    }
}
