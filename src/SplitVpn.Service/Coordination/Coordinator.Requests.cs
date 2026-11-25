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
    private IpcResponse? SettingsUnavailable(IpcRequest request) =>
        _settingsReadError is { } error && request is not (GetStatusRequest or GetServerNetworksRequest or GetEventsRequest or RecoverNetworkRequest
            or DisconnectRequest { KeepProtection: false } or SetVerboseLoggingRequest or CollectDiagnosticsRequest or ReadDiagnosticsChunkRequest)
            ? IpcResponse.Failure(IpcErrorCodes.Busy, error + " Служба повторит чтение автоматически.")
            : null;

    internal async Task<IpcResponse> HandleRequestAsync(IpcRequest request, CancellationToken cancellationToken) => request switch
    {
        _ when request.ContractVersion != IpcNames.ContractVersion => IpcResponse.Failure(IpcErrorCodes.BadRequest, "Версия приложения несовместима со службой. Обновите оба компонента."),
        _ when RefuseWhileEmergencyOff(request) is { } refused => refused,
        RecoverNetworkRequest when _emergency is not null => RecoverWhileEmergencyOff(),
        _ when SettingsUnavailable(request) is { } unavailable => unavailable,
        GetStatusRequest => IpcResponse.Success(BuildStatus()),
        GetServerNetworksRequest networks => ServerNetworksPage(networks),
        GetEventsRequest events => IpcResponse.Success(_deps.Journal.Since(events.SinceId)),
        GetAdaptersRequest => IpcResponse.Success(Adapters()),
        GetSettingsRequest => IpcResponse.Success(_settings),
        SaveSettingsRequest { ExpectedRevision: { } revision } when revision != SettingsSerializer.Revision(_settings)
            => IpcResponse.Failure(IpcErrorCodes.Busy, "Настройки изменились. Повторите команду с актуальными данными."),
        SaveSettingsRequest save => await SaveSettingsAsync(save.Settings, cancellationToken),
        SaveConnectionRequest save => await SaveConnectionAsync(save, cancellationToken),
        SetPasswordRequest password => SetPassword(password.ProfileId, password.Password),
        SetPreSharedKeyRequest key => await SetPreSharedKeyAsync(key, cancellationToken),
        ConnectRequest connect => await ConnectAsync(connect, cancellationToken),
        DisconnectRequest disconnect => await ChangeIntentAsync(disconnect.KeepProtection ? Intent.Protected : Intent.Off, cancellationToken),
        SetProfileRoleRequest role => await SetProfileRoleAsync(role.ProfileId, role.Role, cancellationToken),
        SetTunnelPausedRequest paused => await SetTunnelPausedAsync(paused.ProfileId, paused.Paused, cancellationToken),
        SetProfileOrderRequest order => await SetProfileOrderAsync(order.Order, cancellationToken),
        RecoverNetworkRequest => await ChangeIntentAsync(Intent.Off, cancellationToken, recoverNetwork: true),
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
        UpdateStartedRequest started => _update.InstallStarted(this, started.ProcessId, started.AttemptId),
        SkipUpdateRequest skip => _update.SkipVersion(this, skip.Version),
        ExportReportRequest report => ExportReport(report.MaskPersonalData),
        SetVerboseLoggingRequest verbose => SetVerboseLogging(verbose.Minutes),
        CollectDiagnosticsRequest diagnostics => CollectDiagnostics(cancellationToken, diagnostics.ServiceDirectoryPrefix),
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

    private async Task<IpcResponse> SaveSettingsAsync(AppSettings settings, CancellationToken cancellationToken, bool reconcile = true, Guid? reuseCredentials = null)
    {
        if (Facts.Tunnels.Values.Any(t => t.Dialing) || Facts.ProfileTestRunning)
        {
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Дождитесь завершения дозвона перед изменением настроек.");
        }

        // Проверяется и сохраняется одна и та же нормализованная модель: «null» из канала управления не попадает в файл.
        settings = SettingsSerializer.Normalize(settings);
        // Служебные разделы исходных значений (файл более новой версии) принимаются только такими, какими служба
        // прочитала их из своего файла: подложенный клиентом раздел записал бы в файл непроверенные роль, протокол
        // или способ входа, а подключение с ним миновало бы полную проверку.
        settings = UnknownSettingValues.KeepOnlyTrusted(settings, _settings);
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
        // Потерянные секреты (не читаются дольше UnreadableSecretGrace) тоже удаляются до записи файла, но без копии:
        // при сбое записи их уже не вернуть. Это меньшее зло: удаление после записи могло не состояться (сбой,
        // перезапуск службы), и ожившая расшифровка отдала бы прежний пароль новому серверу.
        // Без явного подтверждения пароль к новому серверу не переходит: настройки с новым сервером
        // появляются только после удаления пароля. Подтверждённая привязка проверена в SaveConnectionAsync.
        var outdated = OutdatedSecrets(previous, settings, reuseCredentials);
        var backups = new List<SecretBackup>();
        try
        {
            OutdatedSecret? unreadable;
            try
            {
                unreadable = DeleteSecrets(outdated.Secrets, backups);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                RestoreSecrets(backups);
                Journal("Ошибка", "Настройки не сохранены: не удалось удалить сохранённый пароль или ключ IPsec — " + ex.Message);
                return IpcResponse.Failure(IpcErrorCodes.Failed, "Настройки не сохранены: не удалось удалить сохранённый пароль или ключ IPsec. " + ex.Message);
            }

            if (unreadable is { } locked)
            {
                // Ничего ещё не удалено. Без копии удалять нельзя: при сбое записи настроек пароль или ключ пропал бы.
                // Не читается подряд дольше нескольких минут - следующее сохранение удалит его без копии (DeleteSecrets).
                var what = SecretName(locked.Kind);
                Journal("Ошибка", $"Настройки не сохранены: {what} «{locked.ProfileName}» нужно удалить, но Windows сейчас не может его расшифровать, "
                    + "а без копии удалять его нельзя. Повторите сохранение через несколько минут: если он так и не прочитается, он будет удалён.");
                return IpcResponse.Failure(IpcErrorCodes.Failed, $"Настройки не сохранены: {what} «{locked.ProfileName}» нужно удалить, но Windows сейчас не может его расшифровать. "
                    + "Повторите сохранение через несколько минут: если он так и не прочитается, он будет удалён, и его придётся ввести заново.");
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

    /// <summary>Как секрет называется в сообщениях.</summary>
    private static string SecretName(SecretKind kind) => kind switch
    {
        SecretKind.PreSharedKey => "ключ IPsec",
        SecretKind.SshPrivateKey => "ключ SSH",
        _ => "сохранённый пароль",
    };

    /// <summary>Секрет, который нужно удалить при сохранении настроек: профиль, вид и название для журнала.</summary>
    private readonly record struct OutdatedSecret(Guid ProfileId, SecretKind Kind, string ProfileName);

    /// <summary>Копия секрета для восстановления при сбое удаления или записи настроек.</summary>
    private readonly record struct SecretBackup(Guid ProfileId, SecretKind Kind, string ProfileName, char[] Value);

    /// <summary>
    /// Секреты, которые не переходят к новым настройкам: ключ IPsec и пароль после смены сервера, протокола,
    /// способа входа или учётной записи; пароль удалённого профиля или профиля, где его больше не сохраняют.
    /// Только вычисляет: удаление, забывание паролей в памяти и записи журнала идут при сохранении.
    /// </summary>
    private (List<OutdatedSecret> Secrets, List<Guid> MemoryPasswords, List<string> Notes) OutdatedSecrets(AppSettings previous, AppSettings settings, Guid? reuseCredentials)
    {
        var secrets = new List<OutdatedSecret>();
        var memory = new List<Guid>();
        var notes = new List<string>();
        foreach (var old in previous.Profiles)
        {
            var next = settings.Profiles.FirstOrDefault(p => p.Id == old.Id);
            var reuse = old.Id == reuseCredentials;
            if (next is null || !VpnProtocols.NeedsPreSharedKey(next) || (!reuse && ConnectionEdits.PreSharedKeyBindingChanged(old, next)))
            {
                if (next is not null && VpnProtocols.NeedsPreSharedKey(next) && SecretKept(old.Id, SecretKind.PreSharedKey))
                {
                    notes.Add($"Ключ IPsec «{old.Name}» удалён: изменились сервер или протокол — введите ключ заново.");
                }

                secrets.Add(new OutdatedSecret(old.Id, SecretKind.PreSharedKey, old.Name));
            }

            // Ключ SSH принадлежит устройству, а не серверу: смена адреса его не трогает (серверу уходит только
            // подпись, сам ключ никуда не передаётся). Удаляется вместе с подключением или при смене его типа.
            if ((next is null || !VpnProtocols.NeedsSshKey(next)) && VpnProtocols.NeedsSshKey(old))
            {
                secrets.Add(new OutdatedSecret(old.Id, SecretKind.SshPrivateKey, old.Name));
            }

            // Без подтверждения пароль не переходит к другому серверу, протоколу или учётной записи.
            var bindingChanged = next is null || (!reuse && ConnectionEdits.PasswordBindingChanged(old, next)) || !VpnProtocols.NeedsPassword(next.AuthMethod);
            var stillNeeded = next is not null && VpnProtocols.NeedsPassword(next.AuthMethod);
            var noLongerSaved = next is not { SavePassword: true };
            // Записанный, но сейчас нечитаемый пароль тоже считается сохранённым: иначе выключенное «сохранять пароль»
            // оставило бы его в файле, и после включения он ожил бы снова. Такой пароль проходит через DeleteSecrets:
            // сохранение ждёт UnreadableSecretGrace, а потом удаляет его без копии.
            var passwordSaved = (noLongerSaved || (bindingChanged && stillNeeded)) && SecretKept(old.Id, SecretKind.Password);
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

    /// <summary>Секрет есть: читается или записан, но сейчас не расшифровывается (Contains читает его через DPAPI).</summary>
    private bool SecretKept(Guid profileId, SecretKind kind) =>
        _deps.Secrets.Contains(profileId, kind) || _deps.Secrets.IsStored(profileId, kind);

    /// <summary>
    /// Сколько секрет может не читаться, прежде чем сохранение удалит его без копии. Сбой DPAPI при загрузке
    /// (LSA, RPC) проходит за секунды; секрет, который не читается дольше, считается потерянным навсегда.
    /// </summary>
    internal static readonly TimeSpan UnreadableSecretGrace = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Перерыв между сохранениями, заставшими секрет нечитаемым, после которого отсчёт начинается заново: в перерыве
    /// секрет мог читаться и работать, и разовый сбой DPAPI позже не должен удалить его сразу. Вдвое больше
    /// <see cref="UnreadableSecretGrace"/>: повтор «через несколько минут» после первого отказа отсчёт не сбрасывает.
    /// </summary>
    internal static readonly TimeSpan UnreadableSecretGap = UnreadableSecretGrace * 2;

    /// <summary>Первое и последнее сохранение подряд, заставшие секрет нечитаемым: метки монотонных часов.</summary>
    private readonly record struct UnreadableSighting(long First, long Last);

    /// <summary>
    /// С какого времени сохранения подряд застают секрет записанным, но нечитаемым. Время монотонное: Windows
    /// поправляет системные часы сразу после загрузки (при двух системах или снимке виртуальной машины - на часы),
    /// и по ним временно нечитаемый секрет удалился бы раньше срока. Только в памяти: после перезапуска службы
    /// отсчёт начинается заново, и временный сбой при загрузке снова защищён.
    /// </summary>
    private readonly Dictionary<(Guid ProfileId, SecretKind Kind), UnreadableSighting> _unreadableSecrets = [];

    /// <summary>
    /// Удаляет секреты, оставляя копии в <paramref name="backups"/>. Секрет, которого нет или который не
    /// расшифруется никогда (чужой компьютер), удаляется без копии: возвращать нечего. Секрет, который записан,
    /// но сейчас не читается (LSA или RPC ещё не готовы при загрузке), без копии не удаляется: тогда ничего
    /// не удаляется, и возвращается этот секрет - сохранение нужно повторить позже. Если же секрет не читается
    /// подряд дольше <see cref="UnreadableSecretGrace"/>, сбой считается постоянным (DPAPI вернул код, которого нет
    /// среди постоянных, или нерасшифровываемое значение не удалось отложить в копию): такой секрет удаляется
    /// здесь же, до записи настроек, но без копии - при сбое записи настроек его уже не вернуть. Откладывать
    /// удаление на после записи нельзя: если оно не состоится, а DPAPI потом оживёт, прежний пароль уйдёт новому серверу.
    /// </summary>
    private OutdatedSecret? DeleteSecrets(List<OutdatedSecret> secrets, List<SecretBackup> backups)
    {
        // Сначала читаются все копии, и только потом что-то удаляется: недоступный секрет останавливает
        // сохранение до первого удаления.
        // Отсчёт идёт для всех нечитаемых сразу, а не только для первого: иначе каждый следующий ждал бы своей очереди.
        var now = _deps.Time.GetTimestamp();
        ForgetStaleSightings(now);
        var lost = new HashSet<(Guid ProfileId, SecretKind Kind)>();
        OutdatedSecret? blocked = null;
        foreach (var secret in secrets)
        {
            var key = (secret.ProfileId, secret.Kind);
            var value = _deps.Secrets.TryLoad(secret.ProfileId, secret.Kind);
            if (value is not null)
            {
                _unreadableSecrets.Remove(key);
                // Удаление может завершиться ошибкой уже после записи основного файла.
                backups.Add(new SecretBackup(secret.ProfileId, secret.Kind, secret.ProfileName, value));
            }
            else if (_deps.Secrets.IsStored(secret.ProfileId, secret.Kind))
            {
                var since = _unreadableSecrets.TryGetValue(key, out var seen) ? seen.First : now;
                _unreadableSecrets[key] = new UnreadableSighting(since, now);
                if (_deps.Time.GetElapsedTime(since, now) >= UnreadableSecretGrace)
                {
                    lost.Add(key);
                }
                else
                {
                    blocked ??= secret;
                }
            }
            else
            {
                _unreadableSecrets.Remove(key);
            }
        }

        if (blocked is not null)
        {
            return blocked;
        }

        // Сбой удаления прерывает сохранение (SaveSettingsAsync): отметка нечитаемого остаётся, и следующее
        // сохранение снова удалит потерянный секрет без ожидания.
        foreach (var secret in secrets)
        {
            var key = (secret.ProfileId, secret.Kind);
            _deps.Secrets.Delete(secret.ProfileId, secret.Kind);
            _unreadableSecrets.Remove(key);
            if (lost.Contains(key))
            {
                var what = SecretName(secret.Kind);
                Journal("Предупреждение", $"Удалён {what} «{secret.ProfileName}»: Windows не может расшифровать его уже несколько минут, "
                    + "копию сохранить нельзя - он не вернётся, даже если настройки не сохранятся. При необходимости введите его заново.");
            }
        }

        return null;
    }

    /// <summary>
    /// Забывает отсчёт, если секрет давно не застигали нечитаемым (в перерыве он мог читаться и работать) или
    /// профиля уже нет: иначе давняя отметка позже позволила бы удалить секрет при разовом сбое без всякого ожидания.
    /// </summary>
    private void ForgetStaleSightings(long now)
    {
        foreach (var key in _unreadableSecrets.Keys.ToList())
        {
            if (_deps.Time.GetElapsedTime(_unreadableSecrets[key].Last, now) >= UnreadableSecretGap || _settings.Profile(key.ProfileId) is null)
            {
                _unreadableSecrets.Remove(key);
            }
        }
    }

    /// <summary>
    /// Записан или удалён новый секрет: отсчёт нечитаемости прежнего снимается, иначе временный сбой DPAPI
    /// с новым секретом унаследовал бы чужой срок и удалил бы его без ожидания.
    /// </summary>
    private void SecretReplaced(Guid profileId, SecretKind kind) => _unreadableSecrets.Remove((profileId, kind));

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
                var what = SecretName(secret.Kind);
                Journal("Ошибка", $"Не удалось вернуть {what} «{secret.ProfileName}» после сбоя сохранения настроек - введите его заново: {ex.Message}");
            }
        }
    }

    private async Task<IpcResponse?> ValidateSshKeyAsync(SaveConnectionRequest request, ConnectionProfile profile, CancellationToken cancellationToken)
    {
        // Ключ проверяется до записи настроек: непригодный файл не должен оставить подключение без ключа.
        if (request.SshPrivateKey is { Length: > 0 } candidate
            && Core.SshTunnel.SshPrivateKey.Check(candidate) is var check and not Core.SshTunnel.SshPrivateKeyCheck.Ok)
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, Core.SshTunnel.SshPrivateKey.Describe(check));
        }

        if (request.SshPrivateKey is { Length: > 0 } newKey)
        {
            if (!Core.SshTunnel.SshHostKey.TryParse(profile.SshVpn?.HostKey, out var hostKey))
            {
                return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Некорректный ключ сервера SSH.");
            }

            var parameters = new Core.SshTunnel.SingBoxParameters
            {
                HostKey = hostKey, User = profile.UserName, Server = Ipv4.Parse("127.0.0.1"),
                Port = 22, InterfaceName = Core.SshTunnel.SshTunnelDefaults.InterfaceName(profile.Id),
            };
            try
            {
                if (!await _deps.SshTunnel.CanReadKeyAsync(parameters, newKey, cancellationToken))
                {
                    return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Движок не смог прочитать ключ SSH. Прежний ключ сохранён.");
                }
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested && ex is IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException or OperationCanceledException or InvalidOperationException)
            {
                return IpcResponse.Failure(IpcErrorCodes.Failed, "Проверка ключа SSH не завершилась. Прежний ключ сохранён.");
            }
        }

        return null;
    }

    /// <summary>Сохраняет профиль и его секреты одним действием актора, до запуска дозвона.</summary>
    private async Task<IpcResponse> SaveConnectionAsync(SaveConnectionRequest request, CancellationToken cancellationToken, bool keyChecked = false)
    {
        if (request.ExpectedRevision is { } revision && revision != SettingsSerializer.Revision(_settings))
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Настройки изменились. Повторите команду с актуальными данными.");

        var profile = request.Settings.Profiles.FirstOrDefault(p => p.Id == request.ProfileId);
        if (profile is null || request.Password is { Length: > 256 } || request.PreSharedKey is { Length: > 256 }
            || request.Password?.Contains('\0') == true || request.PreSharedKey?.Contains('\0') == true
            || (request.Password is not null && !VpnProtocols.NeedsPassword(profile.AuthMethod))
            || (request.PreSharedKey is not null && !VpnProtocols.NeedsPreSharedKey(profile))
            || (request.SshPrivateKey is not null && !VpnProtocols.NeedsSshKey(profile)))
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Недопустимые параметры входа или ключа IPsec.");
        }

        if (!keyChecked && await ValidateSshKeyAsync(request, profile, cancellationToken) is { } validation) return validation;

        var previous = _settings;
        // Повторное использование разрешено только для явно подтверждённой и ещё актуальной привязки.
        // Остальные профили в том же запросе по-прежнему теряют секреты при смене привязки.
        if (request.ReuseCredentialsFrom is { } source &&
            (source.Id != request.ProfileId || previous.Profile(request.ProfileId) is not { } current ||
             ConnectionEdits.PasswordBindingChanged(source, current)))
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Параметры входа уже изменились. Откройте подключение заново и повторите сохранение.");
        }

        // Без ключа IPsec профиль L2TP/PSK не дозвонится вовсе: использовать прежний ключ можно, только если он есть.
        // Сохранённого пароля может и не быть (его вводят при подключении): тогда переносить нечего, и пароль,
        // как и раньше, спросят при дозвоне - это не ошибка.
        if (request.ReuseCredentialsFrom is not null
            && VpnProtocols.NeedsPreSharedKey(profile) && request.PreSharedKey is not { Length: > 0 }
            && !_deps.Secrets.IsStored(profile.Id, SecretKind.PreSharedKey))
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, $"У подключения «{profile.Name}» нет сохранённого ключа IPsec: введите общий ключ IPsec и сохраните ещё раз.");
        }

        var result = await SaveSettingsAsync(request.Settings, cancellationToken, reconcile: false,
            reuseCredentials: request.ReuseCredentialsFrom is null ? null : request.ProfileId);
        if (!result.Ok)
        {
            return result;
        }

        // Настройки уже записаны: сбой записи секрета не должен отменять переподключение туннелей, у которых
        // сменился сервер, иначе туннель остался бы на старом сервере (следующее сохранение разницы уже не увидит).
        // Ошибка секрета возвращается в конце, чтобы интерфейс показал, что вход не сохранён.
        IpcResponse? secretFailure = null;
        var secretChanged = false;
        if (request.Password is { } password)
        {
            var passwordResult = SetPassword(profile.Id, password);
            if (passwordResult.Ok) { secretChanged = true; }
            else { secretFailure = passwordResult; }
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
                SecretReplaced(profile.Id, SecretKind.PreSharedKey);
                secretChanged = true;
            }
            catch (Exception ex) when (IsSecretWriteFailure(ex))
            {
                _deps.Logger.LogWarning(ex, "Ключ IPsec для {Name} не сохранён", profile.Name);
                secretFailure ??= IpcResponse.Failure(IpcErrorCodes.Failed, $"Не удалось сохранить ключ IPsec для «{profile.Name}»: {ex.Message}");
            }
        }

        if (request.SshPrivateKey is { } sshKey)
        {
            try
            {
                if (sshKey.Length == 0)
                {
                    _deps.Secrets.Delete(profile.Id, SecretKind.SshPrivateKey);
                }
                else
                {
                    _deps.Secrets.Save(profile.Id, sshKey, SecretKind.SshPrivateKey);
                }

                SecretReplaced(profile.Id, SecretKind.SshPrivateKey);
                secretChanged = true;
                Journal("Сведения", sshKey.Length == 0 ? $"Ключ SSH для «{profile.Name}» удалён." : $"Ключ SSH для «{profile.Name}» сохранён.");
            }
            catch (Exception ex) when (IsSecretWriteFailure(ex))
            {
                _deps.Logger.LogWarning(ex, "Ключ SSH для {Name} не сохранён", profile.Name);
                secretFailure ??= IpcResponse.Failure(IpcErrorCodes.Failed, $"Не удалось сохранить ключ SSH для «{profile.Name}»: {ex.Message}");
            }
        }

        // Новые данные входа применяются только после переподключения этого туннеля.
        if (secretChanged
            && Facts.Tunnels.GetValueOrDefault(profile.Id) is { } tunnel)
        {
            if (tunnel.HasSession)
            {
                tunnel.ReconnectRequired = true;
                try
                {
                    await HangUpAsync(tunnel, "изменены данные входа", cancellationToken);
                    tunnel.ReconnectRequired = false;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // Настройки и данные входа уже записаны. Флаг ReconnectRequired остаётся, и сверка повторит
                    // разрыв; смена сервера ниже всё равно должна сбросить адреса прежнего сервера.
                    _deps.Logger.LogWarning(ex, "Изменены данные входа {Name}: соединение не разорвано, повтор при сверке", tunnel.Name);
                }
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

    /// <summary>
    /// Ожидаемые сбои записи секрета: диск, права и DPAPI. Отказ CryptProtectData приходит как
    /// NativeCallException, а не CryptographicException: без него ошибка ушла бы мимо обработки уже после
    /// записи настроек, и переподключение к новому серверу не выполнилось бы.
    /// </summary>
    private static bool IsSecretWriteFailure(Exception ex) => ex is IOException or UnauthorizedAccessException
        or System.Security.Cryptography.CryptographicException or SplitVpn.Windows.Native.NativeCallException;

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
                SecretReplaced(profileId, SecretKind.Password);
            }
            catch (Exception ex) when (IsSecretWriteFailure(ex))
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

        // Сбой записи ключа (диск, права, DPAPI) - понятная ошибка клиенту: ничего ещё не изменено, сверка не прерывалась,
        // и «неполное применение» здесь было бы ложным (как в SaveConnectionAsync).
        try
        {
            if (request.Key.Length == 0)
            {
                _deps.Secrets.Delete(profile.Id, SecretKind.PreSharedKey);
            }
            else
            {
                _deps.Secrets.Save(profile.Id, request.Key, SecretKind.PreSharedKey);
            }
        }
        catch (Exception ex) when (IsSecretWriteFailure(ex))
        {
            _deps.Logger.LogWarning(ex, "Ключ IPsec для {Name} не сохранён", profile.Name);
            return IpcResponse.Failure(IpcErrorCodes.Failed, $"Не удалось сохранить ключ IPsec для «{profile.Name}»: {ex.Message}");
        }

        SecretReplaced(profile.Id, SecretKind.PreSharedKey);
        if (Facts.Tunnels.GetValueOrDefault(profile.Id) is { } tunnel)
        {
            // Новый ключ уже записан: повторная сверка должна применить его даже после отказа RAS.
            tunnel.ReconnectRequired = true;
            if (tunnel.HasSession)
            {
                await HangUpAsync(tunnel, "изменён ключ IPsec", cancellationToken);
            }

            try
            {
                // Запись с прежним ключом убирается сразу; не вышло - не беда: перед дозвоном запись готовится
                // заново (PrepareEntry) и получает уже новый ключ.
                _deps.Ras.DeleteEntry(tunnel.EntryName);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _deps.Logger.LogWarning(ex, "Изменён ключ IPsec {Name}: прежняя запись телефонной книги не удалена, она будет переписана перед дозвоном", tunnel.Name);
            }

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

            if (request.Password is { } profilePassword && SetPassword(id, profilePassword) is { Ok: false } refused)
            {
                return refused;
            }

            // AnyConnect не бывает опорным: включается дополнительным.
            var anyConnect = _settings.Profile(id)!.Protocol == VpnProtocol.AnyConnect;
            if (_settings.Profile(id)!.Role == ProfileRole.Off)
            {
                var assigned = await SetProfileRoleAsync(id, anyConnect ? ProfileRole.Secondary : ProfileRole.Primary, cancellationToken);
                if (!assigned.Ok)
                {
                    return assigned;
                }
            }

            if (anyConnect) Facts.SignInApproved.Add(id);
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
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => request.ProfileId is null || request.ProfileId == t.ProfileId))
        {
            tunnel.BlockingError = ErrorCategory.None;
            tunnel.NextDialAt = now;
            if (!tunnel.Dialing && !tunnel.HasSession)
            {
                tunnel.DialSettled = false;
                tunnel.DialStartedUtc = null;
            }
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

        return await ChangeIntentAsync(Intent.Connected, cancellationToken, request.ProfileId);
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
        if (TrySaveSettings(settings, "Порядок подключений не сохранён") is { } failed)
        {
            return failed;
        }

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
        if (TrySaveSettings(settings, "Роль подключения не изменена") is { } failed)
        {
            return failed;
        }

        _settings = settings;
        Journal("Сведения", $"«{settings.Profile(profileId)!.Name}»: роль — {RoleName(role)}.");
        await ReconnectChangedEndpointsAsync(previous, cancellationToken);
        await ReconcileAsync(cancellationToken);
        return IpcResponse.Success(BuildStatus());
    }

    /// <summary>
    /// Запись настроек для команды, которая меняет только их: сбой записи (диск заполнен, файл занят, нет доступа) —
    /// понятный отказ клиенту. Ничего ещё не изменено, поэтому «неполное применение» и внеочередная сверка были бы ложью.
    /// </summary>
    private IpcResponse? TrySaveSettings(AppSettings settings, string what)
    {
        try
        {
            _deps.Stores.SaveSettings(settings);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Journal("Ошибка", $"{what}: не удалось записать файл настроек — {ex.Message}");
            return IpcResponse.Failure(IpcErrorCodes.Failed, $"{what}: не удалось записать файл настроек (диск заполнен, файл занят или нет доступа). {ex.Message}");
        }
    }

    private static string RoleName(ProfileRole role) => role switch
    {
        ProfileRole.Primary => "опорное",
        ProfileRole.Secondary => "дополнительное",
        _ => "выключено",
    };

    private bool _recoveryWritePending;

    internal async Task<IpcResponse> ChangeIntentAsync(Intent intent, CancellationToken cancellationToken, Guid? profileId = null, bool recoverNetwork = false)
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
        var forceProtection = false;
        if (intent == Intent.Off && _settingsReadError is not null)
        {
            next = next with { AutoConnectBootUtc = BootTime() };
            forceProtection = true;
        }
        string? saveFailure = null;
        try
        {
            _deps.Stores.SaveState(next);
            _recoveryWritePending = false;
        }
        catch (Exception ex) when (recoverNetwork && ex is IOException or UnauthorizedAccessException)
        {
            _recoveryWritePending = true;
            saveFailure = $"Состояние восстановления не записано: {ex.Message}";
            Journal("Ошибка", saveFailure);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Обычная команда не записана: сеть и намерение остаются прежними, сверка не прерывалась — понятный
            // отказ, а не «неполное применение» с внеочередной сверкой.
            Journal("Ошибка", $"Команда не выполнена: не удалось записать файл состояния — {ex.Message}");
            return IpcResponse.Failure(IpcErrorCodes.Failed,
                $"Команда не выполнена: не удалось записать файл состояния (диск заполнен, файл занят или нет доступа). {ex.Message}");
        }

        if (forceProtection)
        {
            Facts.ForceProtection = true;
        }

        foreach (var tunnel in Facts.Tunnels.Values.Where(t => profileId is null || t.ProfileId == profileId))
        {
            tunnel.ExternallyDisconnected = false;
        }

        if (intent != Intent.Connected)
        {
            Facts.SignInApproved.Clear();
        }

        _state = next;
        if (recoverNetwork) { Facts.ForceProtection = true; }
        await ReconcileAsync(cancellationToken);
        var orphanProblems = new List<string>();
        if (recoverNetwork)
        {
            // Как у команды восстановления без службы: адаптеры, на которых наш DNS остался без копии (копия потеряна или
            // повреждена), возвращаются на «автоматически», иначе после восстановления имена на них не разрешались бы.
            try
            {
                ResetOrphanDns(serviceStopped: false, ourSuffixes: null, orphanProblems);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                orphanProblems.Add("DNS: " + ex.Message);
            }

            if (_dnsFlushPending)
            {
                _dnsFlushPending = false;
                FlushDnsCacheSafely("восстановление сети");
            }
        }

        if (recoverNetwork && (Facts.PartialError is not null || orphanProblems.Count > 0))
        {
            var parts = new[] { saveFailure, Facts.PartialError, orphanProblems.Count > 0 ? "DNS без копии: " + string.Join("; ", orphanProblems) : null };
            return IpcResponse.Failure(IpcErrorCodes.RecoveryIncomplete, string.Join(Environment.NewLine, parts.OfType<string>()));
        }
        return saveFailure is null ? IpcResponse.Success(BuildStatus()) : IpcResponse.Failure(IpcErrorCodes.Failed, saveFailure);
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
        var blocked = _state.Intent != Intent.Off && !_state.ProtectionSuspended && (classification.Decision == Decision.Block
            || (classification.Decision == Decision.Vpn && Facts.Tunnels.GetValueOrDefault(classification.Tunnel)?.Luid is null
                && !DirectOnOutage(classification.Tunnel)));
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
            .OrderByDescending(r => SettingsSerializer.EffectivePriority(r.Rule.Priority, r.Rule.FolderId, _settings.RoutingFolders))
            .ThenByDescending(r => r.Suffix.Length)
            .Select(r => r.Rule)
            .FirstOrDefault();
    }

    private string TargetNameFor(Classification classification) => classification.Decision switch
    {
        Decision.Vpn => _settings.TargetName(_settings.Group(classification.Tunnel) is not null
            ? RouteTarget.Group(classification.Tunnel) : RouteTarget.Tunnel(classification.Tunnel)),
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

    private IpcResponse ExportReport(bool mask) => ExportReport(mask, BuildStatus(), Adapters());

    /// <summary>Сколько последних событий журнала остаётся в отчёте, если полный не помещается в кадр канала.</summary>
    internal const int ReportFallbackEvents = 100;

    /// <summary>
    /// Отчёт по готовым состоянию и адаптерам: вне очереди актора он собирается из последнего снимка — журнал
    /// событий потокобезопасен, настройки заменяются целиком. Отчёт — компактный JSON строкой в ответе (её разбирает
    /// и форматирует для файла клиент); сети шлюзов в состоянии уже сокращены до числа и первых
    /// <see cref="ServerNetworksDto.MaxStatusNetworks"/>. Не помещается в кадр — остаются последние
    /// <see cref="ReportFallbackEvents"/> событий, не помещается и так — понятный отказ с советом собрать архив.
    /// </summary>
    private IpcResponse ExportReport(bool mask, StatusDto status, IReadOnlyList<AdapterDto> adapters)
    {
        var events = _deps.Journal.Since(0);
        var report = BuildReport(mask, status, adapters, events, null);
        if (FitsFrame(report))
        {
            return IpcResponse.Success(report);
        }

        var recent = events.Skip(Math.Max(0, events.Count - ReportFallbackEvents)).ToList();
        report = BuildReport(mask, status, adapters, recent, string.Create(CultureInfo.InvariantCulture,
            $"Отчёт сокращён: из {events.Count} событий журнала в него вошли последние {recent.Count}. Полный журнал — в архиве для разбора («Диагностика»)."));
        return FitsFrame(report)
            ? IpcResponse.Success(report)
            : IpcResponse.Failure(IpcErrorCodes.Failed, string.Create(CultureInfo.InvariantCulture,
                $"Отчёт больше {FrameCodec.MaxFrameMegabytes} МБ и не может быть передан. Соберите архив для разбора в «Диагностике»: в нём полное состояние и журнал."));
    }

    private static bool FitsFrame(string report) =>
        IpcSerializer.SerializeResponse(IpcResponse.Success(report)).Length <= FrameCodec.MaxFrameBytes;

    private string BuildReport(bool mask, StatusDto status, IReadOnlyList<AdapterDto> adapters, IReadOnlyList<ServiceEvent> events, string? note)
    {
        var settings = _settings;
        var report = JsonSerializer.Serialize(new
        {
            generatedUtc = _deps.Time.GetUtcNow(),
            note,
            status = WithoutUrlSecrets(status),
            adapters,
            events,
        }, JsonDefaults.Compact);
        // Маскирование идёт по строковым значениям разобранного JSON, а не по тексту: кавычка или косая черта
        // в названии профиля не ломают структуру. Названия профилей, групп и адаптеров тоже личные. Журнал
        // событий помнит и прежние названия и серверы — они маскируются по настройкам, бывшим с запуска службы.
        if (!mask) return report;
        var personal = PersonalValues(settings)
            .Concat(_formerPersonalValues.Keys)
            .Concat(status.Tunnels.SelectMany(TunnelPersonalNames))
            .Concat(_gatewayNodeHosts.Keys)
            .Concat(adapters.Select(a => a.Name))
            .Concat(adapters.Select(a => a.Description))
            .OfType<string>()
            .Where(s => s.Length > 0)
            .ToList();
        return Redactor.RedactJson(report, personal, JsonDefaults.Compact);
    }

    /// <summary>
    /// Личные значения настроек, сменённых с запуска службы (названия, серверы, учётные записи): журнал событий
    /// хранит записи о переименованных и удалённых подключениях, и отчёт маскирует их и после смены настроек.
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _formerPersonalValues = new(StringComparer.Ordinal);

    private void RememberPersonalValues(AppSettings settings)
    {
        var retained = _deps.Journal.Since(0);
        var oldest = retained.Count == 0 ? long.MaxValue : retained[0].Id;
        foreach (var item in _formerPersonalValues.Where(item => item.Value < oldest))
        {
            var lastReference = retained.LastOrDefault(e => e.Text.Contains(item.Key, StringComparison.OrdinalIgnoreCase));
            if (lastReference is null) _formerPersonalValues.TryRemove(item.Key, out _);
            else _formerPersonalValues[item.Key] = lastReference.Id;
        }
        foreach (var value in PersonalValues(settings))
        {
            _formerPersonalValues[value] = retained.Count == 0 ? 0 : retained[^1].Id;
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
    private IpcResponse CollectDiagnostics(CancellationToken cancellationToken, bool serviceDirectoryPrefix = false)
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
            package = packages.Create(stream => collector.Write(stream, parts, cancellationToken, serviceDirectoryPrefix));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Нет места на диске, каталог недоступен: клиент получает причину, а не обрыв канала.
            _deps.Logger.LogWarning(ex, "Архив для разбора не собран");
            return IpcResponse.Failure(IpcErrorCodes.Failed, "Архив не собран: " + ex.Message);
        }

        return package is null
            ? IpcResponse.Failure(IpcErrorCodes.Busy, "Архив уже собирается: дождитесь окончания.")
            : IpcResponse.Success(package with { ServiceDirectoryPrefix = serviceDirectoryPrefix });
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
