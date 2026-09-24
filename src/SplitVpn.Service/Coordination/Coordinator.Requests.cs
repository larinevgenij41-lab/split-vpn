using System.Globalization;
using System.Net;
using System.Net.Sockets;
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
                a.DefaultGateway is { } g ? Ipv4.Format(g) : null, a.Luid == Facts.Primary?.Luid))
            .ToList();
    }

    private async Task<IpcResponse> SaveSettingsAsync(AppSettings settings, CancellationToken cancellationToken, bool reconcile = true)
    {
        if (Facts.Tunnels.Values.Any(t => t.Dialing) || Facts.ProfileTestRunning)
        {
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Дождитесь завершения дозвона перед изменением настроек.");
        }

        var validation = SettingsValidator.Validate(settings);
        if (!validation.IsValid)
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, string.Join(Environment.NewLine, validation.Errors));
        }

        var connected = Facts.Tunnels.Values.Where(t => t.IsUp).ToList();
        if (connected.Find(t => settings.Profiles.All(p => p.Id != t.ProfileId)) is { } removed)
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, $"Нельзя удалить подключение «{removed.Name}»: оно сейчас активно.");
        }

        var previous = _settings;
        _deps.Stores.SaveSettings(settings);
        var removedSecrets = _settings.Profiles.Where(old => settings.Profiles.FirstOrDefault(p => p.Id == old.Id) is not { SavePassword: true })
            .Where(old => _deps.Secrets.Contains(old.Id)).ToList();
        foreach (var old in _settings.Profiles)
        {
            var next = settings.Profiles.FirstOrDefault(p => p.Id == old.Id);
            if (next is null || !VpnProtocols.NeedsPreSharedKey(next) || ConnectionEdits.PreSharedKeyBindingChanged(old, next))
            {
                if (next is not null && VpnProtocols.NeedsPreSharedKey(next) && _deps.Secrets.Contains(old.Id, SecretKind.PreSharedKey))
                {
                    Journal("Сведения", $"Ключ IPsec «{old.Name}» удалён: изменились сервер или протокол — введите ключ заново.");
                }

                _deps.Secrets.Delete(old.Id, SecretKind.PreSharedKey);
            }

            // Пароль не переходит к другому серверу, протоколу, способу входа или учётной записи.
            if (next is null || ConnectionEdits.PasswordBindingChanged(old, next) || !VpnProtocols.NeedsPassword(next.AuthMethod))
            {
                if (next is not null && VpnProtocols.NeedsPassword(next.AuthMethod) && _deps.Secrets.Contains(old.Id))
                {
                    Journal("Сведения", $"Сохранённый пароль «{old.Name}» удалён: изменились сервер, протокол, способ входа или учётная запись — введите пароль заново.");
                }

                _deps.Secrets.Delete(old.Id);
                if (Facts.MemoryPasswordProfile == old.Id && Facts.MemoryPassword is { } memory)
                {
                    Array.Clear(memory); Facts.MemoryPassword = null; Facts.MemoryPasswordProfile = null;
                }
            }
        }
        _settings = settings;
        foreach (var profile in removedSecrets)
        {
            _deps.Secrets.Delete(profile.Id);
            Journal("Сведения", $"Сохранённый пароль «{profile.Name}» удалён: профиль удалён или пароль больше не сохраняется.");
        }

        Journal("Сведения", "Настройки сохранены.");
        if (reconcile)
        {
            await ReconnectChangedEndpointsAsync(previous, cancellationToken);
            await ReconcileAsync(cancellationToken);
        }

        return IpcResponse.Success(validation.Warnings);
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

        if (request.Password is { } password)
        {
            SetPassword(profile.Id, password);
        }

        if (request.PreSharedKey is { } key)
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

        // Новые данные входа применяются только после переподключения этого туннеля.
        if ((request.PreSharedKey is not null || request.Password is not null)
            && Facts.Tunnels.GetValueOrDefault(profile.Id) is { } tunnel)
        {
            if (tunnel.HasSession)
            {
                await HangUpAsync(tunnel, "изменены данные входа", cancellationToken);
            }

            tunnel.BlockingError = ErrorCategory.None;
            tunnel.NextDialAt = _deps.Time.GetUtcNow();
            RetryFromScratch(tunnel);
        }

        await ReconnectChangedEndpointsAsync(previous, cancellationToken);
        await ReconcileAsync(cancellationToken);
        return result;
    }

    /// <summary>Переподключает туннели, у которых изменились адрес сервера или учётные данные.</summary>
    private async Task ReconnectChangedEndpointsAsync(AppSettings previous, CancellationToken cancellationToken)
    {
        ForgetChangedServers(previous);
        foreach (var tunnel in Facts.Tunnels.Values.ToList())
        {
            var before = previous.Profile(tunnel.ProfileId);
            var after = _settings.Profile(tunnel.ProfileId);
            var changed = before is null || after is null || VpnProtocols.ConnectionKey(before) != VpnProtocols.ConnectionKey(after);
            if (!changed)
            {
                continue;
            }

            tunnel.BlockingError = ErrorCategory.None;
            tunnel.ServerAddresses = [];
            RetryFromScratch(tunnel);
            if (tunnel.HasSession)
            {
                await HangUpAsync(tunnel, "изменены параметры подключения", cancellationToken);
                tunnel.NextDialAt = _deps.Time.GetUtcNow();
            }
        }
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
        _deps.Stores.SaveState(_state);
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => changed.Contains(t.ProfileId)))
        {
            tunnel.ServerAddresses = [];
            tunnel.ServerResolvedUtc = default;
            tunnel.FailedDialsSinceResolve = 0;
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

        if (!VpnProtocols.NeedsPassword(profile.AuthMethod)) { return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Для этого способа входа пароль не используется."); }

        if (profile.SavePassword)
        {
            _deps.Secrets.Save(profileId, password);
            if (Facts.MemoryPasswordProfile == profileId && Facts.MemoryPassword is { } old)
            {
                Array.Clear(old); Facts.MemoryPassword = null; Facts.MemoryPasswordProfile = null;
            }
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
            if (tunnel.HasSession)
            {
                await HangUpAsync(tunnel, "изменён ключ IPsec", cancellationToken);
            }

            _deps.Ras.DeleteEntry(tunnel.EntryName);
            tunnel.AppliedEntryServer = null;
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
        if (Facts.MemoryPassword is { } old)
        {
            Array.Clear(old);
        }

        Facts.MemoryPassword = password.ToCharArray();
        Facts.MemoryPasswordProfile = profileId;
    }

    private async Task<IpcResponse> ConnectAsync(ConnectRequest request, CancellationToken cancellationToken)
    {
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

            if (request.Password is { } profilePassword)
            {
                SetPassword(id, profilePassword);
            }
        }
        else
        {
            if (request.Password is { } password && PasswordRecipient() is { } recipient)
            {
                SetPassword(recipient.Id, password);
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
            await HangUpAsync(tunnel, "отключено вами", cancellationToken);
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
        if (role == ProfileRole.Primary && !settings.DefaultTarget.IsVpn)
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

        foreach (var tunnel in Facts.Tunnels.Values)
        {
            tunnel.ExternallyDisconnected = false;
        }

        if (intent != Intent.Connected)
        {
            Facts.SignInApproved.Clear();
        }

        _state = _state with { Intent = intent, ProtectionSuspended = false };
        _deps.Stores.SaveState(_state);
        await ReconcileAsync(cancellationToken);
        return IpcResponse.Success(BuildStatus());
    }

    private async Task<AddressCheckDto> CheckAddressAsync(string query, CancellationToken cancellationToken)
    {
        var addresses = await ResolveForCheckAsync(query.Trim(), cancellationToken);
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
                && _state.Intent != Intent.Off && _settings.OutageMode != OutageMode.AllowAll);
        return new AddressCheckItem(
            Ipv4.Format(address),
            classification.Decision.ToString(),
            classification.Source.ToString(),
            TargetNameFor(classification),
            expected,
            actual,
            blocked,
            Explain(classification, domain));
    }

    /// <summary>Правило для домена с самым длинным подходящим суффиксом.</summary>
    private DomainRuleSetting? MatchingDomainRule(string query)
    {
        if (Ipv4.TryParse(query, out _))
        {
            return null;
        }

        var name = query.Trim().Trim('.').ToLowerInvariant();
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

    private string Explain(Classification classification, DomainRuleSetting? domain)
    {
        if (domain is not null)
        {
            return $"Правило для домена «{domain.Suffix}» ({_settings.TargetName(domain.Target)}); маршрут ставится на время TTL ответа DNS.";
        }

        return classification.Source switch
        {
            DecisionSource.Geo => "Адрес есть в RU-базе — " + _settings.TargetName(_settings.GeoTarget) + ".",
            DecisionSource.Bypass => "Адрес есть в списке обхода блокировок — " + _settings.TargetName(BypassTarget) + ".",
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
            status,
            adapters,
            events = _deps.Journal.Since(0),
        }, JsonDefaults.Options);
        // Маскирование идёт по готовому JSON: обратная косая черта там удвоена («CORP\\user»), поэтому
        // значения ищутся и в исходном, и в экранированном виде. Названия профилей, групп и адаптеров тоже личные.
        var personal = settings.Profiles.SelectMany(p => new[] { p.UserName, p.Server, p.Domain, p.Name })
            .Concat(settings.Groups.Select(g => g.Name))
            .Concat(adapters.Select(a => a.Name))
            .Concat(adapters.Select(a => a.Description))
            .OfType<string>()
            .Where(s => s.Length > 0)
            .ToList();
        var secrets = personal.Concat(personal.Where(s => s.Contains('\\', StringComparison.Ordinal)).Select(s => s.Replace("\\", "\\\\", StringComparison.Ordinal)));
        return mask ? Redactor.Redact(report, secrets) : report;
    }
}
