using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Core.Update;

namespace SplitVpn.Cli;

/// <summary>
/// Управление установленной службой через канал IPC. Работает без повышения: служба принимает команды
/// администратора интерактивного сеанса и в фильтрованном UAC-токене.
/// </summary>
internal static class ServiceCommands
{
    private const string ServiceName = "SplitVpn";

    public static Task<int> StatusAsync(CliArgs args) => WithClientAsync(async client =>
    {
        var status = Expect<StatusDto>(await SendAsync(client, new GetStatusRequest()));
        if (args.Flag("--json"))
        {
            Console.WriteLine(JsonSerializer.Serialize(status, JsonDefaults.Options));
            return 0;
        }

        PrintStatus(status);
        return 0;
    });

    public static Task<int> EventsAsync(CliArgs args) => WithClientAsync(async client =>
    {
        long since = 0;
        if (args.Option("--since") is { } raw && (!long.TryParse(raw, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out since) || since < 0))
        {
            Console.Error.WriteLine("--since требует неотрицательный номер события.");
            return 2;
        }
        var events = Expect<List<ServiceEvent>>(await SendAsync(client, new GetEventsRequest(since)));
        foreach (var e in events.TakeLast(args.IntOption("--last", 50)))
        {
            Console.WriteLine(Text.Inv($"{e.Id,5} {e.TimeUtc.ToLocalTime():dd.MM HH:mm:ss} {e.Level,-8} {e.Text}"));
        }

        return 0;
    });

    public static Task<int> AdaptersAsync(CliArgs args) => WithClientAsync(async client =>
    {
        foreach (var a in Expect<List<AdapterDto>>(await SendAsync(client, new GetAdaptersRequest())))
        {
            Console.WriteLine($"{(a.IsPrimary ? "*" : " ")} {a.Name} [{a.Type}] шлюз {a.Gateway ?? "—"} {a.InterfaceGuid}");
        }

        return 0;
    });

    /// <summary>diagnostics --out файл.zip: часть службы для архива разбора (журналы, снимки состояния и сети).</summary>
    public static Task<int> DiagnosticsAsync(CliArgs args) => WithClientAsync(async client =>
    {
        if (args.Option("--out") is not { } path)
        {
            Console.WriteLine("diagnostics --out <файл.zip>");
            return 2;
        }

        var package = Expect<DiagnosticsPackageDto>(await SendAsync(client, new CollectDiagnosticsRequest()));
        var target = Path.GetFullPath(path);
        var temp = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            {
                while (true)
                {
                    var chunk = Expect<DiagnosticsChunkDto>(await SendAsync(client, new ReadDiagnosticsChunkRequest(package.Token, file.Length)));
                    if (file.Length + chunk.Data.Length > package.Length || (!chunk.Last && chunk.Data.Length == 0))
                    {
                        throw new InvalidDataException("Неверный размер данных диагностики.");
                    }

                    await file.WriteAsync(chunk.Data);
                    if (chunk.Last)
                    {
                        break;
                    }
                }

                file.Position = 0;
                var hash = await System.Security.Cryptography.SHA256.HashDataAsync(file);
                if (file.Length != package.Length || !Convert.ToHexString(hash).Equals(package.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Не совпадает длина или контрольная сумма архива диагностики.");
                }
            }

            File.Move(temp, target, overwrite: true);
            await DiagnosticsArchive.ConfirmReceiptAsync((request, token) => client.SendAsync(request, RequestTimeouts.For(request), token), package, CliCancellation.Token);
        }
        finally
        {
            File.Delete(temp);
        }

        foreach (var problem in package.Problems)
        {
            Console.WriteLine("Не собрано: " + problem);
        }

        Console.WriteLine($"Архив службы: {path} ({package.Length} байт)");
        return 0;
    });

    internal const string SettingsUsage = "settings get [--out <файл>] | settings set --file <файл> [--revision <ревизия> | --force]";

    /// <summary>
    /// settings get [--out файл] | settings set --file файл [--revision R | --force]. «get --out» кладёт рядом
    /// файл «.revision» с ревизией прочитанных настроек; «set» передаёт её службе, и та отклоняет запись, если
    /// настройки за это время изменили (приложение или другая команда). Без ревизии запись идёт только с --force.
    /// </summary>
    public static Task<int> SettingsAsync(CliArgs args) => WithClientAsync(async client =>
    {
        switch (args.Positional(0))
        {
            case "get":
                var current = Expect<AppSettings>(await SendAsync(client, new GetSettingsRequest()));
                var json = JsonSerializer.Serialize(current, JsonDefaults.Options);
                var revision = SettingsSerializer.Revision(current);
                if (args.Option("--out") is { } output)
                {
                    WriteOrPrint(output, json);
                    File.WriteAllText(RevisionPath(output), revision);
                    Console.WriteLine("Ревизия настроек: " + revision);
                }
                else
                {
                    // Только JSON: сценарии разбирают вывод целиком (вместе с потоком ошибок).
                    Console.WriteLine(json);
                }

                return 0;
            case "set" when args.Option("--file") is { } file:
                if (!TryExpectedRevision(args, file, out var expected))
                {
                    return 2;
                }

                var loaded = SettingsSerializer.Deserialize(await ReadInputFileAsync(file));
                if (loaded.Settings is null)
                {
                    Console.WriteLine("Файл настроек не разобран: " + loaded.Error);
                    return 1;
                }

                var saved = await SendAsync(client, new SaveSettingsRequest(loaded.Settings, expected));
                if (!saved.Ok && expected is not null)
                {
                    Console.WriteLine("Если настройки изменились после «settings get», получите их заново и повторите правку (или запишите поверх с --force).");
                }

                var result = PrintWarnings(saved);
                if (saved.Ok && File.Exists(RevisionPath(file)))
                {
                    // Следующая правка того же файла сверяется уже с записанными настройками, а не с исходными.
                    var stored = Expect<AppSettings>(await SendAsync(client, new GetSettingsRequest()));
                    File.WriteAllText(RevisionPath(file), SettingsSerializer.Revision(stored));
                }

                return result;
            default:
                Console.WriteLine(SettingsUsage);
                return 2;
        }
    });

    /// <summary>Файл ревизии рядом с файлом настроек: «settings.json» → «settings.json.revision».</summary>
    internal static string RevisionPath(string settingsFile) => settingsFile + ".revision";

    /// <summary>
    /// Ревизия, с которой сверяется запись: --revision, иначе файл «.revision» от «settings get --out».
    /// Без них — отказ, если не указан --force (null: запись без проверки).
    /// </summary>
    internal static bool TryExpectedRevision(CliArgs args, string settingsFile, out string? revision)
    {
        revision = args.Option("--revision");
        var force = args.Flag("--force");
        if (revision is not null && force)
        {
            Console.WriteLine("Укажите только одно: --revision или --force.");
            return false;
        }

        if (revision is null && !force && File.Exists(RevisionPath(settingsFile)))
        {
            revision = File.ReadAllText(RevisionPath(settingsFile)).Trim();
        }

        if (revision is { Length: 0 })
        {
            revision = null;
        }

        if (revision is null && !force)
        {
            Console.WriteLine($"Нет ревизии настроек: получите их через «settings get --out {settingsFile}» (рядом появится {Path.GetFileName(RevisionPath(settingsFile))}), "
                + "укажите --revision <ревизия> или запишите поверх изменений с --force.");
            return false;
        }

        return true;
    }

    /// <summary>
    /// profile set --name --server --user [--role] [--password-file]: создаёт или обновляет профиль с этим именем
    /// и передаёт пароль из одноразового файла. Без --role роль прежнего профиля не меняется, новый становится опорным;
    /// так же без --save-password/--no-save-password не меняется выбор, сохранять ли пароль.
    /// </summary>
    public static Task<int> ProfileAsync(CliArgs args) => WithClientAsync(async client =>
    {
        var fromDev = args.Flag("--from-dev-creds");
        var devProfile = fromDev ? Proto.ProtoContext.LoadProfile() : null;
        var (name, server, user) = (args.Option("--name"), devProfile?.Server ?? args.Option("--server"), devProfile?.UserName ?? args.Option("--user"));
        if (args.Positional(0) != "set" || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(user))
        {
            Console.WriteLine("profile set --name <имя> --server <хост[:порт]> --user <пользователь> [--role primary|secondary|off] [--password-file <файл>] [--save-password|--no-save-password]");
            Console.WriteLine("  без --role роль существующего профиля не меняется, новый профиль становится опорным");
            Console.WriteLine("  без --save-password/--no-save-password выбор существующего профиля не меняется, новый профиль сохраняет пароль");
            Console.WriteLine("profile set --name <имя> --from-dev-creds   (с повышением: сервер, пользователь и пароль из «creds set»)");
            Console.WriteLine("profile set ... --ssh-host-key \"ssh-ed25519 AAAA...\" [--ssh-key-file <файл>]   подключение «VPN поверх SSH»; файл ключа не удаляется");
            return 2;
        }

        // «VPN поверх SSH»: ключ сервера задаёт тип подключения, файл ключа устройства уходит службе одним запросом
        // с профилем. В командной строке ключа устройства нет - только путь к файлу.
        var sshHostKey = args.Option("--ssh-host-key");
        var hasPasswordOptions = fromDev || args.Option("--password-file") is not null || args.Flag("--save-password") || args.Flag("--no-save-password");
        if (sshHostKey is not null && hasPasswordOptions)
        {
            Console.WriteLine("Параметры пароля несовместимы с ключом SSH.");
            return 2;
        }

        string? sshKey = null;
        if (args.Option("--ssh-key-file") is { } sshKeyFile)
        {
            if (sshHostKey is null || !File.Exists(sshKeyFile))
            {
                Console.WriteLine(sshHostKey is null ? "--ssh-key-file требует --ssh-host-key." : $"Файл ключа не найден: {sshKeyFile}");
                return 2;
            }

            try
            {
                sshKey = Core.SshTunnel.SshPrivateKey.ReadFile(sshKeyFile);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
            {
                Console.WriteLine(ex.Message);
                return 2;
            }
        }

        var settings = Expect<AppSettings>(await SendAsync(client, new GetSettingsRequest()));
        // Имена подключений сравниваются так же, как в проверке настроек: без учёта регистра и пробелов по краям.
        var existing = settings.Profiles.FirstOrDefault(p => string.Equals(p.Name.Trim(), name.Trim(), StringComparison.OrdinalIgnoreCase));
        if (existing?.Protocol == VpnProtocol.SshVpn && hasPasswordOptions)
        {
            Console.WriteLine("Параметры пароля несовместимы с подключением SSH.");
            return 2;
        }

        if (!TryParseRole(args.Option("--role"), out var requested))
        {
            Console.WriteLine($"Неизвестная роль \"{args.Option("--role")}\": допустимо primary, secondary или off.");
            return 2;
        }

        var (savePassword, noSavePassword) = (args.Flag("--save-password"), args.Flag("--no-save-password"));
        if (savePassword && noSavePassword)
        {
            Console.WriteLine("Укажите только один из флагов: --save-password или --no-save-password.");
            return 2;
        }

        // Без --role роль не меняется: смена сервера или пароля не должна переключать опорное подключение.
        var role = requested ?? existing?.Role ?? ProfileRole.Primary;
        var profile = (existing ?? new ConnectionProfile()) with
        {
            Name = name,
            Server = server,
            UserName = user,
            Role = role,
            // Без флага выбор прежнего профиля сохраняется: иначе пароль из --password-file лёг бы на диск
            // у подключения, для которого запись пароля выключена.
            SavePassword = ConnectionEdits.SavePasswordFor(existing, savePassword || noSavePassword ? savePassword : default(bool?)),
        };
        if (sshHostKey is not null)
        {
            profile = profile with
            {
                Protocol = VpnProtocol.SshVpn,
                AuthMethod = AuthMethod.SshKey,
                SshVpn = new SshVpnSettings { HostKey = sshHostKey.Trim() },
            };
        }

        // Профиль остаётся на своём месте в списке: порядок задаёт очерёдность подъёма.
        var profiles = settings.Profiles
            .Select(p => p.Id == profile.Id ? profile : role == ProfileRole.Primary && p.Role == ProfileRole.Primary ? p with { Role = ProfileRole.Secondary } : p)
            .ToList();
        if (existing is null)
        {
            profiles.Add(profile);
        }

        var updated = settings with { Profiles = profiles };
        // «Остальной интернет» переходит на профиль, только когда тот становится опорным, как в приложении:
        // правка уже опорного профиля не отменяет выбор «Напрямую» или «Блокировать».
        if (role == ProfileRole.Primary && existing?.Role != ProfileRole.Primary && updated.DefaultFollowsNewPrimary())
        {
            updated = updated with { DefaultTarget = RouteTarget.Tunnel(profile.Id) };
        }

        var revision = SettingsSerializer.Revision(settings);
        string? password = null;
        string? passwordFile = null;
        if (fromDev)
        {
            var characters = Proto.ProtoContext.LoadPassword();
            try { password = new string(characters); }
            finally { Array.Clear(characters); }
        }
        else if (args.Option("--password-file") is { } file)
        {
            passwordFile = file;
            password = await ReadPasswordFileAsync(file);
        }
        if (password is { Length: 0 })
        {
            Console.Error.WriteLine("В файле пустой пароль.");
            return 1;
        }

        IpcRequest save = sshHostKey is null && password is null
            ? new SaveSettingsRequest(updated, revision)
            : new SaveConnectionRequest(updated, profile.Id, password, null, null, sshKey, revision);
        var accepted = false;
        try
        {
            var saved = await SendAsync(client, save);
            accepted = saved.Ok;
            if (PrintWarnings(saved) != 0) { return 1; }
        }
        finally
        {
            ConsumePasswordFile(passwordFile, accepted);
        }
        Console.WriteLine($"Профиль «{name}» ({RoleText(role)}): {profile.Id}");
        return 0;
    });

    /// <summary>password --password-file файл [--profile id]: пароль активного или указанного профиля.</summary>
    public static Task<int> PasswordAsync(CliArgs args) => WithClientAsync(async client =>
    {
        if (args.Option("--password-file") is not { } file)
        {
            Console.WriteLine("password --password-file <файл> [--profile <id>]  (файл удаляется после чтения)");
            return 2;
        }

        if (!TryProfileOption(args, out var explicitId))
        {
            return 2;
        }

        var settings = Expect<AppSettings>(await SendAsync(client, new GetSettingsRequest()));
        var id = explicitId ?? settings.PrimaryProfile?.Id;
        if (id is null)
        {
            Console.WriteLine("Нет опорного подключения: укажите --profile.");
            return 1;
        }

        return await SendPasswordAsync(client, id.Value, file);
    });

    public static Task<int> ConnectAsync(CliArgs args) => SendStatusCommandAsync(new ConnectRequest(null, null));

    /// <summary>
    /// --profile: нет параметра - null (берётся опорное подключение); есть, но это не идентификатор - отказ.
    /// Опечатка в идентификаторе не должна отправить пароль из файла другому подключению.
    /// </summary>
    internal static bool TryProfileOption(CliArgs args, out Guid? id)
    {
        id = null;
        if (!args.TryOption("--profile", out var text))
        {
            Console.WriteLine("После --profile требуется идентификатор подключения.");
            return false;
        }
        if (text is null) { return true; }

        if (Guid.TryParse(text, out var parsed))
        {
            id = parsed;
            return true;
        }

        Console.WriteLine($"--profile \"{text}\" не похоже на идентификатор подключения (его печатает «profile set»).");
        return false;
    }

    /// <summary>Без --role роль не задана (null); неизвестное значение отклоняется: опечатка не должна менять роли и маршрутизацию.</summary>
    private static bool TryParseRole(string? text, out ProfileRole? role)
    {
        role = null;
        switch (text?.ToLowerInvariant())
        {
            case null:
                return true;
            case "primary" or "опорное":
                role = ProfileRole.Primary;
                return true;
            case "secondary" or "дополнительное":
                role = ProfileRole.Secondary;
                return true;
            case "off" or "выключено":
                role = ProfileRole.Off;
                return true;
            default:
                return false;
        }
    }

    private static string RoleText(ProfileRole role) => role switch
    {
        ProfileRole.Primary => "опорное",
        ProfileRole.Secondary => "дополнительное",
        _ => "выключено",
    };

    /// <summary>tunnels: состояние каждого поднимаемого туннеля.</summary>
    public static Task<int> TunnelsAsync(CliArgs args) => WithClientAsync(async client =>
    {
        var status = Expect<StatusDto>(await SendAsync(client, new GetStatusRequest()));
        Console.WriteLine($"Остальной интернет: {status.DefaultTargetName}; Россия: {status.GeoTargetName}");
        foreach (var tunnel in status.Tunnels)
        {
            Console.WriteLine($"{tunnel.ProfileId}	{tunnel.Name}	{RoleText(tunnel.Role)}	{(tunnel.Paused ? "Отключено вами" : StatusText.StateName(tunnel.State))}	{tunnel.VpnAddress ?? "—"}	{tunnel.AdapterName ?? "—"}	{tunnel.ErrorText ?? ""}");
            if (tunnel.SignIn is { } signIn)
            {
                // Вход в SSO выполняет интерфейс: из командной строки его можно только начать.
                Console.WriteLine($"	вход: {SignInText(signIn.Kind)} ({signIn.GatewayHost}){(signIn.Kind == SignInKind.Required ? "; начать: SplitVpn.Cli sign-in --profile " + tunnel.ProfileId : "")}");
            }

            if (tunnel.ServerNetworks is { } gateway)
            {
                Console.WriteLine($"	шлюз: сетей {gateway.Networks.Count}, DNS {string.Join(", ", gateway.Dns)}, MTU {gateway.Mtu}, {(gateway.DtlsActive ? "DTLS" : "TLS")}{(gateway.SessionExpiresUtc is { } until ? ", сеанс до " + until.ToLocalTime().ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture) : "")}");
            }
        }

        return status.Tunnels.Count == 0 ? 1 : 0;
    });

    /// <summary>Положить или поднять один туннель, не трогая настройки: то же, что выключатель в строке.</summary>
    public static Task<int> TunnelPauseAsync(CliArgs args) => SetPausedAsync(args, paused: true);

    public static Task<int> TunnelResumeAsync(CliArgs args) => SetPausedAsync(args, paused: false);

    private static Task<int> SetPausedAsync(CliArgs args, bool paused) => WithClientAsync(async client =>
    {
        ArgumentNullException.ThrowIfNull(args);
        if (!Guid.TryParse(args.Option("--profile"), out var profileId))
        {
            Console.WriteLine("Укажите подключение: --profile <идентификатор> (имена и ID всех профилей — команда settings get).");
            return 2;
        }

        var status = Expect<StatusDto>(await SendAsync(client, new SetTunnelPausedRequest(profileId, paused)));
        var tunnel = status.Tunnels.FirstOrDefault(t => t.ProfileId == profileId);
        Console.WriteLine($"{tunnel?.Name ?? profileId.ToString()}: {(paused ? "отключено" : "включено")}.");
        return 0;
    });

    /// <summary>Порядок подключений: он задаёт и вид на экране, и очерёдность подъёма.</summary>
    public static Task<int> ProfileOrderAsync(CliArgs args) => WithClientAsync(async client =>
    {
        ArgumentNullException.ThrowIfNull(args);
        var ids = (args.Option("--ids") ?? "").Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (ids.Length == 0 || !ids.All(id => Guid.TryParse(id, out _)))
        {
            Console.WriteLine("Укажите порядок: --ids <id1,id2,...> (все подключения, список — команда tunnels).");
            return 2;
        }

        var status = Expect<StatusDto>(await SendAsync(client, new SetProfileOrderRequest([.. ids.Select(Guid.Parse)])));
        Console.WriteLine("Порядок: " + string.Join(", ", status.Tunnels.Select(t => t.Name)));
        return 0;
    });

    private static string SignInText(SignInKind kind) => kind switch
    {
        SignInKind.Browser => "открыто окно браузера",
        SignInKind.Form => "шлюз ждёт форму",
        _ => "требуется",
    };

    /// <summary>sign-in --profile id: начать вход в AnyConnect; окно входа откроет запущенный интерфейс.</summary>
    public static Task<int> SignInAsync(CliArgs args)
    {
        if (Guid.TryParse(args.Option("--profile"), out var id))
        {
            return SendStatusCommandAsync(new BeginSignInRequest(id));
        }

        Console.WriteLine("Использование: sign-in --profile <id подключения AnyConnect>");
        return Task.FromResult(2);
    }

    public static Task<int> DisconnectAsync(CliArgs args)
    {
        if (args.OnlyFlags("--keep-protection")) { return SendStatusCommandAsync(new DisconnectRequest(args.Flag("--keep-protection"))); }
        Console.Error.WriteLine("disconnect [--keep-protection]");
        return Task.FromResult(2);
    }

    public static Task<int> RecoverNetworkAsync(CliArgs args) => SendStatusCommandAsync(new RecoverNetworkRequest());

    /// <summary>test-profile [--profile id]: пробное подключение (при снятой защите) или отчёт по сеансу.</summary>
    public static Task<int> TestProfileAsync(CliArgs args) => WithClientAsync(async client =>
    {
        if (!TryProfileOption(args, out var explicitId))
        {
            return 2;
        }

        var settings = Expect<AppSettings>(await SendAsync(client, new GetSettingsRequest()));
        var id = explicitId ?? settings.PrimaryProfile?.Id;
        if (id is null)
        {
            Console.WriteLine("Нет опорного подключения: укажите --profile.");
            return 1;
        }

        var result = Expect<ProfileTestDto>(await SendAsync(client, new TestProfileRequest(id.Value)));
        Console.WriteLine(result.Text);
        return result.Success ? 0 : 1;
    });

    public static Task<int> CheckAsync(CliArgs args) => WithClientAsync(async client =>
    {
        if (args.Positional(0) is not { } query)
        {
            Console.WriteLine("check <IP или домен>");
            return 2;
        }

        var result = Expect<AddressCheckDto>(await SendAsync(client, new CheckAddressRequest(query)));
        foreach (var item in result.Items)
        {
            Console.WriteLine($"{item.Address}: {item.Decision} ({item.Source}); ожидается {item.ExpectedInterface}, маршрут {item.ActualInterface ?? "—"}{(item.Blocked ? ", заблокировано" : "")}");
            Console.WriteLine("  " + item.Explanation);
        }

        if (result.Note is not null)
        {
            Console.WriteLine(result.Note);
        }

        return 0;
    });

    /// <summary>geo update | rollback | accept | reject | clear-skipped | import --file ru.txt [--list bypass]</summary>
    public static Task<int> GeoAsync(CliArgs args) => WithClientAsync(async client =>
    {
        // Без --list команда относится к RU-базе: так же, как в службе и в сохранённых сценариях.
        var list = GeoListKind.Geo;
        if (args.Option("--list") is { } listName)
        {
            if (string.Equals(listName, "bypass", StringComparison.OrdinalIgnoreCase))
            {
                list = GeoListKind.Bypass;
            }
            else if (!string.Equals(listName, "geo", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"Неизвестный список \"{listName}\": допустимо geo или bypass.");
                return 2;
            }
        }

        GeoListRequest? request = args.Positional(0) switch
        {
            "update" => new GeoUpdateNowRequest(),
            "rollback" => new GeoRollbackRequest(),
            "accept" => new GeoAcceptPendingRequest(),
            "reject" => new GeoRejectPendingRequest(),
            "clear-skipped" => new GeoClearSkippedRequest(),
            "import" when args.Option("--file") is { } file => new GeoImportRequest(await ReadGeoFileAsync(file)),
            _ => null,
        };
        if (request is null)
        {
            Console.WriteLine("geo update | rollback | accept | reject | clear-skipped | import --file <ru.txt> [--list geo|bypass]");
            return 2;
        }

        request = request with { List = list };
        if (!FrameCodec.Fits(request))
        {
            // Клиент такой кадр не отправит, а служба не примет: понятное сообщение вместо ошибки канала.
            Console.WriteLine($"Файл слишком большой: служба принимает список не больше {FrameCodec.MaxFrameMegabytes} МБ, а переводы строк при передаче занимают вдвое больше места, чем в файле.");
            return 1;
        }

        return PrintResponse(await SendAsync(client, request));
    });

    /// <summary>update [status] | check | download | install | skip [--version X]</summary>
    public static Task<int> UpdateAsync(CliArgs args) => WithClientAsync(async client =>
    {
        var status = Expect<StatusDto>(await SendAsync(client, new GetStatusRequest()));
        var update = status.Update;
        var version = args.Option("--version") ?? update?.AvailableVersion ?? "";
        switch (args.Positional(0) ?? "status")
        {
            case "status":
                PrintUpdate(update);
                return update is null || update.Phase == UpdatePhase.Failed ? 1 : 0;
            case "check":
                return PrintResponse(await SendAsync(client, new CheckUpdateRequest()));
            case "download":
                return PrintResponse(await SendAsync(client, new DownloadUpdateRequest(version)));
            case "install":
                return await InstallUpdateAsync(client, version);
            case "skip":
                return PrintResponse(await SendAsync(client, new SkipUpdateRequest(version)));
            default:
                Console.WriteLine("update [status] | check | download | install | skip [--version <версия>]");
                return 2;
        }
    });

    /// <summary>Установку запускает вызывающий: служба отдаёт проверенную команду, а msiexec требует прав администратора.</summary>
    private static async Task<int> InstallUpdateAsync(IpcClient client, string version)
    {
        var response = await SendAsync(client, new InstallUpdateRequest(version));
        if (!response.Ok)
        {
            return PrintResponse(response);
        }

        var install = response.ResultAs<UpdateInstallDto>()!;
        Console.WriteLine($"Запуск установки {install.Version}; журнал: {install.LogPath}");
        Console.WriteLine("Закройте «Раздельный VPN», если он открыт: установщик заменит его файлы.");
        var processId = 0;
        var registered = false;
        // Описатель msiexec держится открытым, пока служба не получит номер процесса: иначе завершившийся
        // установщик (например, сразу с кодом 1618) освободил бы номер, и служба приняла бы чужой процесс за него.
        System.Diagnostics.Process? process = null;
        try
        {
            process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(install.FileName, install.Arguments)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Environment.SystemDirectory,
            });
            processId = process?.Id ?? 0;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            // 1223 (ERROR_CANCELLED) — отказ в окне контроля учётных записей.
            Console.Error.WriteLine(ex.NativeErrorCode == 1223
                ? "Установка отменена: для обновления нужны права администратора."
                : "Установщик обновления не запустился: " + ex.Message);
        }
        finally
        {
            // Служба должна узнать номер процесса или отказ (ноль) при любом исходе: иначе она 15 минут
            // считает установку идущей и не даёт ни проверить обновления, ни повторить установку.
            // Сбой этого сообщения не должен подменять исходную ошибку запуска: только предупреждение.
            try
            {
                // Без токена прерывания: сведения о запуске нужны службе и после Ctrl+C; срок ответа ограничен.
                var started = new UpdateStartedRequest(processId) { AttemptId = install.AttemptId };
                var confirmation = await client.SendAsync(started, RequestTimeouts.For(started), CancellationToken.None);
                registered = confirmation.Ok;
                if (!registered) { Console.Error.WriteLine("Служба отклонила сведения о запуске: " + confirmation.ErrorMessage); }
            }
            catch (Exception ex) when (ex is ServiceUnavailableException or IpcProtocolException or IOException or ObjectDisposedException or OperationCanceledException)
            {
                Console.Error.WriteLine("Предупреждение: служба не получила сведения о запуске установки: " + ex.Message);
            }
            finally
            {
                process?.Dispose();
            }
        }

        return processId != 0 && registered ? 0 : 1;
    }

    private static void PrintUpdate(UpdateStatusDto? update)
    {
        if (update is null)
        {
            Console.WriteLine("Служба не сообщает о состоянии обновления: версии программы и службы разошлись.");
            return;
        }

        Console.WriteLine(Text.Inv($"Установлено: {update.CurrentVersion}; состояние: {update.Phase}"));
        if (update.AvailableVersion is { } available)
        {
            Console.WriteLine(Text.Inv($"Доступно: {available}; скачано {update.DownloadedBytes} из {update.PackageSize} байт"));
        }

        if (update.SkippedVersion is { } skipped)
        {
            Console.WriteLine("Пропущена версия: " + skipped);
        }

        Console.WriteLine("Последняя проверка: " + (update.LastCheckUtc?.ToLocalTime().ToString("g", System.Globalization.CultureInfo.CurrentCulture) ?? "не было")
            + "; итог: " + (update.LastResult ?? "нет"));
        if (update.LastInstallResult is { } install)
        {
            Console.WriteLine("Последняя установка: " + install + (update.InstallLogPath is { } log ? "; журнал: " + log : ""));
        }
    }

    public static Task<int> ReportAsync(CliArgs args) => WithClientAsync(async client =>
    {
        var report = Expect<string>(await SendAsync(client, new ExportReportRequest(!args.Flag("--no-mask"))));
        WriteOrPrint(args.Option("--out"), report);
        return 0;
    });

    /// <summary>Положительное целое значение параметра, умноженное на <paramref name="scale"/>; иначе -1.</summary>
    private static async Task<string> ReadGeoFileAsync(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > FrameCodec.MaxFrameBytes)
            {
                throw new InvalidDataException($"Файл превышает {FrameCodec.MaxFrameMegabytes} МБ.");
            }

            using var reader = new StreamReader(stream);
            return await reader.ReadToEndAsync();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InputFileException(path, ex);
        }
    }

    private static int PositiveOption(CliArgs args, string name, int scale)
    {
        var value = args.IntOption(name, -1);
        return value > 0 && value <= int.MaxValue / scale ? value * scale : -1;
    }

    /// <summary>Подробный журнал: diag verbose on --hours N | --minutes N, off, status.</summary>
    public static async Task<int> DiagAsync(CliArgs args)
    {
        if (args.Positional(0) == "collect")
        {
            return await CollectAsync(args.Option("--out"));
        }

        if (args.Positional(0) != "verbose")
        {
            Console.WriteLine("Использование: diag verbose on [--hours N | --minutes N] | off | status | diag collect [--out <zip>]");
            return 2;
        }

        if (args.Positional(1) is "status" or null)
        {
            var until = VerboseRegistry.Read(DateTimeOffset.UtcNow);
            Console.WriteLine(until is { } value
                ? "Подробный журнал включён до " + value.ToLocalTime().ToString("g", System.Globalization.CultureInfo.CurrentCulture)
                : "Подробный журнал выключен.");
            return 0;
        }

        // «on» с нулём, отрицательным числом или опечаткой - ошибка: иначе «--hours 0» выключал бы журнал,
        // а «--hours abc» молча ставил бы час.
        var minutes = args.Positional(1) switch
        {
            "on" => args.Option("--minutes") is not null ? PositiveOption(args, "--minutes", 1)
                : args.Option("--hours") is not null ? PositiveOption(args, "--hours", 60)
                : 60,
            "off" => 0,
            _ => -1,
        };
        if (minutes < 0)
        {
            Console.WriteLine("Использование: diag verbose on [--hours N | --minutes N] | off | status");
            return 2;
        }

        return await WithClientAsync(async client =>
        {
            var until = Expect<DateTimeOffset?>(await SendAsync(client, new SetVerboseLoggingRequest(minutes)));
            Console.WriteLine(until is { } value
                ? "Подробный журнал включён до " + value.ToLocalTime().ToString("g", System.Globalization.CultureInfo.CurrentCulture)
                : "Подробный журнал выключен.");
            return 0;
        });
    }

    /// <summary>Архив для разбора: часть службы (если она ответила) и файлы этого пользователя.</summary>
    private static async Task<int> CollectAsync(string? output)
    {
        output ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), DiagnosticsArchive.DefaultFileName(DateTimeOffset.Now));
        IpcClient? client = null;
        Exception? failure = null;
        try
        {
            client = await IpcClient.ConnectAsync(ServiceName, TimeSpan.FromSeconds(5), CliCancellation.Token);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Отказ службы тоже попадает в архив: это и есть предмет разбора.
            failure = ex;
        }

        await using (client)
        {
            Func<IpcRequest, CancellationToken, Task<IpcResponse>> send = client is null
                ? (_, _) => Task.FromException<IpcResponse>(failure!)
                : (request, token) => client.SendAsync(request, RequestTimeouts.For(request), token);
            var files = DiagnosticsArchive.UserFiles().Append(new ArchiveFile("ui/environment.json", Text: ClientEnvironment.Json(
                new Dictionary<string, string?> { ["client"] = "splitvpn-cli" }))).ToList();
            var result = await DiagnosticsArchive.BuildAsync(send, files, output, new Progress<string>(Console.WriteLine), CliCancellation.Token);
            Console.WriteLine("Архив: " + result.Path + (result.ServiceIncluded ? "" : " (без части службы — см. service-missing.txt)"));
            foreach (var problem in result.Problems)
            {
                Console.WriteLine("! " + problem);
            }

            return 0;
        }
    }

    /// <summary>
    /// Проверка отказов канала: неизвестный тип, неверный JSON, недопустимая длина кадра. Канал открывается
    /// напрямую, минуя клиент, чтобы отправить то, что клиент не пропустит.
    /// </summary>
    public static async Task<int> ProbeBadAsync(CliArgs args)
    {
        var failures = 0;
        failures += await ExpectBadRequestAsync("неизвестный тип", Encoding.UTF8.GetBytes("{\"type\":\"deleteEverything\"}"));
        failures += await ExpectBadRequestAsync("неверный JSON", Encoding.UTF8.GetBytes("{not json"));
        failures += await ExpectBadRequestAsync("пароль без профиля", Encoding.UTF8.GetBytes("{\"type\":\"setPassword\"}"));
        failures += await ExpectClosedOnOversizeAsync();
        Console.WriteLine(failures == 0 ? "Все недопустимые запросы отклонены." : $"Не отклонено: {failures}");
        return failures == 0 ? 0 : 1;
    }

    private static async Task<int> ExpectBadRequestAsync(string name, byte[] payload)
    {
        await using var pipe = await OpenRawAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await FrameCodec.WriteAsync(pipe, payload, timeout.Token);
        var answer = await FrameCodec.ReadAsync(pipe, timeout.Token);
        var response = answer is null ? null : IpcSerializer.DeserializeResponse(answer);
        var rejected = response is { Ok: false, ErrorCode: IpcErrorCodes.BadRequest or IpcErrorCodes.NotFound };
        Console.WriteLine($"{name}: {(rejected ? "отклонён" : "ПРИНЯТ")} ({response?.ErrorCode ?? "канал закрыт"})");
        return rejected ? 0 : 1;
    }

    private static async Task<int> ExpectClosedOnOversizeAsync()
    {
        await using var pipe = await OpenRawAsync();
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, FrameCodec.MaxFrameBytes + 1);
        await pipe.WriteAsync(header);
        await pipe.FlushAsync();
        var buffer = new byte[4];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var read = await pipe.ReadAsync(buffer, timeout.Token);
        var closed = read == 0;
        Console.WriteLine($"кадр больше 2 МБ: {(closed ? "канал закрыт" : "ПРИНЯТ")}");
        return closed ? 0 : 1;
    }

    private static async Task<NamedPipeClientStream> OpenRawAsync()
    {
        var pipe = IpcClient.OpenPipe();
        await pipe.ConnectAsync(5000);
        return pipe;
    }

    private static async Task<int> SendPasswordAsync(IpcClient client, Guid profileId, string file)
    {
        var password = await ReadPasswordFileAsync(file);
        if (password.Length == 0)
        {
            Console.WriteLine("Пароль пустой — не передан.");
            return 1;
        }

        var accepted = false;
        try
        {
            var response = await SendAsync(client, new SetPasswordRequest(profileId, password));
            accepted = response.Ok;
            return PrintResponse(response);
        }
        finally
        {
            ConsumePasswordFile(file, accepted);
        }
    }

    private static async Task<string> ReadPasswordFileAsync(string file)
    {
        try
        {
            return (await File.ReadAllTextAsync(file)).TrimEnd('\r', '\n');
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InputFileException(file, ex);
        }
    }

    /// <summary>
    /// Одноразовый файл пароля удаляется только после того, как служба приняла пароль: при отказе, сбое связи
    /// или прерывании это единственная копия, и команду можно повторить с тем же файлом.
    /// </summary>
    internal static void ConsumePasswordFile(string? file, bool accepted)
    {
        if (file is null)
        {
            return;
        }

        if (!accepted)
        {
            Console.WriteLine($"Файл пароля не удалён: {file}. Повторите команду или удалите файл сами.");
            return;
        }

        try
        {
            File.Delete(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.WriteLine($"Пароль принят, но файл {file} удалить не удалось: {ex.Message}. Удалите его сами.");
        }
    }

    /// <summary>Входной файл команды (настройки и т. п.); ошибка чтения — ошибка использования (код 2), а не отказ службы.</summary>
    private static async Task<string> ReadInputFileAsync(string file)
    {
        try
        {
            return await File.ReadAllTextAsync(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InputFileException(file, ex);
        }
    }

    /// <summary>
    /// Запрос с пределом ожидания по типу (как в приложении) и прерыванием по Ctrl+C: зависшая служба
    /// не должна держать команду бесконечно.
    /// </summary>
    private static Task<IpcResponse> SendAsync(IpcClient client, IpcRequest request) =>
        client.SendAsync(request, RequestTimeouts.For(request), CliCancellation.Token);

    private static Task<int> SendStatusCommandAsync(IpcRequest request) => WithClientAsync(async client =>
    {
        var response = await SendAsync(client, request);
        if (!response.Ok)
        {
            return PrintResponse(response);
        }

        PrintStatus(response.ResultAs<StatusDto>()!);
        return 0;
    });

    private static async Task<int> WithClientAsync(Func<IpcClient, Task<int>> action)
    {
        try
        {
            await using var client = await IpcClient.ConnectAsync(ServiceName, TimeSpan.FromSeconds(5), CliCancellation.Token);
            return await action(client);
        }
        catch (ServiceUnavailableException ex) when (ex.Reason == ServiceUnavailableReason.Timeout)
        {
            // Запрос мог дойти до службы: команда, возможно, выполняется или уже выполнена.
            Console.WriteLine(ex.Message + " Команда могла выполниться — проверьте результат командой «status».");
            return 3;
        }
        catch (ServiceUnavailableException ex)
        {
            Console.WriteLine(ex.Message);
            return 3;
        }
        catch (OperationCanceledException) when (CliCancellation.IsInterrupted)
        {
            Console.WriteLine("Прервано: ответ службы не получен. Команда могла выполниться — проверьте результат командой «status».");
            return 3;
        }
        catch (Exception ex) when (ex is IpcProtocolException or System.Text.Json.JsonException)
        {
            // Испорченный или чужой ответ канала — та же «связь со службой не работает», что и её недоступность:
            // сценарии, проверяющие код 3, не должны принять его за отказ службы в команде (код 1).
            Console.WriteLine("Служба ответила сообщением, которое не удалось разобрать: " + ex.Message);
            return 3;
        }
        catch (ServiceCommandException ex)
        {
            Console.WriteLine(ex.Message);
            return 1;
        }
    }

    private static T Expect<T>(IpcResponse response) => response.Ok
        ? response.ResultAs<T>()!
        : throw new ServiceCommandException($"Служба отклонила запрос: {response.ErrorCode} — {response.ErrorMessage}");

    private static int PrintResponse(IpcResponse response)
    {
        Console.WriteLine(response.Ok
            ? "Готово." + (response.Result is { } result ? " " + result.GetRawText() : "")
            : $"Ошибка: {response.ErrorCode} — {response.ErrorMessage}");
        return response.Ok ? 0 : 1;
    }

    private static int PrintWarnings(IpcResponse response)
    {
        if (!response.Ok)
        {
            return PrintResponse(response);
        }

        foreach (var warning in response.ResultAs<List<string>>() ?? [])
        {
            Console.WriteLine("Предупреждение: " + warning);
        }

        return 0;
    }

    private static void PrintStatus(StatusDto status)
    {
        Console.WriteLine($"{StatusText.StateName(status.State)} — {StatusText.Format(status)}");
        Console.WriteLine($"Намерение: {status.Intent}; защита: {(status.ProtectionActive ? "включена" : status.ProtectionSuspended ? "приостановлена" : "выключена")}; профиль: {status.ProfileName ?? "—"}");
        Console.WriteLine($"Адаптер: {status.PrimaryAdapterName ?? "—"}; VPN-адрес: {status.VpnAddress ?? "—"}; сервер: {status.ServerAddress}");
        Console.WriteLine(Text.Inv($"База: {status.GeoRevision?[..Math.Min(12, status.GeoRevision.Length)] ?? "нет"} ({status.GeoV4Count} v4); передано {status.BytesSent} / принято {status.BytesReceived} байт"));
        if (status.ErrorText is not null)
        {
            Console.WriteLine($"Ошибка: {status.ErrorCategory} — {status.ErrorText} (код {status.ErrorCode?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "—"})");
        }

        foreach (var warning in status.Warnings)
        {
            Console.WriteLine("! " + warning.Text);
        }
    }

    private static void WriteOrPrint(string? path, string content)
    {
        if (path is null)
        {
            Console.WriteLine(content);
            return;
        }

        File.WriteAllText(path, content);
        Console.WriteLine("Записано: " + path);
    }
}

internal sealed class ServiceCommandException(string message) : Exception(message);
