using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
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
        var status = Expect<StatusDto>(await client.SendAsync(new GetStatusRequest(), CancellationToken.None));
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
        var events = Expect<List<ServiceEvent>>(await client.SendAsync(new GetEventsRequest(args.IntOption("--since", 0)), CancellationToken.None));
        foreach (var e in events.TakeLast(args.IntOption("--last", 50)))
        {
            Console.WriteLine(Text.Inv($"{e.Id,5} {e.TimeUtc.ToLocalTime():dd.MM HH:mm:ss} {e.Level,-8} {e.Text}"));
        }

        return 0;
    });

    public static Task<int> AdaptersAsync(CliArgs args) => WithClientAsync(async client =>
    {
        foreach (var a in Expect<List<AdapterDto>>(await client.SendAsync(new GetAdaptersRequest(), CancellationToken.None)))
        {
            Console.WriteLine($"{(a.IsPrimary ? "*" : " ")} {a.Name} [{a.Type}] шлюз {a.Gateway ?? "—"} {a.InterfaceGuid}");
        }

        return 0;
    });

    /// <summary>settings get [--out файл] | settings set --file файл</summary>
    public static Task<int> SettingsAsync(CliArgs args) => WithClientAsync(async client =>
    {
        switch (args.Positional(0))
        {
            case "get":
                var json = JsonSerializer.Serialize(Expect<AppSettings>(await client.SendAsync(new GetSettingsRequest(), CancellationToken.None)), JsonDefaults.Options);
                WriteOrPrint(args.Option("--out"), json);
                return 0;
            case "set" when args.Option("--file") is { } file:
                var loaded = SettingsSerializer.Deserialize(await File.ReadAllTextAsync(file));
                if (loaded.Settings is null)
                {
                    Console.WriteLine("Файл настроек не разобран: " + loaded.Error);
                    return 1;
                }

                return PrintWarnings(await client.SendAsync(new SaveSettingsRequest(loaded.Settings), CancellationToken.None));
            default:
                Console.WriteLine("settings get [--out <файл>] | settings set --file <файл>");
                return 2;
        }
    });

    /// <summary>
    /// profile set --name --server --user [--password-file]: создаёт или обновляет профиль с этим именем,
    /// делает его активным и передаёт пароль из одноразового файла.
    /// </summary>
    public static Task<int> ProfileAsync(CliArgs args) => WithClientAsync(async client =>
    {
        var fromDev = args.Flag("--from-dev-creds");
        var devProfile = fromDev ? Proto.ProtoContext.LoadProfile() : null;
        var (name, server, user) = (args.Option("--name"), devProfile?.Server ?? args.Option("--server"), devProfile?.UserName ?? args.Option("--user"));
        if (args.Positional(0) != "set" || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(user))
        {
            Console.WriteLine("profile set --name <имя> --server <хост[:порт]> --user <пользователь> [--role primary|secondary|off] [--password-file <файл>] [--no-save-password]");
            Console.WriteLine("profile set --name <имя> --from-dev-creds   (с повышением: сервер, пользователь и пароль из «creds set»)");
            return 2;
        }

        var settings = Expect<AppSettings>(await client.SendAsync(new GetSettingsRequest(), CancellationToken.None));
        var existing = settings.Profiles.FirstOrDefault(p => p.Name == name);
        var role = ParseRole(args.Option("--role"));
        var profile = (existing ?? new ConnectionProfile()) with
        {
            Name = name,
            Server = server,
            UserName = user,
            Role = role,
            SavePassword = !args.Flag("--no-save-password"),
        };
        var profiles = settings.Profiles.Where(p => p.Id != profile.Id)
            .Select(p => role == ProfileRole.Primary && p.Role == ProfileRole.Primary ? p with { Role = ProfileRole.Secondary } : p)
            .Append(profile).ToList();
        var updated = settings with { Profiles = profiles };
        if (role == ProfileRole.Primary && !updated.DefaultTarget.IsVpn)
        {
            updated = updated with { DefaultTarget = RouteTarget.Tunnel(profile.Id) };
        }

        var saved = await client.SendAsync(new SaveSettingsRequest(updated), CancellationToken.None);
        if (PrintWarnings(saved) != 0)
        {
            return 1;
        }

        Console.WriteLine($"Профиль «{name}» ({RoleText(role)}): {profile.Id}");
        if (fromDev)
        {
            var password = Proto.ProtoContext.LoadPassword();
            try
            {
                return PrintResponse(await client.SendAsync(new SetPasswordRequest(profile.Id, new string(password)), CancellationToken.None));
            }
            finally
            {
                Array.Clear(password);
            }
        }

        return args.Option("--password-file") is { } file ? await SendPasswordAsync(client, profile.Id, file) : 0;
    });

    /// <summary>password --password-file файл [--profile id]: пароль активного или указанного профиля.</summary>
    public static Task<int> PasswordAsync(CliArgs args) => WithClientAsync(async client =>
    {
        if (args.Option("--password-file") is not { } file)
        {
            Console.WriteLine("password --password-file <файл> [--profile <id>]  (файл удаляется после чтения)");
            return 2;
        }

        var settings = Expect<AppSettings>(await client.SendAsync(new GetSettingsRequest(), CancellationToken.None));
        var id = Guid.TryParse(args.Option("--profile"), out var parsed) ? parsed : settings.PrimaryProfile?.Id;
        if (id is null)
        {
            Console.WriteLine("Нет опорного подключения: укажите --profile.");
            return 1;
        }

        return await SendPasswordAsync(client, id.Value, file);
    });

    public static Task<int> ConnectAsync(CliArgs args) => SendStatusCommandAsync(new ConnectRequest(null, null));

    private static ProfileRole ParseRole(string? text) => text?.ToLowerInvariant() switch
    {
        "secondary" or "дополнительное" => ProfileRole.Secondary,
        "off" or "выключено" => ProfileRole.Off,
        _ => ProfileRole.Primary,
    };

    private static string RoleText(ProfileRole role) => role switch
    {
        ProfileRole.Primary => "опорное",
        ProfileRole.Secondary => "дополнительное",
        _ => "выключено",
    };

    /// <summary>tunnels: состояние каждого поднимаемого туннеля.</summary>
    public static Task<int> TunnelsAsync(CliArgs args) => WithClientAsync(async client =>
    {
        var status = Expect<StatusDto>(await client.SendAsync(new GetStatusRequest(), CancellationToken.None));
        Console.WriteLine($"Остальной интернет: {status.DefaultTargetName}; Россия: {status.GeoTargetName}");
        foreach (var tunnel in status.Tunnels)
        {
            Console.WriteLine($"{tunnel.Name}	{RoleText(tunnel.Role)}	{StatusText.StateName(tunnel.State)}	{tunnel.VpnAddress ?? "—"}	{tunnel.AdapterName ?? "—"}	{tunnel.ErrorText ?? ""}");
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

    public static Task<int> DisconnectAsync(CliArgs args) => SendStatusCommandAsync(new DisconnectRequest(args.Flag("--keep-protection")));

    public static Task<int> RecoverNetworkAsync(CliArgs args) => SendStatusCommandAsync(new RecoverNetworkRequest());

    /// <summary>test-profile [--profile id]: пробное подключение (при снятой защите) или отчёт по сеансу.</summary>
    public static Task<int> TestProfileAsync(CliArgs args) => WithClientAsync(async client =>
    {
        var settings = Expect<AppSettings>(await client.SendAsync(new GetSettingsRequest(), CancellationToken.None));
        var id = Guid.TryParse(args.Option("--profile"), out var parsed) ? parsed : settings.PrimaryProfile?.Id;
        if (id is null)
        {
            Console.WriteLine("Нет опорного подключения: укажите --profile.");
            return 1;
        }

        var result = Expect<ProfileTestDto>(await client.SendAsync(new TestProfileRequest(id.Value), CancellationToken.None));
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

        var result = Expect<AddressCheckDto>(await client.SendAsync(new CheckAddressRequest(query), CancellationToken.None));
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
        var list = args.Option("--list") is "bypass" ? GeoListKind.Bypass : GeoListKind.Geo;
        GeoListRequest? request = args.Positional(0) switch
        {
            "update" => new GeoUpdateNowRequest(),
            "rollback" => new GeoRollbackRequest(),
            "accept" => new GeoAcceptPendingRequest(),
            "reject" => new GeoRejectPendingRequest(),
            "clear-skipped" => new GeoClearSkippedRequest(),
            "import" when args.Option("--file") is { } file => new GeoImportRequest(await File.ReadAllTextAsync(file)),
            _ => null,
        };
        if (request is null)
        {
            Console.WriteLine("geo update | rollback | accept | reject | clear-skipped | import --file <ru.txt> [--list geo|bypass]");
            return 2;
        }

        request = request with { List = list };

        return PrintResponse(await client.SendAsync(request, CancellationToken.None));
    });

    /// <summary>update [status] | check | download | install | skip [--version X]</summary>
    public static Task<int> UpdateAsync(CliArgs args) => WithClientAsync(async client =>
    {
        var status = Expect<StatusDto>(await client.SendAsync(new GetStatusRequest(), CancellationToken.None));
        var update = status.Update;
        var version = args.Option("--version") ?? update?.AvailableVersion ?? "";
        switch (args.Positional(0) ?? "status")
        {
            case "status":
                PrintUpdate(update);
                return update?.Phase == UpdatePhase.Failed ? 1 : 0;
            case "check":
                return PrintResponse(await client.SendAsync(new CheckUpdateRequest(), CancellationToken.None));
            case "download":
                return PrintResponse(await client.SendAsync(new DownloadUpdateRequest(version), CancellationToken.None));
            case "install":
                return await InstallUpdateAsync(client, version);
            case "skip":
                return PrintResponse(await client.SendAsync(new SkipUpdateRequest(version), CancellationToken.None));
            default:
                Console.WriteLine("update [status] | check | download | install | skip [--version <версия>]");
                return 2;
        }
    });

    /// <summary>Установку запускает вызывающий: служба отдаёт проверенную команду, а msiexec требует прав администратора.</summary>
    private static async Task<int> InstallUpdateAsync(IpcClient client, string version)
    {
        var response = await client.SendAsync(new InstallUpdateRequest(version), CancellationToken.None);
        if (!response.Ok)
        {
            return PrintResponse(response);
        }

        var install = response.ResultAs<UpdateInstallDto>()!;
        Console.WriteLine($"Запуск установки {install.Version}; журнал: {install.LogPath}");
        Console.WriteLine("Закройте «Раздельный VPN», если он открыт: установщик заменит его файлы.");
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(install.FileName, install.Arguments)
        {
            UseShellExecute = true,
            Verb = "runas",
        });
        await client.SendAsync(new UpdateStartedRequest(process?.Id ?? 0), CancellationToken.None);
        return process is null ? 1 : 0;
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
        var report = Expect<string>(await client.SendAsync(new ExportReportRequest(!args.Flag("--no-mask")), CancellationToken.None));
        WriteOrPrint(args.Option("--out"), report);
        return 0;
    });

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
        await FrameCodec.WriteAsync(pipe, payload, CancellationToken.None);
        var answer = await FrameCodec.ReadAsync(pipe, CancellationToken.None);
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
        string password;
        try
        {
            password = (await File.ReadAllTextAsync(file)).TrimEnd('\r', '\n');
        }
        finally
        {
            File.Delete(file);
        }

        if (password.Length == 0)
        {
            Console.WriteLine("Пароль пустой — не передан.");
            return 1;
        }

        return PrintResponse(await client.SendAsync(new SetPasswordRequest(profileId, password), CancellationToken.None));
    }

    private static Task<int> SendStatusCommandAsync(IpcRequest request) => WithClientAsync(async client =>
    {
        var response = await client.SendAsync(request, CancellationToken.None);
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
            await using var client = await IpcClient.ConnectAsync(ServiceName, TimeSpan.FromSeconds(5), CancellationToken.None);
            return await action(client);
        }
        catch (ServiceUnavailableException ex)
        {
            Console.WriteLine(ex.Message);
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
