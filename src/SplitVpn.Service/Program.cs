using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Settings;
using SplitVpn.Service;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Diagnostics;
using SplitVpn.Service.Ipc;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.OpenConnect;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Security;
using SplitVpn.Windows.Wfp;

var paths = ServicePaths.Default;
if (args.Length > 0 && string.Equals(args[0], "recover", StringComparison.OrdinalIgnoreCase))
{
    return await ServiceRecovery.RunAsync(paths, ServiceRecovery.ParseMode(args));
}

// Владелец, защищённый DACL и права потомков — до первого обращения к данным, в том числе до журнала.
var dataWarnings = SecretStore.SecureDataRoot(paths.Root);

// Подробный журнал: срок читается из реестра до создания журнала, поэтому включённый режим
// действует с первой строки после перезапуска службы или перезагрузки.
var levelSwitch = new Serilog.Core.LoggingLevelSwitch();
var verbose = new VerboseMode(levelSwitch, TimeProvider.System, VerboseRegistry.ReadRaw, VerboseRegistry.Write, paths.Logs);
verbose.Initialize();
Log.Logger = ServiceLogging.Create(paths.Logs, levelSwitch);
Verbose.Sink = ServiceLogging.VerboseSink(Log.Logger);
System.Diagnostics.Trace.Listeners.Add(new SerilogTraceListener(Log.Logger));
if (verbose.UntilUtc is { } verboseUntil)
{
    Log.Information("Подробный журнал действует до {Until:O}", verboseUntil);
}

foreach (var warning in dataWarnings)
{
    Log.Warning("Каталог данных: {Problem}", warning);
}

// Разрешение установщику стереть данные (PurgeData) действует только внутри удаления; служба запустилась - удаление
// отменено или откачено, и отметка снимается. Сбой - только в журнал.
ServiceRecovery.ClearStalePurgeMark(problem => Log.Warning("Удаление программы: {Problem}", problem));

try
{
    var builder = Host.CreateApplicationBuilder(args);
    // Остановка идёт по шагам: канал управления (до 3 с), очередь координатора и затем помощники AnyConnect и движок
    // SSH (параллельно, до 15 с). Общий срок - меньше 30 с, которые установщик ждёт остановки службы (расчёт - у
    // CoordinatorHost.ShutdownTimeout).
    builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = CoordinatorHost.ShutdownTimeout);
    builder.Services.AddWindowsService(options => options.ServiceName = ServicePaths.ServiceName);
    if (Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService())
    {
        // Та же служба Windows, но с событиями сеансов (вход, выход, переключение пользователя) в журнале.
        builder.Services.AddSingleton<IHostLifetime, SessionAwareLifetime>();
    }

    builder.Services.AddSerilog();
    // Уровень решает переключатель Serilog; фильтр Microsoft.Extensions.Logging не должен резать отладочные строки раньше него.
    builder.Logging.SetMinimumLevel(LogLevel.Trace);
    builder.Services.AddSingleton(provider => CreateDependencies(paths, verbose, provider.GetRequiredService<ILoggerFactory>()));
    builder.Services.AddSingleton<Coordinator>();
    builder.Services.AddHostedService<RouteSinkHost>();
    builder.Services.AddHostedService<CoordinatorHost>();
    builder.Services.AddHostedService<IpcServer>();
    await builder.Build().RunAsync();
    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "Служба остановлена из-за ошибки");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

static ServiceDependencies CreateDependencies(ServicePaths paths, VerboseMode verbose, ILoggerFactory loggers)
{
    // Хранилища находят повреждённые файлы уже при чтении, до создания координатора: общий журнал находок
    // отдаётся ему готовым, а он переносит их в журнал событий и предупреждения статуса.
    var corruptFiles = new CorruptFileLog();
    var logger = loggers.CreateLogger("SplitVpn");
    var journal = new EventJournal(TimeProvider.System);
    verbose.Journal = (level, text) =>
    {
        journal.Add(level, text);
        logger.Log(level == "Сведения" ? LogLevel.Information : LogLevel.Warning, "{Event}", text);
    };
    return new ServiceDependencies
    {
        Stores = new ServiceStores(paths),
        Inventory = new SystemNetInventory(),
        Routes = new SystemRouteOps(),
        Wfp = new SystemWfpOps(WfpIdentity.Product),
        Dns = new SystemDnsOps(),
        DnsBackups = new DnsBackupStore(paths.DnsBackup),
        Ras = new SystemRasOps(paths.Phonebook),
        Secrets = new SystemSecretOps(paths.Secrets, corruptFiles.Add),
        Resolver = new SystemResolver(),
        AnyConnect = new SystemAnyConnectOps(Path.Combine(AppContext.BaseDirectory, SystemAnyConnectOps.HelperFileName)),
        SshTunnel = new SplitVpn.Windows.SshTunnel.SystemSshTunnelOps(
            Path.Combine(AppContext.BaseDirectory, SplitVpn.Windows.SshTunnel.SystemSshTunnelOps.EngineFileName), paths.SshEngineWork,
            message => logger.LogInformation("{Message}", message)),
        DnsProxy = new SystemDnsProxy(message => logger.LogWarning("{Message}", message)),
        Probes = new SystemProbeOps(),
        Http = CreateHttpClient(),
        Time = TimeProvider.System,
        Journal = journal,
        Verbose = verbose,
        DiagnosticsCollector = new DiagnosticsCollector(paths, TimeProvider.System, () => SystemDiagnostics.Parts(() => verbose.UntilUtc), SystemDiagnostics.UserProfiles),
        DiagnosticsPackages = new DiagnosticsPackages(Path.Combine(paths.Root, "diag"), TimeProvider.System),
        Logger = logger,
        ServiceExecutablePath = Environment.ProcessPath!,
        CorruptFiles = corruptFiles,
        BfeProcessId = () => SystemMetrics.ServiceStatus("BFE").ProcessId,
        RasTerminationReason = SystemSignals.RasTerminationReason,
        DetectConflicts = inputs => ConflictDetector.Detect(paths.Phonebook, inputs.Tunnels, inputs.Servers, inputs.Resolve, inputs.StillCurrent),
        SubscribeNetworkChanges = changed => NetworkChangeWatcher.Start(changed),
        SubscribeWifiEvents = raise => WifiEventWatcher.Start(raise),
        WifiIncidentDirectory = paths.Logs,
        DisableWifiBadStateTracking = () => WcmBadStateTracking.Apply() == WcmBadStateTrackingResult.Disabled,
        IsMeteredNetwork = SystemSignals.IsMeteredNetwork,
    };
}

static HttpClient CreateHttpClient()
{
    // Общий предел снят намеренно: в .NET он покрывает и чтение тела ответа, поэтому установщик на
    // десятки мегабайт обрывался бы на медленном канале. Свой предел ставит каждый загрузчик: список
    // адресов — на запрос, установщик — по бездействию.
    var client = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
    client.DefaultRequestHeaders.UserAgent.ParseAdd("SplitVpn/" + SplitVpn.Core.Update.UpdateVersion.Text(SplitVpn.Core.Update.UpdateVersion.Current));
    return client;
}

/// <summary>Связывает DNS-посредник с координатором: адреса из правил для доменов идут в маршруты.</summary>
internal sealed class RouteSinkHost(Coordinator coordinator, ServiceDependencies deps) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        deps.DnsProxy.RouteSink = new CoordinatorRouteSink(coordinator);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

internal sealed class CoordinatorHost(Coordinator coordinator, ILogger<CoordinatorHost> logger) : BackgroundService
{
    /// <summary>
    /// Предел ожидания помощников AnyConnect. Прощание со шлюзом обычно занимает секунды; собственный срок выхода
    /// помощника (15 с, затем принудительное завершение) может оказаться длиннее - тогда его завершит закрытие Job
    /// при выходе службы. Предел ограничен сроком остановки (<see cref="ShutdownTimeout"/>), а не сроком помощника.
    /// </summary>
    private static readonly TimeSpan AnyConnectExitBudget = TimeSpan.FromSeconds(15);

    /// <summary>Предел ожидания движка «VPN поверх SSH»: он завершается по команде и прощаться ему не с кем.</summary>
    private static readonly TimeSpan SshExitBudget = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Общий срок остановки хоста. Установщик (ServiceControl Wait="yes") ждёт остановки службы около 30 с, иначе
    /// ошибка 1921 и возможный откат обновления, поэтому сумма должна быть заведомо меньше 30 с. Шаги хоста идут друг
    /// за другом (в обратном порядке регистрации): канал управления ждёт клиентов до 3 с (IpcServer.ClientShutdownWait),
    /// затем координатор доводит текущую работу очереди под отменой и ждёт выхода помощников: AnyConnect до 15 с и SSH
    /// до 5 с параллельно, то есть до 15 с. Итого 3 + 15 = 18 с плюс работа очереди; 28 с оставляют ей 10 с, а сверх
    /// срока хост перестаёт ждать, и процесс завершается с запасом 2 с до предела установщика (на сброс журнала).
    /// </summary>
    internal static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(28);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await coordinator.RunAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Остановка службы: фильтры, маршруты и соединения RAS остаются — новая служба их подхватит.
            // Сеанс AnyConnect не переносится между процессами: его сети снимаются, помощник прощается со шлюзом.
            // Выход службы закрывает Job помощников (KILL_ON_JOB_CLOSE): ждём, пока они попрощаются со шлюзом.
            // Сам сеанс помощника ограничивает ожидание (15 с на выход, затем завершение); здесь ждём не дольше
            // AnyConnectExitBudget, чтобы остановка уложилась в срок установщика.
            // Движок «VPN поверх SSH» службу не переживает (он в её Job): завершаем его сами и ждём выхода.
            // Синхронная часть (снятие сетей AnyConnect, команды выхода) идёт в прежнем порядке, а ожидание выхода
            // процессов — параллельно: друг от друга они не зависят, и последовательные пределы не складываются.
            // Каждая остановка вызывается независимо: исключение одной не должно оставить другую без вызова.
            var anyConnect = StopSafely(coordinator.ShutdownAnyConnect, "помощников AnyConnect");
            var ssh = StopSafely(coordinator.ShutdownSshTunnels, "движка «VPN поверх SSH»");
            await WaitExitAsync(anyConnect, ssh);
            logger.LogInformation("Служба останавливается; системные объекты сохранены для подхвата.");
        }
        catch (Exception ex)
        {
            // Без координатора служба бесполезна: фильтры WFP постоянные, трафик остаётся заблокированным,
            // а DNS-посредник не отвечает. Ненулевой код завершения — сигнал SCM перезапустить службу
            // (действия восстановления 5 с / 5 с / 30 с).
            logger.LogCritical(ex, "Цикл координатора остановлен ошибкой: служба завершается для перезапуска");
            await Log.CloseAndFlushAsync();
            Environment.Exit(1);
        }
    }

    /// <summary>Синхронная часть остановки; её сбой - запись в журнал и завершённая задача, а не срыв остальной остановки.</summary>
    private Task StopSafely(Func<Task> stop, string name)
    {
        try
        {
            return stop();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Остановка {Name} завершилась ошибкой", name);
            return Task.CompletedTask;
        }
    }

    private async Task WaitExitAsync(Task anyConnect, Task ssh)
    {
        var sshLimit = Task.Delay(SshExitBudget, CancellationToken.None);
        var anyConnectLimit = Task.Delay(AnyConnectExitBudget, CancellationToken.None);
        if (await Task.WhenAny(ssh, sshLimit) != ssh)
        {
            logger.LogWarning("Движок «VPN поверх SSH» не завершился за {Seconds} с", SshExitBudget.TotalSeconds);
        }

        if (await Task.WhenAny(anyConnect, anyConnectLimit) != anyConnect)
        {
            logger.LogWarning("Помощники AnyConnect не завершились за {Seconds} с", AnyConnectExitBudget.TotalSeconds);
        }

        foreach (var (task, name) in new[] { (anyConnect, "помощников AnyConnect"), (ssh, "движка «VPN поверх SSH»") })
        {
            if (task.IsFaulted)
            {
                logger.LogWarning(task.Exception?.GetBaseException(), "Остановка {Name} завершилась ошибкой", name);
            }
        }
    }
}
