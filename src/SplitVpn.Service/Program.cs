using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using SplitVpn.Core.Settings;
using SplitVpn.Service;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Ipc;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.OpenConnect;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Security;
using SplitVpn.Windows.Wfp;

var paths = ServicePaths.Default;
if (args.Length > 0 && string.Equals(args[0], "recover", StringComparison.OrdinalIgnoreCase))
{
    return await ServiceRecovery.RunAsync(paths, uninstall: args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase));
}

Directory.CreateDirectory(paths.Root);
SecretStore.RestrictToSystemAndAdministrators(paths.Root);

// Журнал: файл на сутки, но при 10 МБ он продолжается следующим файлом, а не обрывается до полуночи.
// Предел в 30 файлов при пределе возраста в 14 суток означает, что даже «разговорчивые» сутки (до трёх
// файлов) целиком остаются в истории.
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.File(Path.Combine(paths.Logs, "service-.log"), formatProvider: System.Globalization.CultureInfo.InvariantCulture,
        rollingInterval: RollingInterval.Day, retainedFileCountLimit: 30, retainedFileTimeLimit: TimeSpan.FromDays(14),
        fileSizeLimitBytes: 10_000_000, rollOnFileSizeLimit: true)
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddWindowsService(options => options.ServiceName = ServicePaths.ServiceName);
    builder.Services.AddSerilog();
    builder.Services.AddSingleton(provider => CreateDependencies(paths, provider.GetRequiredService<ILoggerFactory>()));
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

static ServiceDependencies CreateDependencies(ServicePaths paths, ILoggerFactory loggers)
{
    // Хранилища находят повреждённые файлы уже при чтении, до создания координатора: общий журнал находок
    // отдаётся ему готовым, а он переносит их в журнал событий и предупреждения статуса.
    var corruptFiles = new CorruptFileLog();
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
        DnsProxy = new SystemDnsProxy(),
        Probes = new SystemProbeOps(),
        Http = CreateHttpClient(),
        Time = TimeProvider.System,
        Journal = new EventJournal(TimeProvider.System),
        Logger = loggers.CreateLogger("SplitVpn"),
        ServiceExecutablePath = Environment.ProcessPath!,
        CorruptFiles = corruptFiles,
        BfeProcessId = () => SystemMetrics.ServiceStatus("BFE").ProcessId,
        RasTerminationReason = SystemSignals.RasTerminationReason,
        DetectConflicts = tunnelLuids => ConflictDetector.Detect(paths.Phonebook, tunnelLuids),
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
            coordinator.ShutdownAnyConnect();
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
}
