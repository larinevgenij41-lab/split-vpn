using Microsoft.Extensions.Logging;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Coordination;

/// <summary>Всё, через что координатор взаимодействует с системой. В тестах подменяется фейками.</summary>
public sealed record ServiceDependencies
{
    public required ServiceStores Stores { get; init; }

    public required INetInventory Inventory { get; init; }

    public required IRouteOps Routes { get; init; }

    public required IWfpOps Wfp { get; init; }

    public required IDnsOps Dns { get; init; }

    public required DnsBackupStore DnsBackups { get; init; }

    public required IRasOps Ras { get; init; }

    public required ISecretOps Secrets { get; init; }

    public required IResolver Resolver { get; init; }

    /// <summary>Процессы-помощники AnyConnect.</summary>
    public required IAnyConnectOps AnyConnect { get; init; }

    public required IDnsProxy DnsProxy { get; init; }

    public required IProbeOps Probes { get; init; }

    public required HttpClient Http { get; init; }

    public required TimeProvider Time { get; init; }

    public required EventJournal Journal { get; init; }

    public required ILogger Logger { get; init; }

    /// <summary>Путь исполняемого файла службы для условия ALE_APP_ID.</summary>
    public required string ServiceExecutablePath { get; init; }

    /// <summary>Повреждённые служебные файлы: находки всех хранилищ службы в одном месте.</summary>
    public Core.Settings.CorruptFileLog CorruptFiles { get; init; } = new();

    public Random Random { get; init; } = Random.Shared;

    /// <summary>PID процесса службы BFE: смена означает перезапуск BFE и потерю static-фильтров.</summary>
    public Func<uint> BfeProcessId { get; init; } = () => 0;

    /// <summary>
    /// Код завершения последнего RAS-соединения своей записи после указанного момента (журнал RasClient, событие 20226).
    /// 631 — отключение пользователем (меню сети Windows, rasdial), остальное — обрыв; null — неизвестно.
    /// </summary>
    public Func<DateTimeOffset, uint?> RasTerminationReason { get; init; } = _ => null;

    /// <summary>Время с загрузки Windows: автоподключение срабатывает только при запуске системы.</summary>
    public Func<TimeSpan> SystemUptime { get; init; } = () => TimeSpan.FromMilliseconds(Environment.TickCount64);

    /// <summary>Конфликты с другими программами: чужие VPN-соединения, маршруты на туннеле, жёсткие разрешения WFP.</summary>
    public Func<IReadOnlyList<Windows.Diagnostics.ConflictTunnel>, IReadOnlyList<Core.Ipc.StatusWarning>> DetectConflicts { get; init; } = _ => [];

    /// <summary>Лимитная сеть (мобильная точка доступа и т. п.): фоновая загрузка базы откладывается.</summary>
    public Func<bool> IsMeteredNetwork { get; init; } = () => false;
}
