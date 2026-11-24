using Microsoft.Extensions.Logging;
using SplitVpn.Core.Update;
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

    /// <summary>Процесс движка «VPN поверх SSH».</summary>
    public required ISshTunnelOps SshTunnel { get; init; }

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

    /// <summary>Версия установленной программы: по ней служба решает, что предлагать и установилось ли обновление.</summary>
    public Version ProductVersion { get; init; } = UpdateVersion.Current;

    /// <summary>Проверка подписи манифеста обновлений; в тестах подменяется своим ключом.</summary>
    public IManifestVerifier ManifestVerifier { get; init; } = EcdsaManifestVerifier.Default;

    /// <summary>
    /// Ждёт завершения чужого процесса по номеру и возвращает его код; null — процесса нет или код
    /// получить не удалось. Так служба узнаёт итог msiexec, если MSI не успел её остановить.
    /// </summary>
    public Func<int, CancellationToken, Task<int?>> WaitForProcessAsync { get; init; } = SystemSignals.WaitForProcessAsync;

    public Random Random { get; init; } = Random.Shared;

    /// <summary>PID процесса службы BFE: смена означает перезапуск BFE и потерю static-фильтров.</summary>
    public Func<uint> BfeProcessId { get; init; } = () => 0;

    /// <summary>
    /// Код и время завершения последнего соединения указанной записи RAS после указанного момента (журнал
    /// RasClient, событие 20226). 631 — отключение пользователем (меню сети Windows, rasdial), остальное — обрыв;
    /// null — неизвестно.
    /// </summary>
    public Func<DateTimeOffset, string, RasTermination?> RasTerminationReason { get; init; } = (_, _) => null;

    /// <summary>Время с загрузки Windows: автоподключение срабатывает только при запуске системы.</summary>
    public Func<TimeSpan> SystemUptime { get; init; } = () => TimeSpan.FromMilliseconds(Environment.TickCount64);

    /// <summary>
    /// Идентификатор текущей загрузки Windows, не зависящий от настенных часов; null — недоступен (тогда загрузка
    /// узнаётся по времени). По нему автоподключение срабатывает один раз за загрузку.
    /// </summary>
    public Func<string?> BootId { get; init; } = WindowsBootId.Read;

    /// <summary>Конфликты с другими программами: чужие VPN-соединения, маршруты на туннеле, жёсткие разрешения WFP.</summary>
    public Func<Windows.Diagnostics.ConflictInputs, IReadOnlyList<Core.Ipc.StatusWarning>> DetectConflicts { get; init; } = _ => [];

    /// <summary>
    /// Подписка на системные уведомления о смене сети (интерфейс, адрес, маршрут по умолчанию). Обработчик
    /// вызывается из чужого потока. null — подписки нет, изменения замечает только периодический тик.
    /// </summary>
    public Func<Action, IDisposable?> SubscribeNetworkChanges { get; init; } = _ => null;

    /// <summary>
    /// Подписка на события службы автонастройки WLAN (подключение Wi-Fi, повторная проверка безопасности,
    /// восстановление адаптера). Обработчик вызывается из чужого потока. null — подписки нет.
    /// </summary>
    public Func<Action<WifiEvent>, IDisposable?> SubscribeWifiEvents { get; init; } = _ => null;

    /// <summary>
    /// Отключает переподключение Wi-Fi диспетчером подключений Windows (<see cref="Windows.Net.WcmBadStateTracking"/>);
    /// true - реестр изменён сейчас. В тестах реестр не трогается.
    /// </summary>
    public Func<bool> DisableWifiBadStateTracking { get; init; } = () => false;

    /// <summary>Каталог записей подключения Wi-Fi (<c>wifi-incident-*.log</c>); null — записи остаются в памяти.</summary>
    public string? WifiIncidentDirectory { get; init; }

    /// <summary>Лимитная сеть (мобильная точка доступа и т. п.): фоновая загрузка базы откладывается.</summary>
    public Func<bool> IsMeteredNetwork { get; init; } = () => false;

    /// <summary>Подробный журнал на срок; в тестах, где он не нужен, — нет.</summary>
    public Diagnostics.VerboseMode? Verbose { get; init; }

    /// <summary>Сбор части службы для архива разбора; нет — архив недоступен.</summary>
    public Diagnostics.DiagnosticsCollector? DiagnosticsCollector { get; init; }

    /// <summary>Собранные архивы до выдачи интерфейсу.</summary>
    public Diagnostics.DiagnosticsPackages? DiagnosticsPackages { get; init; }
}

/// <summary>
/// Номер загрузки Windows: значение BootId в PrefetchParameters диспетчера памяти. Windows увеличивает его при каждой
/// загрузке, и от настенных часов оно не зависит.
/// </summary>
internal static class WindowsBootId
{
    private const string Key = @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";

    public static string? Read()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(Key);
            return key?.GetValue("BootId") is int value
                ? value.ToString(System.Globalization.CultureInfo.InvariantCulture)
                : null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // Нет значения или доступа: загрузка узнаётся по времени, как прежде.
            return null;
        }
    }
}
