using System.IO;
using SplitVpn.Core.Diagnostics;

namespace SplitVpn.App.Services;

/// <summary>
/// Подробный журнал интерфейса: %LOCALAPPDATA%\SplitVpn\ui-verbose.log. Включается вместе со службой —
/// срок приходит в состоянии службы, а если служба недоступна или отказала, читается из реестра: именно
/// такой интерфейс и должен записать, почему ему отказывают.
/// </summary>
public static class UiVerbose
{
    private static readonly TimeSpan RegistryInterval = TimeSpan.FromSeconds(10);
    private static RollingTextLog? _log;
    private static DateTimeOffset _registryReadAt = DateTimeOffset.MinValue;

    public static string LogPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SplitVpn", "ui-verbose.log");

    /// <summary>До какого момента включён режим; null — выключен.</summary>
    public static DateTimeOffset? Until { get; private set; }

    /// <summary>Подключить журнал и сразу узнать о режиме из реестра — до первого ответа службы.</summary>
    public static void Start()
    {
        _log = new RollingTextLog(LogPath, TimeProvider.System);
        Verbose.Sink = _log.Write;
        RefreshFromRegistry(force: true);
    }

    /// <summary>Срок из состояния службы.</summary>
    public static void Apply(DateTimeOffset? until) => Set(until is { } value && value > DateTimeOffset.UtcNow ? value : null);

    /// <summary>Служба не ответила: срок из реестра, не чаще раза в 10 секунд.</summary>
    public static void RefreshFromRegistry(bool force = false)
    {
        var now = DateTimeOffset.UtcNow;
        if (!force && now - _registryReadAt < RegistryInterval)
        {
            return;
        }

        _registryReadAt = now;
        Set(VerboseRegistry.Read(now));
    }

    private static void Set(DateTimeOffset? until)
    {
        if (until == Until)
        {
            return;
        }

        var wasOn = Until is not null;
        Until = until;
        if (until is not null && !wasOn)
        {
            Verbose.Set(true);
            Verbose.Write("Ui", "подробный журнал включён; окружение: " + string.Join("; ",
                ClientEnvironment.Describe().Select(p => p.Key + " = " + p.Value)));
        }
        else if (until is null)
        {
            Verbose.Write("Ui", "подробный журнал выключен");
            Verbose.Set(false);
        }
    }
}
