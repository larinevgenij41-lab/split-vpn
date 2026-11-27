using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;

namespace SplitVpn.App.Services;

/// <summary>
/// PAC-прокси шлюза AnyConnect в настройках пользователя. Ставится, пока туннель подключён и в профиле включено
/// «Применять прокси шлюза»; снимается при отключении, выходе интерфейса и при следующем запуске после сбоя.
/// Служба работает от SYSTEM и прокси пользователя поставить не может — это делает интерфейс в его сеансе.
/// </summary>
public sealed class ProxyService : IDisposable
{
    private readonly IProxySettings _settings;
    private readonly string _directoryPath;
    private readonly string _leasePath;
    private readonly string _backupPath;
    private readonly ProxyApplier _applier;
    private readonly object _gate = new();
    private FileStream? _lease;
    private bool _closed;
    private long _version;

    public ProxyService(IProxySettings settings)
        : this(settings, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SplitVpn")) { }

    internal ProxyService(IProxySettings settings, string directoryPath)
    {
        _settings = settings;
        _directoryPath = directoryPath;
        _leasePath = Path.Combine(directoryPath, "proxy-session.lock");
        _backupPath = Path.Combine(directoryPath, "proxy-backup.json");
        _applier = new ProxyApplier(settings, _backupPath);
    }

    /// <summary>Последняя синхронизация прошла успешно: прокси приведён к <see cref="_syncedPac"/>.</summary>
    private bool _synced;

    private string? _syncedPac;

    /// <summary>
    /// Делать нечего: желаемый PAC тот же, что при последней успешной синхронизации, и копия исходного прокси на месте,
    /// только пока PAC применён. Статус приходит раз в 1,5-5 с, и без этой проверки каждый раз брались бы межпроцессные
    /// блокировки (мьютекс - с ожиданием до 2 с). Копия, оставшаяся после аварийного выхода или от другой копии
    /// интерфейса, и пропавшая копия при применённом PAC ведут к обычной синхронизации; первый вызов идёт всегда.
    /// </summary>
    private bool UpToDate(string? pac) =>
        _synced && string.Equals(_syncedPac, pac, StringComparison.Ordinal) && File.Exists(_backupPath) == (pac is not null);

    public async Task<string?> UpdateAsync(StatusDto? status, bool stopped)
    {
        if (status is null && !stopped) { return null; }
        var pac = status?.Tunnels.Where(t => t.State == ConnectionState.Connected).Select(t => t.ServerNetworks)
            .FirstOrDefault(n => n is { ApplyProxy: true, ProxyPac.Length: > 0 })?.ProxyPac;
        var version = Interlocked.Increment(ref _version);
        return await Task.Run(() =>
        {
            lock (_gate)
            {
                if (_closed || _closing || version != Interlocked.Read(ref _version) || UpToDate(pac)) { return null; }
                var error = Sync(pac, exiting: false, out var busy);
                // Занято другой копией: не ошибка для пользователя, но и не синхронизировано — повтор на следующем опросе.
                _synced = error is null && !busy;
                _syncedPac = pac;
                return error;
            }
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// Ожидание фоновой синхронизации при выходе. Одна синхронизация держит блокировку до ~4 с (ожидание межпроцессной
    /// блокировки 2 с и WinINet); дольше — значит, она зависла, и выход не должен висеть вместе с ней.
    /// </summary>
    public static readonly TimeSpan ExitWait = TimeSpan.FromSeconds(5);

    /// <summary>Выход начат: синхронизации, ждущие своей очереди, прокси уже не применяют.</summary>
    private volatile bool _closing;

    public void Dispose() => Close(ExitWait);

    /// <summary>
    /// Снять свой прокси шлюза и больше его не ставить. Ожидание идущей фоновой синхронизации ограничено
    /// <paramref name="wait"/>: false — не дождались, прокси не снят (его снимет следующий запуск интерфейса по копии
    /// исходного прокси); повторный вызов снова попробует снять.
    /// </summary>
    public bool Close(TimeSpan wait)
    {
        _closing = true;
        if (!Monitor.TryEnter(_gate, wait))
        {
            Verbose.Write("Proxy", "Прокси при выходе не снят: синхронизация не закончилась за " + wait.TotalSeconds + " с");
            return false;
        }

        try
        {
            if (_closed) { return true; }
            _closed = true;
            // Занято другой копией: снимать не будем — оставшаяся копия снимет прокси сама (как до аудита блокировок).
            if (_lease is not null) { Sync(null, exiting: true, out _); }
            _lease?.Dispose();
            return true;
        }
        finally
        {
            Monitor.Exit(_gate);
        }
    }

    /// <summary>Имя межпроцессного мьютекса; в проверках подменяется, по умолчанию Global\SplitVpn.Proxy.&lt;SID&gt;.</summary>
    internal string? MutexName { get; init; }

    private static string DefaultMutexName()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return @"Global\SplitVpn.Proxy." + identity.User!.Value;
    }

    /// <param name="busy">Блокировку держит другая копия интерфейса: ничего не сделано, ошибки нет, повторить позже.</param>
    private string? Sync(string? pac, bool exiting, out bool busy)
    {
        busy = false;
        try
        {
            // Снятие прокси при отключении и выходе не должно зависеть от мьютекса: его имя может занять
            // другой пользователь компьютера. Берутся файловая блокировка в профиле и мьютекс; без мьютекса -
            // под одной файловой, без обеих (обе недоступны) - без блокировки (UserGate). Файловую держит другая
            // копия этого пользователя - «занято»: параллельно с ней копию исходного прокси не пишем.
            using var gate = UserGate.Enter(MutexName ?? DefaultMutexName(), Path.Combine(_directoryPath, "proxy-sync.lock"), TimeSpan.FromSeconds(2), "Proxy");
            Directory.CreateDirectory(_directoryPath);
            if (exiting)
            {
                _lease?.Dispose();
                _lease = null;
                try { using var last = File.Open(_leasePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
                catch (IOException ex) when ((ex.HResult & 0xffff) == 32) { return null; }
            }
            else
            {
                _lease ??= File.Open(_leasePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
            }
            _applier.Sync(pac);
            if (_settings is WinInetProxySettings windows) { windows.NotifyChanges(); }
            return null;
        }
        catch (UserGateBusyException ex)
        {
            Verbose.Write("Proxy", "Прокси не обновлён, повтор позже: " + ex.Message);
            busy = true;
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
        {
            Verbose.Write("Proxy", "Не удалось обновить прокси: " + ex.Message);
            // Системный текст — в журнал; пользователю — что это значит для браузеров.
            return "Не удалось обновить прокси Windows: браузеры могут идти мимо прокси шлюза AnyConnect. Повторная попытка — при следующем изменении состояния.";
        }
    }
}

/// <summary>Прокси подключения по локальной сети через WinINet (INTERNET_OPTION_PER_CONNECTION_OPTION).</summary>
public sealed unsafe partial class WinInetProxySettings : IProxySettings
{
    private bool _notifyPending;
    private const int OptionPerConnection = 75;
    private const int OptionSettingsChanged = 39;
    private const int OptionRefresh = 37;
    private const int PerConnFlags = 1;
    private const int PerConnAutoConfigUrl = 4;

    public ProxyState Read()
    {
        var options = stackalloc PerConnOption[2];
        options[0].Option = PerConnFlags;
        options[1].Option = PerConnAutoConfigUrl;
        var list = NewList(options, 2);
        var size = (uint)sizeof(PerConnOptionList);
        if (!InternetQueryOption(0, OptionPerConnection, &list, &size))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Не удалось прочитать настройки прокси");
        }

        var url = options[1].Value == 0 ? null : Marshal.PtrToStringUni(options[1].Value);
        if (options[1].Value != 0)
        {
            GlobalFree(options[1].Value);
        }

        return new ProxyState((int)options[0].Value, url);
    }

    public void Write(ProxyState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var url = state.AutoConfigUrl is null ? 0 : Marshal.StringToHGlobalUni(state.AutoConfigUrl);
        try
        {
            var options = stackalloc PerConnOption[2];
            options[0].Option = PerConnFlags;
            options[0].Value = state.Flags;
            options[1].Option = PerConnAutoConfigUrl;
            options[1].Value = url;
            var list = NewList(options, 2);
            if (!InternetSetOption(0, OptionPerConnection, &list, (uint)sizeof(PerConnOptionList)))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Не удалось изменить настройки прокси");
            }

            // Запущенные браузеры перечитывают настройки только по оповещению.
            _notifyPending = true;
        }
        finally
        {
            if (url != 0)
            {
                Marshal.FreeHGlobal(url);
            }
        }
    }

    internal void NotifyChanges()
    {
        if (!_notifyPending) { return; }
        if (!InternetSetOption(0, OptionSettingsChanged, null, 0) || !InternetSetOption(0, OptionRefresh, null, 0))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Обновлённые настройки прокси не переданы браузерам");
        }
        _notifyPending = false;
    }

    private static PerConnOptionList NewList(PerConnOption* options, int count) => new()
    {
        Size = (uint)sizeof(PerConnOptionList),
        OptionCount = (uint)count,
        Options = options,
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct PerConnOptionList
    {
        public uint Size;
        public nint Connection;
        public uint OptionCount;
        public uint OptionError;
        public PerConnOption* Options;
    }

    /// <summary>INTERNET_PER_CONN_OPTIONW: номер опции и объединение DWORD/LPWSTR/FILETIME (8 байт на x64).</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct PerConnOption
    {
        public int Option;
        public nint Value;
    }

    [LibraryImport("wininet.dll", EntryPoint = "InternetQueryOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool InternetQueryOption(nint handle, int option, void* buffer, uint* length);

    [LibraryImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool InternetSetOption(nint handle, int option, void* buffer, uint length);

    [LibraryImport("kernel32.dll")]
    private static partial nint GlobalFree(nint memory);
}
