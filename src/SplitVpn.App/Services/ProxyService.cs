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
        _applier = new ProxyApplier(settings, Path.Combine(directoryPath, "proxy-backup.json"));
    }

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
                if (_closed || version != Interlocked.Read(ref _version)) { return null; }
                return Sync(pac, exiting: false);
            }
        }).ConfigureAwait(false);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_closed) { return; }
            _closed = true;
            if (_lease is not null) { Sync(null, exiting: true); }
            _lease?.Dispose();
        }
    }

    private string? Sync(string? pac, bool exiting)
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            using var gate = new Mutex(false, @"Global\SplitVpn.Proxy." + identity.User!.Value);
            try
            {
                if (!gate.WaitOne(TimeSpan.FromSeconds(2))) { return "Не удалось обновить прокси: настройки заняты другим сеансом."; }
            }
            catch (AbandonedMutexException) { /* Завершившийся процесс освободил блокировку. */ }
            try
            {
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
            finally { gate.ReleaseMutex(); }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
        {
            Verbose.Write("Proxy", "Не удалось обновить прокси: " + ex.Message);
            return "Не удалось обновить прокси Windows: " + ex.Message;
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
