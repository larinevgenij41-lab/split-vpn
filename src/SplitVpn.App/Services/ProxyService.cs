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
public sealed class ProxyService(IProxySettings settings)
{
    private readonly ProxyApplier _applier = new(settings, Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SplitVpn", "proxy-backup.json"));

    /// <summary>Нужный PAC по состоянию службы; null в статусе (служба недоступна) ничего не меняет.</summary>
    public string? OnStatus(StatusDto? status)
    {
        if (status is null)
        {
            return null;
        }

        var pac = status.Tunnels
            .Where(t => t.State == ConnectionState.Connected)
            .Select(t => t.ServerNetworks)
            .FirstOrDefault(n => n is { ApplyProxy: true, ProxyPac.Length: > 0 })?.ProxyPac;
        return Sync(pac) is ProxyOutcome.Applied ? "Применён прокси шлюза AnyConnect." : null;
    }

    /// <summary>Выход интерфейса: вернуть исходный прокси.</summary>
    public void Restore() => Sync(null);

    private ProxyOutcome Sync(string? pac)
    {
        try
        {
            return _applier.Sync(pac);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception)
        {
            // Прокси — удобство, а не защита: сбой не должен ломать интерфейс.
            return ProxyOutcome.None;
        }
    }
}

/// <summary>Прокси подключения по локальной сети через WinINet (INTERNET_OPTION_PER_CONNECTION_OPTION).</summary>
public sealed unsafe partial class WinInetProxySettings : IProxySettings
{
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
            InternetSetOption(0, OptionSettingsChanged, null, 0);
            InternetSetOption(0, OptionRefresh, null, 0);
        }
        finally
        {
            if (url != 0)
            {
                Marshal.FreeHGlobal(url);
            }
        }
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
