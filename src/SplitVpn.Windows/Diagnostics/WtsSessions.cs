using System.Runtime.InteropServices;

namespace SplitVpn.Windows.Diagnostics;

/// <summary>Сеанс Windows: номер, состояние, пользователь (пустой — никто не вошёл), имя станции.</summary>
public sealed record WtsSession(int Id, string State, string User, string WinStation, string ClientName);

/// <summary>
/// Сеансы Windows на этом компьютере: кто вошёл, кто отключён, где консоль. Нужны журналу, когда проблема
/// появляется при входе под другим пользователем или при быстром переключении.
/// </summary>
public static partial class WtsSessions
{
    private const int WtsUserName = 5;
    private const int WtsWinStationName = 6;
    private const int WtsDomainName = 7;
    private const int WtsClientName = 10;

    private static readonly string[] States =
        ["активен", "подключён", "подключается", "теневой", "отключён", "простаивает", "ожидание", "сброс", "не работает", "инициализация"];

    /// <summary>Все сеансы; пустой список — перечислить не удалось.</summary>
    public static IReadOnlyList<WtsSession> Enumerate()
    {
        if (!WTSEnumerateSessionsW(0, 0, 1, out var buffer, out var count))
        {
            return [];
        }

        try
        {
            var result = new List<WtsSession>(count);
            var size = Marshal.SizeOf<SessionInfo>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<SessionInfo>(buffer + (i * size));
                result.Add(new WtsSession(info.SessionId, StateName(info.State), UserOf(info.SessionId),
                    Marshal.PtrToStringUni(info.WinStationName) ?? "", Query(info.SessionId, WtsClientName)));
            }

            return result;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    /// <summary>«ДОМЕН\пользователь» сеанса; пусто — никто не вошёл или сеанс уже закрыт.</summary>
    public static string UserOf(int sessionId)
    {
        var user = Query(sessionId, WtsUserName);
        if (user.Length == 0)
        {
            return "";
        }

        var domain = Query(sessionId, WtsDomainName);
        return domain.Length == 0 ? user : domain + "\\" + user;
    }

    /// <summary>Имя станции сеанса: Console, RDP-Tcp#3 и т. п.</summary>
    public static string WinStationOf(int sessionId) => Query(sessionId, WtsWinStationName);

    private static string StateName(int state) => state >= 0 && state < States.Length ? States[state] : state.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static string Query(int sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformationW(0, sessionId, infoClass, out var buffer, out _))
        {
            return "";
        }

        try
        {
            return Marshal.PtrToStringUni(buffer) ?? "";
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SessionInfo
    {
        public int SessionId;
        public nint WinStationName;
        public int State;
    }

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSEnumerateSessionsW(nint server, int reserved, int version, out nint sessionInfo, out int count);

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSQuerySessionInformationW(nint server, int sessionId, int infoClass, out nint buffer, out int bytesReturned);

    [LibraryImport("wtsapi32.dll")]
    private static partial void WTSFreeMemory(nint memory);
}
