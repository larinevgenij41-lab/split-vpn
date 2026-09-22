using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Net;
using Windows.Win32;
using Windows.Win32.NetworkManagement.Rras;
using static SplitVpn.Windows.Ras.RasConstants;

namespace SplitVpn.Windows.Ras;

public readonly record struct RasConnectionHandle(nint Value)
{
    internal HRASCONN Native => new(Value);

    internal static unsafe RasConnectionHandle From(HRASCONN handle) => new((nint)handle.Value);
}

public sealed record RasActiveConnection(RasConnectionHandle Handle, string EntryName, string Phonebook, Guid EntryGuid);

public sealed record RasProjection(uint ClientAddress, uint ServerAddress);

public enum RasConnectionStatus
{
    Connecting,
    Connected,
    Disconnected,
    Gone,
}

public sealed record RasDialResult(bool Success, RasConnectionHandle? Handle, uint ErrorCode, string? ErrorText);

public sealed record RasStatistics(ulong BytesSent, ulong BytesReceived, TimeSpan Duration);

/// <summary>Дозвон, отключение и наблюдение за SSTP-соединениями своей телефонной книги.</summary>
public static class RasClient
{
    private const uint RasCsConnected = 0x2000;
    private const uint RasCsDisconnected = 0x2001;

    private static readonly ConcurrentDictionary<nuint, DialOperation> Operations = new();
    private static long _nextOperationId;

    /// <summary>
    /// Асинхронный дозвон. Пароль копируется в RASDIALPARAMS и затирается сразу после вызова RasDial.
    /// При таймауте или отмене соединение разрывается.
    /// </summary>
    public static async Task<RasDialResult> DialAsync(
        string phonebookPath,
        string entryName,
        string userName,
        ReadOnlyMemory<char> password,
        string? domain,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        byte[]? eapIdentity = null,
        bool machineAuthentication = false)
    {
        // Несостоявшийся дозвон держит запись занятой ещё после RasHangUp: новый RasDial вернул бы 756.
        await HangUpLeftoversAsync(phonebookPath, entryName);

        var operationId = (nuint)Interlocked.Increment(ref _nextOperationId);
        var operation = new DialOperation();
        Operations[operationId] = operation;
        var pinnedEap = GCHandle.Alloc(eapIdentity ?? [], GCHandleType.Pinned);
        try
        {
            var start = StartDial(phonebookPath, entryName, userName, password.Span, domain, operationId,
                pinnedEap.AddrOfPinnedObject(), (uint)(eapIdentity?.Length ?? 0), machineAuthentication, out var handle);
            operation.Handle = handle;
            if (start != ErrorSuccess)
            {
                await HangUpQuietlyAsync(RasConnectionHandle.From(handle));
                return Failed(start);
            }

            return await WaitAsync(operation, handle, timeout, cancellationToken);
        }
        finally
        {
            Operations.TryRemove(operationId, out _);
            pinnedEap.Free();
        }
    }

    private static async Task HangUpLeftoversAsync(string phonebookPath, string entryName)
    {
        var leftovers = EnumerateConnections().Where(c =>
            string.Equals(c.EntryName, entryName, StringComparison.OrdinalIgnoreCase)
            && SamePhonebook(c.Phonebook, phonebookPath));
        foreach (var leftover in leftovers)
        {
            // Не удалось убрать чужой остаток — дозвон всё равно пробуется: RasDial ответит своим кодом (756).
            await HangUpQuietlyAsync(leftover.Handle);
        }
    }

    /// <summary>
    /// Одна ли это телефонная книга. У соединения без записи в книге (встроенный профиль Windows, rasdial
    /// по имени) путь пуст, а Path.GetFullPath на пустом пути бросает исключение и обрывает обход соединений.
    /// </summary>
    public static bool SamePhonebook(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right))
        {
            return false;
        }

        try
        {
            return string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException or System.Security.SecurityException)
        {
            // Путь с недопустимыми знаками: сравниваем как есть, чтобы обход соединений не прерывался.
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>Разрывает соединение и ждёт, пока RAS освободит дескриптор (требование RasHangUp).</summary>
    public static async Task HangUpAsync(RasConnectionHandle handle, CancellationToken cancellationToken)
    {
        if (handle.Value == 0)
        {
            return;
        }

        var code = PInvoke.RasHangUp(handle.Native);
        if (!AlreadyGone(code))
        {
            throw new NativeCallException("RasHangUp", code);
        }

        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (GetStatus(handle).Status != RasConnectionStatus.Gone && DateTime.UtcNow < deadline)
        {
            await Task.Delay(50, cancellationToken);
        }
    }

    /// <summary>
    /// Разрывать уже разорванное соединение — не ошибка. Неудачный дозвон оставляет соединение в этом
    /// состоянии, и RasHangUp отвечает «подключение разорвано» (668) или «порт не открыт» (618): считать
    /// это сбоем нельзя, иначе уборка после дозвона подменила бы собой настоящую причину отказа.
    /// </summary>
    private static bool AlreadyGone(uint code) => code is ErrorSuccess or ErrorInvalidHandle
        or ErrorNoConnection or ErrorPortNotOpen or ErrorPortDisconnected or ErrorAlreadyDisconnecting;

    /// <summary>
    /// Уборка за неудавшимся дозвоном: сбой самого разрыва не должен заменить собой ошибку подключения,
    /// ради которой этот разрыв и делается, — иначе пользователь видит «RasHangUp», а не настоящую причину.
    /// </summary>
    private static async Task HangUpQuietlyAsync(RasConnectionHandle handle)
    {
        try
        {
            await HangUpAsync(handle, CancellationToken.None);
        }
        catch (NativeCallException)
        {
            // Соединение осталось за RAS: следующий дозвон уберёт его как остаток (HangUpLeftoversAsync).
        }
    }

    public static unsafe (RasConnectionStatus Status, uint Error) GetStatus(RasConnectionHandle handle)
    {
        var status = new RASCONNSTATUSW { dwSize = (uint)sizeof(RASCONNSTATUSW) };
        var code = PInvoke.RasGetConnectStatus(handle.Native, ref status);
        if (code == ErrorInvalidHandle)
        {
            return (RasConnectionStatus.Gone, 0);
        }

        NativeCallException.ThrowIfFailed(code, "RasGetConnectStatus");
        var state = (uint)status.rasconnstate;
        return state switch
        {
            RasCsConnected => (RasConnectionStatus.Connected, 0),
            RasCsDisconnected => (RasConnectionStatus.Disconnected, status.dwError),
            _ => (RasConnectionStatus.Connecting, status.dwError),
        };
    }

    /// <summary>Активные соединения; для подхвата фильтруются по пути телефонной книги.</summary>
    public static unsafe IReadOnlyList<RasActiveConnection> EnumerateConnections()
    {
        var count = 4;
        while (true)
        {
            var buffer = new RASCONNW[count];
            buffer[0].dwSize = (uint)sizeof(RASCONNW);
            var size = (uint)(sizeof(RASCONNW) * count);
            var code = PInvoke.RasEnumConnections(buffer, ref size, out var returned);
            if (code == ErrorBufferTooSmall)
            {
                count = (int)(size / sizeof(RASCONNW)) + 1;
                continue;
            }

            NativeCallException.ThrowIfFailed(code, "RasEnumConnections");
            return buffer.Take((int)returned).Select(c => new RasActiveConnection(
                RasConnectionHandle.From(c.hrasconn),
                c.szEntryName.AsReadOnlySpan().SliceAtNull().ToString(),
                c.szPhonebook.AsReadOnlySpan().SliceAtNull().ToString(),
                c.guidEntry)).ToList();
        }
    }

    public static unsafe RasProjection GetProjection(RasConnectionHandle handle)
    {
        var info = new RAS_PROJECTION_INFO { version = (RASAPIVERSION)RasApiVersionCurrent };
        var size = (uint)sizeof(RAS_PROJECTION_INFO);
        var code = PInvoke.RasGetProjectionInfoEx(handle.Native, ref info, ref size);
        if (code == ErrorBufferTooSmall)
        {
            using var arena = new NativeArena();
            var buffer = (RAS_PROJECTION_INFO*)arena.Alloc<byte>(checked((int)size));
            buffer->version = (RASAPIVERSION)RasApiVersionCurrent;
            code = PInvoke.RasGetProjectionInfoEx(handle.Native, buffer, &size);
            NativeCallException.ThrowIfFailed(code, "RasGetProjectionInfoEx");
            return Projection(*buffer);
        }
        NativeCallException.ThrowIfFailed(code, "RasGetProjectionInfoEx");
        return Projection(info);
    }

    internal static RasProjection Projection(RAS_PROJECTION_INFO info)
    {
        if (info.type == RASPROJECTION_INFO_TYPE.PROJECTION_INFO_TYPE_IKEv2)
        {
            return new RasProjection(NetInventory.ToHostOrder(info.ikev2.ipv4Address.S_un.S_addr),
                NetInventory.ToHostOrder(info.ikev2.ipv4ServerAddress.S_un.S_addr));
        }

        return new RasProjection(
            NetInventory.ToHostOrder(info.ppp.ipv4Address.S_un.S_addr),
            NetInventory.ToHostOrder(info.ppp.ipv4ServerAddress.S_un.S_addr));
    }

    public static unsafe RasStatistics GetStatistics(RasConnectionHandle handle)
    {
        var stats = new RAS_STATS { dwSize = (uint)sizeof(RAS_STATS) };
        var code = PInvoke.RasGetConnectionStatistics(handle.Native, ref stats);
        NativeCallException.ThrowIfFailed(code, "RasGetConnectionStatistics");
        return new RasStatistics(stats.dwBytesXmited, stats.dwBytesRcved, TimeSpan.FromMilliseconds(stats.dwConnectDuration));
    }

    /// <summary>Текст кода ошибки: коды RAS спрашиваются у RAS, остальные (в том числе CryptoAPI) — у системы.</summary>
    public static string ErrorText(uint code) => NativeCallException.Describe(code);

    private static unsafe uint StartDial(
        string phonebookPath,
        string entryName,
        string userName,
        ReadOnlySpan<char> password,
        string? domain,
        nuint operationId,
        nint eapData,
        uint eapSize,
        bool machineAuthentication,
        out HRASCONN handle)
    {
        var parameters = new RASDIALPARAMSW { dwSize = (uint)sizeof(RASDIALPARAMSW), dwCallbackId = operationId };
        try
        {
            CopyTo(entryName, parameters.szEntryName.AsSpan());
            CopyTo(userName, parameters.szUserName.AsSpan());
            CopyTo(password, parameters.szPassword.AsSpan());
            CopyTo(domain ?? "", parameters.szDomain.AsSpan());
            delegate* unmanaged[Stdcall]<nuint, uint, HRASCONN, uint, RASCONNSTATE, uint, uint, uint> callback = &OnDialEvent;
            var extensions = new RASDIALEXTENSIONS
            {
                dwSize = (uint)sizeof(RASDIALEXTENSIONS),
                dwfOptions = PInvoke.RDEOPT_DisableConnectedUI | PInvoke.RDEOPT_DisableReconnectUI | PInvoke.RDEOPT_DisableReconnect
                    | (machineAuthentication ? PInvoke.RDEOPT_NoUser : 0),
                RasEapInfo = new RASEAPINFO { dwSizeofEapInfo = eapSize, pbEapInfo = (byte*)eapData },
            };
            return PInvoke.RasDial(extensions, phonebookPath, parameters, NotifierTypeRasDialFunc2, (void*)callback, out handle);
        }
        finally
        {
            parameters.szPassword.AsSpan().Clear();
        }
    }

    private static async Task<RasDialResult> WaitAsync(DialOperation operation, HRASCONN handle, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var connection = RasConnectionHandle.From(handle);
        try
        {
            var error = await operation.Completion.Task.WaitAsync(timeout, cancellationToken);
            if (error == ErrorSuccess)
            {
                return new RasDialResult(true, connection, 0, null);
            }

            await HangUpQuietlyAsync(connection);
            return Failed(error);
        }
        catch (TimeoutException)
        {
            await HangUpQuietlyAsync(connection);
            return new RasDialResult(false, null, 0, "Превышено время ожидания подключения.");
        }
        catch (OperationCanceledException)
        {
            await HangUpQuietlyAsync(connection);
            throw;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static uint OnDialEvent(nuint callbackId, uint subEntry, HRASCONN handle, uint message, RASCONNSTATE state, uint error, uint extendedError)
    {
        if (!Operations.TryGetValue(callbackId, out var operation))
        {
            return 0;
        }

        if (error != ErrorSuccess)
        {
            operation.Completion.TrySetResult(error);
            return 0;
        }

        switch ((uint)state)
        {
            case RasCsConnected:
                operation.Completion.TrySetResult(ErrorSuccess);
                return 0;
            case RasCsDisconnected:
                operation.Completion.TrySetResult(extendedError != 0 ? extendedError : 1);
                return 0;
            default:
                return 1;
        }
    }

    private static void CopyTo(ReadOnlySpan<char> value, Span<char> target)
    {
        if (value.Length >= target.Length)
        {
            throw new ArgumentException("Значение не помещается в поле RAS.");
        }

        target.Clear();
        value.CopyTo(target);
    }

    private static RasDialResult Failed(uint code) => new(false, null, code, ErrorText(code));

    private sealed class DialOperation
    {
        public TaskCompletionSource<uint> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public HRASCONN Handle { get; set; }
    }
}
