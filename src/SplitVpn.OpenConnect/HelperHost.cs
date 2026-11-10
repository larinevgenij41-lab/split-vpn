using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;

namespace SplitVpn.OpenConnect;

/// <summary>
/// Канал помощника со службой: читает кадры команд, пишет кадры событий. Первая команда — Start,
/// сеанс идёт в отдельном потоке; конец канала (служба завершилась) равен команде Stop.
/// </summary>
internal sealed class HelperHost(Stream input, Stream output, Func<OcSession> createSession) : IHelperOutput
{
    private readonly object _writeLock = new();

    /// <summary>Работает до завершения сеанса; возвращает код выхода процесса.</summary>
    public int Run()
    {
        var first = ReadCommand();
        if (first is not StartCommand start)
        {
            // Служба закрыла канал или прислала не Start — сеанс не начинается.
            return first is null ? 0 : 2;
        }

        using var session = createSession();
        var kind = TerminationKind.Internal;
        var worker = new Thread(() => kind = session.Run(start)) { IsBackground = true, Name = "openconnect-session" };
        worker.Start();

        var pump = new Thread(() =>
        {
            while (ReadCommand() is { } command)
            {
                session.Post(command);
            }

            session.RequestStop();
        }) { IsBackground = true, Name = "helper-commands" };
        pump.Start();

        worker.Join();
        return kind is TerminationKind.Cancelled or TerminationKind.AuthRejected or TerminationKind.SessionExpired ? 0 : 1;
    }

    public void Send(HelperEvent helperEvent)
    {
        lock (_writeLock)
        {
            try
            {
                FrameCodec.WriteAsync(output, HelperContract.Serialize(helperEvent), CancellationToken.None).GetAwaiter().GetResult();
            }
            catch (IOException)
            {
                // Служба закрыла канал: событие некому доставить, сеанс остановит поток команд.
            }
        }
    }

    private HelperCommand? ReadCommand()
    {
        try
        {
            while (true)
            {
                var payload = FrameCodec.ReadAsync(input, CancellationToken.None).GetAwaiter().GetResult();
                if (payload is null)
                {
                    return null;
                }

                if (HelperContract.TryDeserializeCommand(payload) is { } command)
                {
                    return command;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or IpcProtocolException or ObjectDisposedException)
        {
            return null;
        }
    }
}
