using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Windows.Operations;
using Windows.Win32;
using Windows.Win32.System.JobObjects;

namespace SplitVpn.Windows.OpenConnect;

/// <summary>
/// Запускает SplitVpn.OpenConnect.exe из каталога службы с парой анонимных труб. Процессы помещаются в Job
/// с KILL_ON_JOB_CLOSE: если служба упала, помощник не переживёт её. Помощник и сам выходит, когда
/// служба закрывает канал.
/// </summary>
public sealed class SystemAnyConnectOps : IAnyConnectOps, IDisposable
{
    public const string HelperFileName = "SplitVpn.OpenConnect.exe";

    private readonly string _helperPath;
    private readonly SafeFileHandle _job;

    public SystemAnyConnectOps(string helperPath)
    {
        _helperPath = helperPath;
        _job = CreateKillOnCloseJob();
    }

    public IAnyConnectSession Start(Action<HelperEvent> onEvent)
    {
        ArgumentNullException.ThrowIfNull(onEvent);
        if (!File.Exists(_helperPath))
        {
            throw new FileNotFoundException("Не найден помощник AnyConnect: переустановите программу.", _helperPath);
        }

        var toHelper = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable);
        var fromHelper = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        try
        {
            var start = new ProcessStartInfo(_helperPath) { UseShellExecute = false, CreateNoWindow = true };
            start.ArgumentList.Add("--pipes");
            start.ArgumentList.Add(toHelper.GetClientHandleAsString());
            start.ArgumentList.Add(fromHelper.GetClientHandleAsString());
            var process = Process.Start(start) ?? throw new InvalidOperationException("Помощник AnyConnect не запустился.");
            toHelper.DisposeLocalCopyOfClientHandle();
            fromHelper.DisposeLocalCopyOfClientHandle();
            if (!PInvoke.AssignProcessToJobObject(_job, process.SafeHandle))
            {
                // Не критично: помощник всё равно выходит при закрытии канала.
                Trace.TraceWarning("AssignProcessToJobObject: " + Marshal.GetLastPInvokeError());
            }

            return new HelperSession(process, toHelper, fromHelper, onEvent);
        }
        catch
        {
            toHelper.Dispose();
            fromHelper.Dispose();
            throw;
        }
    }

    public void Dispose() => _job.Dispose();

    private static unsafe SafeFileHandle CreateKillOnCloseJob()
    {
        var job = PInvoke.CreateJobObject(null, null);
        if (job.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Не удалось создать Job для помощников AnyConnect");
        }

        var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!PInvoke.SetInformationJobObject((global::Windows.Win32.Foundation.HANDLE)job.DangerousGetHandle(), JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation, &limits, (uint)sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)))
        {
            var error = Marshal.GetLastPInvokeError();
            job.Dispose();
            throw new Win32Exception(error, "Не удалось настроить Job для помощников AnyConnect");
        }

        return job;
    }

    /// <summary>
    /// Сеанс помощника. Команды уходят через отдельную ограниченную очередь: помощник мог перестать читать
    /// канал, а труба — заполниться. Синхронная запись из очереди координатора тогда остановила бы службу
    /// целиком, и остановка тоже не началась бы — она ждала бы того же замка.
    /// </summary>
    private sealed class HelperSession : IAnyConnectSession
    {
        /// <summary>Сколько ждать выхода помощника после закрытия канала (BYE на шлюз), прежде чем завершить его.</summary>
        private static readonly TimeSpan ExitGrace = TimeSpan.FromSeconds(15);

        /// <summary>Предел на одну запись в трубу: дольше помощник считается зависшим.</summary>
        private static readonly TimeSpan WriteTimeout = TimeSpan.FromSeconds(10);

        /// <summary>Сколько ждать, пока писатель закончит текущую запись при закрытии сеанса.</summary>
        private static readonly TimeSpan WriteDrainGrace = TimeSpan.FromSeconds(2);

        /// <summary>Глубина очереди команд: столько их не бывает даже при самом длинном входе.</summary>
        private const int MaxPendingCommands = 64;

        private readonly Process _process;
        private readonly AnonymousPipeServerStream _toHelper;
        private readonly AnonymousPipeServerStream _fromHelper;
        private readonly Channel<byte[]> _outgoing = Channel.CreateBounded<byte[]>(
            new BoundedChannelOptions(MaxPendingCommands) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });

        private readonly Task _writer;
        private int _disposed;
        private volatile bool _broken;

        public HelperSession(Process process, AnonymousPipeServerStream toHelper, AnonymousPipeServerStream fromHelper, Action<HelperEvent> onEvent)
        {
            _process = process;
            _toHelper = toHelper;
            _fromHelper = fromHelper;
            _writer = Task.Run(WriteLoopAsync);
            new Thread(() => ReadEvents(onEvent)) { IsBackground = true, Name = "anyconnect-events" }.Start();
        }

        /// <summary>Ставит команду в очередь. Никогда не ждёт: вызывается из очереди актора службы.</summary>
        public bool Send(HelperCommand command)
        {
            if (Volatile.Read(ref _disposed) != 0 || _broken)
            {
                return false;
            }

            return _outgoing.Writer.TryWrite(HelperContract.Serialize(command));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _outgoing.Writer.TryComplete();

            // Конец канала помощник понимает как Stop: даём ему попрощаться со шлюзом, потом завершаем.
            // Ожидание писателя ограничено: зависшая запись не должна задерживать остановку службы.
            _ = Task.Run(async () =>
            {
                using var process = _process;
                try
                {
                    await _writer.WaitAsync(WriteDrainGrace);
                }
                catch (Exception ex) when (ex is TimeoutException or IOException or ObjectDisposedException)
                {
                    // Писатель застрял в трубе: закрытие трубы ниже вытолкнет его из ожидания.
                }

                _toHelper.Dispose();
                try
                {
                    using var timeout = new CancellationTokenSource(ExitGrace);
                    await process.WaitForExitAsync(timeout.Token);
                }
                catch (OperationCanceledException)
                {
                    TryKill(process);
                }
            });
        }

        /// <summary>
        /// Единственный писатель в трубу. Запись за предел означает, что помощник перестал читать: сеанс
        /// признаётся негодным, а процесс завершается независимо от того, чем заняты остальные потоки.
        /// </summary>
        private async Task WriteLoopAsync()
        {
            try
            {
                await foreach (var payload in _outgoing.Reader.ReadAllAsync())
                {
                    // Анонимная труба работает только синхронно: отменить начатую запись нельзя, поэтому
                    // предел ставится гонкой, а выталкивает застрявшую запись закрытие трубы.
                    var write = FrameCodec.WriteAsync(_toHelper, payload, CancellationToken.None);
                    using var delay = new CancellationTokenSource();
                    var finished = await Task.WhenAny(write, Task.Delay(WriteTimeout, delay.Token));
                    if (!ReferenceEquals(finished, write))
                    {
                        Observe(write);
                        Fail("помощник перестал читать канал");
                        return;
                    }

                    await delay.CancelAsync();
                    await write;
                }
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
            {
                Fail(ex.Message);
            }
        }

        /// <summary>Сеанс негоден: команды больше не принимаются, зависший помощник завершается.</summary>
        private void Fail(string reason)
        {
            _broken = true;
            _outgoing.Writer.TryComplete();
            if (Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            Trace.TraceWarning("Помощник AnyConnect не принимает команды: " + reason);
            TryKill(_process);
            _toHelper.Dispose();
        }

        /// <summary>Брошенная запись не должна остаться необработанной ошибкой задачи.</summary>
        private static void Observe(Task task) =>
            _ = task.ContinueWith(t => _ = t.Exception, TaskScheduler.Default);

        private void ReadEvents(Action<HelperEvent> onEvent)
        {
            var terminated = false;
            try
            {
                while (FrameCodec.ReadAsync(_fromHelper, CancellationToken.None).GetAwaiter().GetResult() is { } payload)
                {
                    if (HelperContract.TryDeserializeEvent(payload) is not { } helperEvent)
                    {
                        continue;
                    }

                    terminated |= helperEvent is TerminatedEvent;
                    onEvent(helperEvent);
                }
            }
            catch (Exception ex) when (ex is IOException or IpcProtocolException or ObjectDisposedException)
            {
                // Канал оборван: помощник упал или завершён.
            }
            finally
            {
                _fromHelper.Dispose();
            }

            if (!terminated)
            {
                var code = "нет";
                try
                {
                    code = _process.WaitForExit(2000) ? _process.ExitCode.ToString(System.Globalization.CultureInfo.InvariantCulture) : code;
                }
                catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
                {
                    // Сеанс уже закрыт службой.
                }

                onEvent(new TerminatedEvent(TerminationKind.Internal, $"Помощник AnyConnect завершился без отчёта (код {code})."));
            }
        }

        private static void TryKill(Process process)
        {
            try
            {
                process.Kill();
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
            {
                // Уже завершился.
            }
        }
    }
}
