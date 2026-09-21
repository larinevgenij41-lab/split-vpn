using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
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

    private sealed class HelperSession : IAnyConnectSession
    {
        /// <summary>Сколько ждать выхода помощника после закрытия канала (BYE на шлюз), прежде чем завершить его.</summary>
        private static readonly TimeSpan ExitGrace = TimeSpan.FromSeconds(15);

        private readonly Process _process;
        private readonly AnonymousPipeServerStream _toHelper;
        private readonly AnonymousPipeServerStream _fromHelper;
        private readonly Lock _writeLock = new();
        private bool _disposed;

        public HelperSession(Process process, AnonymousPipeServerStream toHelper, AnonymousPipeServerStream fromHelper, Action<HelperEvent> onEvent)
        {
            _process = process;
            _toHelper = toHelper;
            _fromHelper = fromHelper;
            new Thread(() => ReadEvents(onEvent)) { IsBackground = true, Name = "anyconnect-events" }.Start();
        }

        public bool Send(HelperCommand command)
        {
            lock (_writeLock)
            {
                if (_disposed)
                {
                    return false;
                }

                try
                {
                    FrameCodec.WriteAsync(_toHelper, HelperContract.Serialize(command), CancellationToken.None).GetAwaiter().GetResult();
                    return true;
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException)
                {
                    return false;
                }
            }
        }

        public void Dispose()
        {
            lock (_writeLock)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                _toHelper.Dispose();
            }

            // Конец канала помощник понимает как Stop: даём ему попрощаться со шлюзом, потом завершаем.
            _ = Task.Run(async () =>
            {
                using var process = _process;
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
