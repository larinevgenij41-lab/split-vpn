using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SplitVpn.Core.SshTunnel;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Operations;
using Windows.Win32;

namespace SplitVpn.Windows.SshTunnel;

/// <summary>
/// Запускает движок «VPN поверх SSH» (sing-box.exe из каталога службы). Настройки с закрытым ключом уходят
/// процессу через стандартный ввод: на диске, в командной строке и в окружении ключа нет. Процесс помещается
/// в Job с KILL_ON_JOB_CLOSE до передачи настроек: если служба упала, движок её не переживёт, а с ним исчезнет
/// и адаптер туннеля.
/// </summary>
public sealed partial class SystemSshTunnelOps : ISshTunnelOps, IDisposable
{
    public const string EngineFileName = "sing-box.exe";

    /// <summary>Сколько ждать появления адаптера после запуска движка.</summary>
    internal static readonly TimeSpan AdapterDeadline = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan AdapterPoll = TimeSpan.FromMilliseconds(250);

    private readonly Dictionary<string, Task> _nativePreparations = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _enginePath;
    private readonly string _workDirectory;
    private readonly SafeFileHandle _job;
    private readonly Action<string>? _diagnostics;

    /// <param name="enginePath">Полный путь к sing-box.exe.</param>
    /// <param name="workDirectory">Рабочий каталог движка: пустая папка, куда он не должен ничего писать.</param>
    /// <param name="diagnostics">Куда писать пояснения к непрошедшей проверке связи (журнал службы).</param>
    public SystemSshTunnelOps(string enginePath, string workDirectory, Action<string>? diagnostics = null)
    {
        _diagnostics = diagnostics;
        _enginePath = Path.GetFullPath(enginePath);
        _workDirectory = workDirectory;
        _job = ChildProcessJob.CreateKillOnClose("движка «VPN поверх SSH»");
    }

    public string? EnginePath => File.Exists(_enginePath) ? _enginePath : null;

    /// <summary>
    /// Аргументы движка: настройки из стандартного ввода. Секретов и адреса сервера здесь нет - командную
    /// строку процесса видит любой пользователь компьютера.
    /// </summary>
    internal static IReadOnlyList<string> Arguments(string workDirectory) => ["run", "-c", "stdin", "-D", workDirectory, "--disable-color"];

    public ISshTunnelSession Start(SingBoxParameters parameters, ReadOnlySpan<char> privateKey, Action<SshTunnelEvent> onEvent)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(onEvent);
        if (!File.Exists(_enginePath))
        {
            throw new FileNotFoundException("Не найден движок «VPN поверх SSH»: переустановите программу.", _enginePath);
        }

        lock (_nativePreparations)
        {
            if (_nativePreparations.TryGetValue(parameters.InterfaceName, out var pending) && !pending.IsCompleted)
            {
                throw new IOException("Windows ещё подготавливает адаптер SSH.");
            }
        }
        EnsureAliasAvailable(parameters.InterfaceName);

        Directory.CreateDirectory(_workDirectory);

        var config = new byte[SingBoxConfig.BufferSize(privateKey.Length)];
        Process? process = null;
        try
        {
            var length = SingBoxConfig.Write(config, parameters, privateKey);
            var start = new ProcessStartInfo(_enginePath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
                WorkingDirectory = _workDirectory,
            };
            foreach (var argument in Arguments(_workDirectory))
            {
                start.ArgumentList.Add(argument);
            }

            // Общая с помощниками AnyConnect очередь запусков: их наследуемые концы труб не должны достаться движку.
            lock (ChildProcessJob.StartGate)
            {
                process = Process.Start(start) ?? throw new InvalidOperationException("Движок «VPN поверх SSH» не запустился.");
            }

            // До передачи настроек: без Job движок пережил бы падение службы и продолжал держать туннель без присмотра.
            if (!PInvoke.AssignProcessToJobObject(_job, process.SafeHandle))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Не удалось взять движок «VPN поверх SSH» под надзор службы");
            }

            var session = new Session(process, parameters, onEvent, config, length);
            config = [];
            return session;
        }
        catch
        {
            if (process is not null)
            {
                ChildProcessJob.KillQuietly(process);
                process.Dispose();
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(config);
        }
    }

    public Task PrepareInterfaceAsync(string name) => PrepareInterfaceAsync(name, AdapterDeadline, PrepareAliasAsync);

    internal async Task PrepareInterfaceAsync(string name, TimeSpan timeout, Func<string, CancellationToken, Task> prepare)
    {
        Task preparation;
        lock (_nativePreparations)
        {
            if (!_nativePreparations.TryGetValue(name, out preparation!))
            {
                preparation = Task.Run(async () =>
                {
                    using var limit = new CancellationTokenSource(timeout);
                    try { await prepare(name, limit.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (limit.IsCancellationRequested)
                    {
                        throw new IOException($"Windows не освободила адаптер {name} за отведённое время.");
                    }
                });
                _nativePreparations.Add(name, preparation);
                _ = preparation.ContinueWith(completed =>
                {
                    _ = completed.Exception;
                    lock (_nativePreparations) { _nativePreparations.Remove(name); }
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }

        try { await preparation.WaitAsync(timeout).ConfigureAwait(false); }
        catch (TimeoutException ex)
        {
            throw new IOException($"Windows не освободила адаптер {name} за отведённое время.", ex);
        }
    }

    private async Task PrepareAliasAsync(string name, CancellationToken cancellationToken)
    {
        var elapsed = Stopwatch.StartNew();
        if (TunnelInterfaceConfig.FindLuid(name) is { } luid)
        {
            if (TunnelInterfaceConfig.WintunInstance(luid) is not { } instance)
            {
                EnsureAliasAvailable(name);
                return;
            }

            _diagnostics?.Invoke($"Ожидание освобождения адаптера SSH {name}, устройство {instance}, LUID {luid}.");
            cancellationToken.ThrowIfCancellationRequested();
            OpenForCleanup(name);
            while (elapsed.Elapsed < AdapterDeadline - TimeSpan.FromSeconds(5) && TunnelInterfaceConfig.FindLuid(name) == luid)
            {
                await Task.Delay(AdapterPoll, cancellationToken).ConfigureAwait(false);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        TunnelInterfaceConfig.RemoveStaleWintunEntries(name, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureAliasAvailable(name);
        _diagnostics?.Invoke($"Имя адаптера SSH {name} освобождено.");
    }

    private static void OpenForCleanup(string name)
    {
        try
        {
            var adapter = WintunOpenAdapter(name);
            if (adapter != 0) { WintunCloseAdapter(adapter); }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            throw new IOException("Не удалось загрузить библиотеку Wintun для очистки адаптера SSH.", ex);
        }
    }

    [LibraryImport("wintun.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory)]
    private static partial nint WintunOpenAdapter(string name);

    [LibraryImport("wintun.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory)]
    private static partial void WintunCloseAdapter(nint adapter);

    internal static void EnsureAliasAvailable(string name)
    {
        if (TunnelInterfaceConfig.FindLuid(name) is not null)
        {
            throw new IOException($"Имя сетевого адаптера SSH {name} уже занято.");
        }
    }

    public async Task<bool> CanReadKeyAsync(SingBoxParameters parameters, string privateKey, CancellationToken cancellationToken)
    {
        var config = new byte[SingBoxConfig.BufferSize(privateKey.Length)];
        try
        {
            var length = SingBoxConfig.Write(config, parameters, privateKey);
            var start = new ProcessStartInfo(_enginePath)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                ArgumentList = { "check", "-c", "stdin", "--disable-color" },
            };
            Process process;
            lock (ChildProcessJob.StartGate)
            {
                process = Process.Start(start) ?? throw new IOException("Не удалось проверить ключ SSH.");
            }

            using (process)
            {
                try
                {
                    if (!PInvoke.AssignProcessToJobObject(_job, process.SafeHandle))
                    {
                        throw new Win32Exception(Marshal.GetLastPInvokeError());
                    }

                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    deadline.CancelAfter(AdapterDeadline);
                    using var stop = deadline.Token.Register(() => ChildProcessJob.KillQuietly(process));
                    var output = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
                    var error = process.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
                    await process.StandardInput.BaseStream.WriteAsync(config.AsMemory(0, length), deadline.Token).ConfigureAwait(false);
                    process.StandardInput.Close();
                    await Task.WhenAll(output, error, process.WaitForExitAsync(deadline.Token)).ConfigureAwait(false);
                    return process.ExitCode == 0;
                }
                finally
                {
                    ChildProcessJob.KillQuietly(process);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(config);
        }
    }

    public (ulong Sent, ulong Received)? GetCounters(ulong luid)
    {
        var row = new global::Windows.Win32.NetworkManagement.IpHelper.MIB_IF_ROW2 { InterfaceLuid = new() { Value = luid } };
        return PInvoke.GetIfEntry2(ref row) == 0 ? (row.OutOctets, row.InOctets) : null;
    }

    public int StopLeftovers() => StopOwn(_enginePath);

    /// <summary>Срок одной проверки связи: новое соединение через туннель и ответ сервера DNS.</summary>
    internal static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Имя для проверочного запроса: зарезервированный учебный домен, он есть у любого сервера DNS и ни о чём не сообщает.</summary>
    private const string ProbeName = "example.com";

    public async Task<bool> ProbeAsync(IReadOnlyList<System.Net.IPEndPoint> dnsServers, uint? interfaceIndex, CancellationToken cancellationToken)
    {
        var query = Core.Dns.DnsMessage.BuildQuery((ushort)Random.Shared.Next(1, 65536), ProbeName, Core.Dns.DnsMessage.TypeA);
        // Пересылка сверяет идентификатор и вопрос. Любой совпавший ответ, включая SERVFAIL, доказывает,
        // что данные прошли через соединение SSH туда и обратно.
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(ProbeTimeout);
        var probes = dnsServers.Select(server => Dns.DnsForwarder.ForwardAsync(query, [server], interfaceIndex,
            ProbeTimeout, tcpOnly: true, limit.Token, acceptServerFailure: true)).ToList();
        try
        {
            while (probes.Count > 0)
            {
                var finished = await Task.WhenAny(probes).ConfigureAwait(false);
                probes.Remove(finished);
                if (await finished.ConfigureAwait(false) is not null) { return true; }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Истёк общий срок проверки.
        }
        finally
        {
            await limit.CancelAsync().ConfigureAwait(false);
            try { await Task.WhenAll(probes).ConfigureAwait(false); }
            catch (OperationCanceledException) when (limit.IsCancellationRequested) { }
        }

        cancellationToken.ThrowIfCancellationRequested();
        _diagnostics?.Invoke($"Проверка связи через туннель SSH: нет ответа DNS через адаптер {interfaceIndex} (серверов: {dnsServers.Count}).");
        return false;
    }

    /// <summary>
    /// Завершает процессы движка, запущенные из этого файла: остались от упавшей службы (если Job не сработал)
    /// или мешают восстановлению сети. Чужой sing-box - из другой папки, от другой программы - не трогается.
    /// </summary>
    public static int StopOwn(string enginePath)
    {
        var path = Path.GetFullPath(enginePath);
        var stopped = 0;
        var failures = new List<string>();
        foreach (var candidate in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(path)))
        {
            using (candidate)
            {
                var owned = false;
                try
                {
                    if (!string.Equals(candidate.MainModule?.FileName, path, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    owned = true;
                    candidate.Kill(entireProcessTree: true);
                    if (!candidate.WaitForExit(5000))
                    {
                        throw new TimeoutException($"Процесс {candidate.Id} не завершился за 5 секунд.");
                    }

                    stopped++;
                }
                catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException or TimeoutException)
                {
                    if (owned)
                    {
                        try { if (candidate.HasExited) { continue; } }
                        catch (Exception statusError) when (statusError is InvalidOperationException or Win32Exception) { }
                        failures.Add(ex.Message);
                    }
                }
            }
        }

        if (failures.Count > 0) { throw new IOException(string.Join("; ", failures)); }
        return stopped;
    }

    public void Dispose() => _job.Dispose();

    internal sealed class Session : ISshTunnelSession
    {
        private readonly Process _process;
        private readonly SingBoxParameters _parameters;
        private readonly Action<SshTunnelEvent> _onEvent;
        private readonly CancellationTokenSource _stop = new();
        private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _disposed;

        public Session(Process process, SingBoxParameters parameters, Action<SshTunnelEvent> onEvent, byte[] config, int length, TimeSpan? writeTimeout = null)
        {
            _process = process;
            _parameters = parameters;
            _onEvent = onEvent;
            _ = Task.Run(() => RunAsync(config, length, writeTimeout ?? AdapterDeadline));
        }

        public Task Exited => _exited.Task;

        public bool? HasEstablishedTransport()
        {
            if (_exited.Task.IsCompleted) { return false; }
            try { return SshTcpConnections.HasEstablished(_process.Id, _parameters.Server, _parameters.Port); }
            catch (InvalidOperationException) { return _exited.Task.IsCompleted ? false : null; }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _stop.Cancel();
            }

            // Предыдущая попытка могла не завершить процесс.
            ChildProcessJob.KillQuietly(_process);
        }

        /// <summary>
        /// Читает вывод движка, ждёт адаптер и следит за выходом процесса. Последнее событие всегда
        /// <see cref="SshTunnelExited"/>, ровно одно.
        /// </summary>
        private async Task RunAsync(byte[] config, int length, TimeSpan writeTimeout)
        {
            string? failure = null;
            int? code = null;
            try
            {
                var output = PumpAsync(_process.StandardOutput);
                var errors = PumpAsync(_process.StandardError);
                using (var deadline = new CancellationTokenSource(writeTimeout))
                using (deadline.Token.Register(() => ChildProcessJob.KillQuietly(_process)))
                {
                    try
                    {
                        await _process.StandardInput.BaseStream.WriteAsync(config.AsMemory(0, length)).ConfigureAwait(false);
                        _process.StandardInput.Close();
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(config);
                    }
                }

                var adapter = WaitAdapterAsync();
                await _process.WaitForExitAsync().ConfigureAwait(false);
                await _stop.CancelAsync().ConfigureAwait(false);
                await Task.WhenAll(output, errors).ConfigureAwait(false);
                failure = await adapter.ConfigureAwait(false);
                code = _process.ExitCode;
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or IOException or ObjectDisposedException)
            {
                ChildProcessJob.KillQuietly(_process);
                await _process.WaitForExitAsync().ConfigureAwait(false);
                failure = ex.Message;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(config);
                Raise(new SshTunnelExited(code, failure));
                _process.Dispose();
                _exited.TrySetResult();
            }
        }

        private async Task PumpAsync(StreamReader reader)
        {
            try
            {
                while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
                {
                    if (line.Length > 0)
                    {
                        Raise(new SshTunnelLog(line));
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                // Процесс завершён, поток закрыт.
            }
        }

        /// <summary>Ждёт адаптер движка, задаёт ему адрес /32, MTU и метрику. Возвращает причину неудачи или null.</summary>
        private async Task<string?> WaitAdapterAsync()
        {
            var deadline = Stopwatch.StartNew();
            Win32Exception? last = null;
            try
            {
                while (deadline.Elapsed < AdapterDeadline)
                {
                    if (TunnelInterfaceConfig.FindLuid(_parameters.InterfaceName) is { } luid && TunnelInterfaceConfig.IsPresentWintun(luid))
                    {
                        try
                        {
                            // Движок назначает адрес сам; служба приводит его к /32, чтобы не появился маршрут подсети
                            // без метки программы, и задаёт метрику выше физических адаптеров.
                            TunnelInterfaceConfig.Configure(luid, _parameters.TunAddress, _parameters.Mtu, replaceWrongPrefix: true);
                            Raise(new SshTunnelReady(luid));
                            return null;
                        }
                        catch (Win32Exception ex)
                        {
                            // Имя адаптера Windows отдаёт раньше, чем адаптер готов принять адрес (и некоторое время
                            // после исчезновения прежнего): настройка повторяется, пока не выйдет срок.
                            last = ex;
                        }
                    }

                    await Task.Delay(AdapterPoll, _stop.Token).ConfigureAwait(false);
                }

                ChildProcessJob.KillQuietly(_process);
                return last is null
                    ? "Движок не создал сетевой адаптер за отведённое время."
                    : FormattableString.Invariant($"Адаптер туннеля не настроен за отведённое время: {last.Message} (код {last.NativeErrorCode}).");
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or Win32Exception)
            {
                ChildProcessJob.KillQuietly(_process);
                return $"Не удалось проверить сетевой адаптер SSH: {ex.Message}";
            }
        }

        private void Raise(SshTunnelEvent value)
        {
            try
            {
                _onEvent(value);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
            {
                // Получатель уже остановлен (служба завершается): событие некому обработать.
            }
        }
    }
}
