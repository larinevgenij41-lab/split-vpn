using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using Microsoft.Extensions.Logging.Abstractions;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Ipc;

namespace SplitVpn.Service.Tests;

/// <summary>Исправления аудита: проверка клиента канала до первого кадра, предел первого кадра, команда recover.</summary>
public sealed class IpcRecoveryAuditTests
{
    /// <summary>
    /// R-SVC-3: процесс клиента не открылся (завершился, дескриптор передан другому) — отказ сразу, а не три секунды
    /// ожидания первого кадра с занятым экземпляром канала.
    /// </summary>
    [Fact]
    public async Task UndeterminedClient_IsDeniedAtOnce()
    {
        using var world = new FakeWorld();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var server = new IpcServer(new Coordinator(world.Dependencies()), NullLogger<IpcServer>.Instance)
        {
            PipeName = name,
            Security = () => null,
            Precheck = _ => null,
        };
        await server.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(5000, TestContext.Current.CancellationToken);
            var watch = Stopwatch.StartNew();

            // Ответ «отказано» приходит без запроса клиента: служба не ждёт первого кадра.
            var answer = await FrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken);
            watch.Stop();
            await pipe.DisposeAsync();

            Assert.NotNull(answer);
            var response = IpcSerializer.DeserializeResponse(answer);
            Assert.False(response.Ok);
            Assert.Equal(IpcErrorCodes.Denied, response.ErrorCode);
            Assert.True(watch.Elapsed < IpcServer.FirstFrameTimeout, $"отказ занял {watch.ElapsedMilliseconds} мс");
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    /// <summary>R-SVC-3: заголовок первого кадра больше 64 КБ — соединение закрыто сразу, тело кадра не ждётся.</summary>
    [Fact]
    public async Task OversizedFirstFrame_ClosesConnectionAtOnce()
    {
        using var world = new FakeWorld();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var server = new IpcServer(new Coordinator(world.Dependencies()), NullLogger<IpcServer>.Instance)
        {
            PipeName = name,
            Security = () => null,
            Precheck = _ => true,
        };
        await server.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(5000, TestContext.Current.CancellationToken);
            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, IpcServer.MaxFirstFrameBytes + 1);
            var watch = Stopwatch.StartNew();
            await pipe.WriteAsync(header, TestContext.Current.CancellationToken);
            await pipe.FlushAsync(TestContext.Current.CancellationToken);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            var read = await pipe.ReadAsync(new byte[4], timeout.Token);
            watch.Stop();

            Assert.Equal(0, read);
            Assert.True(watch.Elapsed < IpcServer.FirstFrameTimeout, $"закрытие заняло {watch.ElapsedMilliseconds} мс");
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    /// <summary>
    /// R-SVC-3: длина сверх предела отклоняется по заголовку, до выделения буфера и чтения тела: поток без тела даёт
    /// «недопустимую длину», а не «соединение закрыто посреди сообщения».
    /// </summary>
    [Fact]
    public async Task FrameLimit_IsCheckedBeforeBufferAllocation()
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, IpcServer.MaxFirstFrameBytes + 1);
        using var oversized = new MemoryStream(header);

        var error = await Assert.ThrowsAsync<IpcProtocolException>(() =>
            FrameCodec.ReadAsync(oversized, IpcServer.MaxFirstFrameBytes, TestContext.Current.CancellationToken));
        Assert.Equal("Недопустимая длина сообщения.", error.Message);
    }

    /// <summary>R-SVC-3: настоящий первый кадр клиента — проверка версии — укладывается в предел первого кадра.</summary>
    [Fact]
    public async Task FirstClientRequest_FitsFirstFrameLimit()
    {
        var payload = IpcSerializer.SerializeRequest(new GetStatusRequest());
        Assert.True(payload.Length < IpcServer.MaxFirstFrameBytes / 100, $"первый кадр {payload.Length} байт");

        using var stream = new MemoryStream();
        await FrameCodec.WriteAsync(stream, new byte[IpcServer.MaxFirstFrameBytes], TestContext.Current.CancellationToken);
        stream.Position = 0;
        var read = await FrameCodec.ReadAsync(stream, IpcServer.MaxFirstFrameBytes, TestContext.Current.CancellationToken);
        Assert.Equal(IpcServer.MaxFirstFrameBytes, read!.Length);
    }

    /// <summary>R-SVC-7: sc.exe запускается полным путём из System32 и с рабочим каталогом System32, не по голому имени.</summary>
    [Fact]
    public void ScExe_IsStartedByAbsoluteSystemPath()
    {
        var info = ServiceRecovery.ScStartInfo("query SplitVpn");

        Assert.True(Path.IsPathFullyQualified(info.FileName), info.FileName);
        Assert.Equal(Path.Combine(Environment.SystemDirectory, "sc.exe"), info.FileName, ignoreCase: true);
        Assert.Equal(Environment.SystemDirectory, info.WorkingDirectory, ignoreCase: true);
        Assert.False(info.UseShellExecute);
    }

    /// <summary>R-BLD-5: «‐‐uninstall» для скриптов остаётся прежним (с удалением данных), установщик зовёт сетевой шаг.</summary>
    [Theory]
    [InlineData(new[] { "recover" }, RecoveryMode.Recover)]
    [InlineData(new[] { "recover", "--uninstall" }, RecoveryMode.Uninstall)]
    [InlineData(new[] { "recover", "--uninstall-network" }, RecoveryMode.UninstallNetwork)]
    [InlineData(new[] { "recover", "--UNINSTALL-NETWORK" }, RecoveryMode.UninstallNetwork)]
    public void RecoverArguments_SelectMode(string[] args, RecoveryMode expected) =>
        Assert.Equal(expected, ServiceRecovery.ParseMode(args));

    /// <summary>
    /// Отметка PurgeData от отменённого удаления снимается при обычном старте службы; сбой снятия не мешает запуску -
    /// только предупреждение в журнал.
    /// </summary>
    [Fact]
    public void StaleWipeMark_ClearedOnStart_FailureOnlyWarns()
    {
        var cleared = 0;
        var warnings = new List<string>();
        Assert.True(ServiceRecovery.ClearStalePurgeMark(() => cleared++, warnings.Add));
        Assert.Equal(1, cleared);
        Assert.Empty(warnings);

        Assert.False(ServiceRecovery.ClearStalePurgeMark(() => throw new IOException("Отметка очистки данных не снята: отказано"), warnings.Add));
        Assert.Equal(["Отметка очистки данных не снята: отказано"], warnings);
    }

    /// <summary>R-SVC-8: каждый журнал удаления — новый файл с уникальным именем в своём каталоге; прежние не трогаются.</summary>
    [Fact]
    public void UninstallLog_IsWrittenAsNewUniqueFiles()
    {
        var directory = Path.Combine(Path.GetTempPath(), "SplitVpn.Test." + Guid.NewGuid().ToString("N"), "SplitVpn.Uninstall");
        try
        {
            var secured = new List<string>();
            var first = ServiceRecovery.WriteUninstallLog(directory, "первый", d => { secured.Add(d); Directory.CreateDirectory(d); return []; }, _ => true);
            var second = ServiceRecovery.WriteUninstallLog(directory, "второй", d => { secured.Add(d); return []; }, _ => true);

            Assert.NotNull(first);
            Assert.NotNull(second);
            Assert.NotEqual(first, second);
            Assert.Equal([directory, directory], secured);
            Assert.Equal(directory, Path.GetDirectoryName(first));
            Assert.Contains("первый", File.ReadAllText(first), StringComparison.Ordinal);
            Assert.Contains("второй", File.ReadAllText(second), StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(directory)!, recursive: true);
        }
    }

    /// <summary>R-SVC-8: каталог журнала, заранее созданный посторонней учётной записью или файлом, не используется.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UninstallLog_ForeignDirectory_IsNotUsed(bool asFile)
    {
        var root = Path.Combine(Path.GetTempPath(), "SplitVpn.Test." + Guid.NewGuid().ToString("N"));
        var directory = Path.Combine(root, "SplitVpn.Uninstall");
        Directory.CreateDirectory(root);
        try
        {
            if (asFile)
            {
                File.WriteAllText(directory, "подложено");
            }
            else
            {
                Directory.CreateDirectory(directory);
            }

            var secured = false;
            var path = ServiceRecovery.WriteUninstallLog(directory, "журнал", _ => { secured = true; return []; }, _ => false);

            Assert.Null(path);
            Assert.False(secured);
            if (!asFile)
            {
                Assert.Empty(Directory.EnumerateFileSystemEntries(directory));
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>R-SVC-8: каталог журнала — ссылка (junction) на другой каталог: туда журнал не пишется.</summary>
    [Fact]
    public void UninstallLog_JunctionDirectory_IsNotUsed()
    {
        var root = Path.Combine(Path.GetTempPath(), "SplitVpn.Test." + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(root, "target");
        var directory = Path.Combine(root, "SplitVpn.Uninstall");
        Directory.CreateDirectory(target);
        try
        {
            using (var mklink = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                $"/d /c mklink /J \"{directory}\" \"{target}\"") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!)
            {
                mklink.StandardOutput.ReadToEnd();
                mklink.WaitForExit();
                Assert.Equal(0, mklink.ExitCode);
            }

            Assert.True(new DirectoryInfo(directory).Attributes.HasFlag(FileAttributes.ReparsePoint));
            var path = ServiceRecovery.WriteUninstallLog(directory, "журнал", _ => [], _ => true);

            Assert.Null(path);
            Assert.Empty(Directory.EnumerateFileSystemEntries(target));
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory);
            }

            Directory.Delete(root, recursive: true);
        }
    }
}
