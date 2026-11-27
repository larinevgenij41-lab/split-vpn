using Serilog;
using Serilog.Core;
using Serilog.Events;
using SplitVpn.Service.Diagnostics;

namespace SplitVpn.Service.Tests;

/// <summary>Запуск службы: только диспетчером служб или ключом разработки, один экземпляр; необработанные исключения — в журнал.</summary>
public sealed class ServiceInstanceTests
{
    [Theory]
    [InlineData(true, new string[0], LaunchDecision.Run)]
    [InlineData(true, new[] { "--console" }, LaunchDecision.Run)]
    [InlineData(false, new string[0], LaunchDecision.RefuseConsole)]
    [InlineData(false, new[] { "--environment", "Development" }, LaunchDecision.RefuseConsole)]
    [InlineData(false, new[] { "--console" }, LaunchDecision.Run)]
    [InlineData(false, new[] { "--CONSOLE" }, LaunchDecision.Run)]
    [InlineData(false, new[] { "console" }, LaunchDecision.RefuseConsole)]
    public void Decide_RunsOnlyUnderScmOrWithConsoleOption(bool isWindowsService, string[] args, LaunchDecision expected) =>
        Assert.Equal(expected, ServiceInstance.Decide(args, isWindowsService));

    /// <summary>Ключ разработки хосту не передаётся: разбор командной строки хоста съел бы следующий аргумент как значение.</summary>
    [Fact]
    public void HostArguments_DropConsoleOption()
    {
        Assert.Equal(["--environment", "Development"], ServiceInstance.HostArguments(["--console", "--environment", "Development"]));
        Assert.Empty(ServiceInstance.HostArguments(["--Console"]));
    }

    [Fact]
    public void ConsoleRefusal_NamesRecoveryCommandsAndConsoleOption()
    {
        Assert.Contains("emergency-off", ServiceInstance.ConsoleRefusal, StringComparison.Ordinal);
        Assert.Contains(ServiceInstance.ConsoleOption, ServiceInstance.ConsoleRefusal, StringComparison.Ordinal);
        Assert.NotEqual(0, ServiceInstance.RefusedExitCode);
        Assert.NotEqual(0, ServiceInstance.BusyExitCode);
    }

    /// <summary>
    /// Второй экземпляр мьютекс не получает (занят, а без прав администратора ещё и закрыт явными правами); после выхода
    /// первого мьютекс снова свободен. Имя - в Local\: Global\ без SeCreateGlobalPrivilege тесту недоступно.
    /// </summary>
    [Fact]
    public void TryAcquire_SecondInstanceRefused_FreeAfterFirstReleases()
    {
        var name = @"Local\SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var first = ServiceInstance.TryAcquire(name, TimeSpan.Zero, out var firstProblem);
        Assert.NotNull(first);
        Assert.Null(firstProblem);

        Mutex? second = null;
        string? secondProblem = null;
        var other = new Thread(() => second = ServiceInstance.TryAcquire(name, TimeSpan.FromMilliseconds(100), out secondProblem));
        other.Start();
        other.Join();
        Assert.Null(second);
        Assert.Contains(name, secondProblem, StringComparison.Ordinal);

        first.ReleaseMutex();
        first.Dispose();

        Mutex? third = null;
        var again = new Thread(() =>
        {
            third = ServiceInstance.TryAcquire(name, TimeSpan.Zero, out _);
            third?.ReleaseMutex();
        });
        again.Start();
        again.Join();
        Assert.NotNull(third);
        third.Dispose();
    }

    [Fact]
    public void Unhandled_WritesFatalFlushesAndReportsToConsole()
    {
        var sink = new ListSink();
        using var logger = new LoggerConfiguration().WriteTo.Sink(sink).CreateLogger();
        var flushed = 0;
        var console = new List<string>();

        ServiceCrash.OnUnhandled(new InvalidOperationException("поток событий"), logger, () => flushed++, console.Add);

        var fatal = Assert.Single(sink.Events);
        Assert.Equal(LogEventLevel.Fatal, fatal.Level);
        Assert.IsType<InvalidOperationException>(fatal.Exception);
        Assert.Equal(1, flushed);
        Assert.Contains(console, line => line.Contains("поток событий", StringComparison.Ordinal));
    }

    /// <summary>Обработчик сам не бросает: сбой сброса журнала не подменяет исходную причину завершения.</summary>
    [Fact]
    public void Unhandled_FlushFailure_DoesNotThrow()
    {
        using var logger = new LoggerConfiguration().CreateLogger();
        ServiceCrash.OnUnhandled("не исключение", logger, () => throw new IOException("диск"), _ => throw new IOException("консоль"));
    }

    [Fact]
    public void Unobserved_IsLoggedAndObserved()
    {
        var sink = new ListSink();
        using var logger = new LoggerConfiguration().WriteTo.Sink(sink).CreateLogger();
        var args = new UnobservedTaskExceptionEventArgs(new AggregateException(new IOException("фон")));

        ServiceCrash.OnUnobserved(args, logger);

        Assert.True(args.Observed);
        Assert.Equal(LogEventLevel.Warning, Assert.Single(sink.Events).Level);
    }

    private sealed class ListSink : ILogEventSink
    {
        public List<LogEvent> Events { get; } = [];

        public void Emit(LogEvent logEvent) => Events.Add(logEvent);
    }
}
