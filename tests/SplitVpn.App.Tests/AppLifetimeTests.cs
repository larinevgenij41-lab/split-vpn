using System.IO;
using SplitVpn.App.Services;

namespace SplitVpn.App.Tests;

/// <summary>
/// Пути завершения интерфейса без штатного выхода (<see cref="AppLifetime"/>): сбой запуска не оставляет
/// невидимый процесс с мьютексом единственного экземпляра, а падение, лавина ошибок и конец сеанса Windows
/// снимают свой прокси шлюза до выхода.
/// </summary>
public sealed class AppLifetimeTests
{
    /// <summary>
    /// Сбой запуска первой копии: ошибка записана, слушатель активации остановлен, мьютекс освобождён (его сразу
    /// берёт другой процесс — следующий запуск станет первой копией), человеку показано сообщение, выход с кодом 1.
    /// Сбой самого сообщения не мешает выходу.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void StartupFailure_ReleasesMutexAndShutsDown(bool messageFails)
    {
        var name = @"Local\SplitVpn.Test.App." + Guid.NewGuid().ToString("N");
        var steps = new List<string>();
        var recorded = new List<Exception>();
        var failure = new InvalidOperationException("окно не создано");
        var lifetime = new AppLifetime(ex => { recorded.Add(ex); return true; })
        {
            Instance = new Mutex(true, name, out var first),
            CancelActivation = () => steps.Add("activation"),
            ShowStartupError = () =>
            {
                steps.Add("message");
                if (messageFails) { throw new InvalidOperationException("окно сообщения"); }
            },
            AllowWindowClose = () => steps.Add("close"),
            Shutdown = code => steps.Add("shutdown " + code),
            Exit = code => steps.Add("exit " + code),
        };
        Assert.True(first);
        Assert.False(TakenElsewhere(name));

        lifetime.StartFirstInstance(() => throw failure);

        Assert.Same(failure, recorded[0]);
        Assert.Equal(messageFails ? 2 : 1, recorded.Count);
        Assert.Equal(["activation", "message", "close", "shutdown 1"], steps);
        Assert.Null(lifetime.Instance);
        Assert.True(TakenElsewhere(name));
    }

    /// <summary>Удачный запуск: мьютекс остаётся у первой копии, выхода нет.</summary>
    [Fact]
    public void StartupSuccess_KeepsMutex()
    {
        var name = @"Local\SplitVpn.Test.App." + Guid.NewGuid().ToString("N");
        var steps = new List<string>();
        using var instance = new Mutex(true, name, out _);
        var lifetime = new AppLifetime(_ => true) { Instance = instance, Shutdown = code => steps.Add("shutdown " + code), Exit = code => steps.Add("exit " + code) };
        var started = false;

        lifetime.StartFirstInstance(() => started = true);

        Assert.True(started);
        Assert.Empty(steps);
        Assert.Same(instance, lifetime.Instance);
        Assert.False(TakenElsewhere(name));
        instance.ReleaseMutex();
    }

    /// <summary>
    /// Лавина одинаковых ошибок UI-потока: прокси шлюза снят, значок убран (и его сбой выходу не мешает), выход с
    /// кодом 2 — один раз, даже если ошибка повторилась во время выхода. Обычная ошибка приложение не закрывает.
    /// </summary>
    [Fact]
    public void ErrorStorm_RevertsProxyRemovesTrayAndExitsOnce()
    {
        var storm = false;
        var steps = new List<string>();
        var lifetime = new AppLifetime(_ => !storm)
        {
            CloseProxy = wait => { steps.Add("proxy " + wait.TotalSeconds); return true; },
            DisposeTray = () => { steps.Add("tray"); throw new InvalidOperationException("значок"); },
            Exit = code => steps.Add("exit " + code),
        };

        lifetime.OnDispatcherError(new InvalidOperationException("одна"));
        Assert.Empty(steps);

        storm = true;
        lifetime.OnDispatcherError(new InvalidOperationException("лавина"));
        lifetime.OnDispatcherError(new InvalidOperationException("лавина"));

        Assert.Equal(["proxy " + ProxyService.ExitWait.TotalSeconds, "tray", "exit 2"], steps);
    }

    /// <summary>Необработанное исключение: записано, прокси шлюза снят; сбой снятия прокси наружу не выходит.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Crash_RecordsAndRevertsProxy(bool proxyFails)
    {
        var recorded = new List<Exception>();
        var closed = 0;
        var lifetime = new AppLifetime(ex => { recorded.Add(ex); return true; })
        {
            CloseProxy = _ =>
            {
                closed++;
                return proxyFails ? throw new IOException("реестр") : true;
            },
            Exit = _ => Assert.Fail("падение завершает процесс само"),
        };
        var crash = new InvalidOperationException("падение");

        lifetime.OnCrash(crash);
        lifetime.OnCrash("не исключение");

        Assert.Equal([crash], recorded);
        Assert.Equal(2, closed);
    }

    /// <summary>Конец сеанса Windows: сначала снимается прокси, затем ждётся запись настроек, затем выход.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SessionEnding_RevertsProxyBeforeWaitingAndExits(bool written)
    {
        var steps = new List<string>();
        var lifetime = new AppLifetime(_ => true) { CloseProxy = _ => { steps.Add("proxy"); return true; } };

        lifetime.OnSessionEnding(wait => { steps.Add("preferences " + wait.TotalSeconds); return written; }, TimeSpan.FromSeconds(2), () => steps.Add("exit"));

        Assert.Equal(["proxy", "preferences 2", "exit"], steps);
    }

    /// <summary>Прокси ещё не создан (сбой до него): снимать нечего, ошибок нет.</summary>
    [Fact]
    public void NoProxyYet_ExitPathsDoNotFail()
    {
        var exits = new List<int>();
        var lifetime = new AppLifetime(_ => false) { Exit = exits.Add };

        lifetime.OnCrash(new InvalidOperationException("рано"));
        lifetime.OnDispatcherError(new InvalidOperationException("рано"));

        Assert.Equal([2], exits);
    }

    /// <summary>Мьютекс может взять другой поток (как другой процесс): прежний владелец его освободил.</summary>
    private static bool TakenElsewhere(string name)
    {
        var taken = false;
        var thread = new Thread(() =>
        {
            using var mutex = new Mutex(false, name);
            try
            {
                taken = mutex.WaitOne(0);
            }
            catch (AbandonedMutexException)
            {
                // Владелец закрыл мьютекс, не освободив его: так выглядит прежняя ошибка.
                taken = false;
                return;
            }

            if (taken) { mutex.ReleaseMutex(); }
        });
        thread.Start();
        Assert.True(thread.Join(TimeSpan.FromSeconds(30)));
        return taken;
    }
}
