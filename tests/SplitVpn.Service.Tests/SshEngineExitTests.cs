using System.Diagnostics;
using SplitVpn.Core.SshTunnel;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.SshTunnel;

namespace SplitVpn.Service.Tests;

/// <summary>Выход движка «VPN поверх SSH» наступает по выходу процесса, а не по концу его вывода.</summary>
public sealed class SshEngineExitTests
{
    /// <summary>
    /// Движок завершился, а трубу его вывода держит унаследовавший её процесс (здесь ping, запущенный cmd в фоне на
    /// ~30 с): выход сеанса наступает через срок дочитывания вывода, и событий после SshTunnelExited нет.
    /// </summary>
    [Fact]
    public async Task ExitIsNotHeldByInheritedOutputPipe()
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            ArgumentList = { "/d", "/c", "start", "/b", "ping", "-n", "30", "127.0.0.1" },
        };
        using var process = Process.Start(start)!;
        var parameters = new SingBoxParameters
        {
            InterfaceName = Guid.NewGuid().ToString(), Server = 0, Port = 22, User = "test",
            HostKey = new SshHostKey("ssh-ed25519", ""),
        };
        var events = new List<SshTunnelEvent>();
        var config = new byte[16];
        var watch = Stopwatch.StartNew();
        using var session = new SystemSshTunnelOps.Session(process, parameters, e => { lock (events) { events.Add(e); } }, config, config.Length);

        await session.Exited.WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(15), $"выход занял {watch.ElapsedMilliseconds} мс");

        // Вывод ping ещё идёт, но после выхода сеанса не доставляется.
        await Task.Delay(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
        lock (events)
        {
            Assert.IsType<SshTunnelExited>(events[^1]);
            Assert.Single(events.OfType<SshTunnelExited>());
        }
    }
}
