using Microsoft.Extensions.Logging;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>Чем «ответила» цель пробы.</summary>
public enum ProbeAnswer
{
    Connected,
    Refused,
    Timeout,
}

/// <summary>
/// Пробы с ответом на каждую цель «IP:порт» отдельно. Цели без заданного ответа и проба сертификата идут к
/// обычному фейку мира.
/// </summary>
internal sealed class ScriptedProbes(FakeProbes inner) : IProbeOps
{
    private readonly Lock _lock = new();
    private readonly List<(uint Address, ushort Port)> _calls = [];

    public Dictionary<(uint Address, ushort Port), ProbeAnswer> Answers { get; } = [];

    public IReadOnlyList<(uint Address, ushort Port)> Calls
    {
        get
        {
            lock (_lock)
            {
                return _calls.ToList();
            }
        }
    }

    public Task<TcpProbeResult> TcpAsync(uint remote, ushort port, uint? localAddress, TimeSpan timeout, CancellationToken cancellationToken)
    {
        lock (_lock)
        {
            _calls.Add((remote, port));
        }

        if (!Answers.TryGetValue((remote, port), out var answer))
        {
            return inner.TcpAsync(remote, port, localAddress, timeout, cancellationToken);
        }

        return Task.FromResult(answer switch
        {
            ProbeAnswer.Connected => new TcpProbeResult(true, localAddress, null),
            ProbeAnswer.Refused => new TcpProbeResult(false, localAddress, "ConnectionRefused", Refused: true),
            _ => new TcpProbeResult(false, null, "таймаут"),
        });
    }

    public Task<ServerCertificateFacts?> ServerCertificateAsync(uint remote, ushort port, string? host, TimeSpan timeout, CancellationToken cancellationToken) =>
        inner.ServerCertificateAsync(remote, port, host, timeout, cancellationToken);

    public BestRoute? FindBestRoute(uint destination) => inner.FindBestRoute(destination);
}

/// <summary>RAS, у которого подготовка записи телефонной книги падает заданными ошибками, а остальное - как у фейка мира.</summary>
internal sealed class FlakyPhonebookRas(FakeRas inner) : IRasOps
{
    public Queue<Exception> SaveFailures { get; } = new();

    public void SaveEntry(string entryName, ConnectionProfile profile, ReadOnlySpan<char> preSharedKey)
    {
        if (SaveFailures.TryDequeue(out var failure))
        {
            throw failure;
        }

        inner.SaveEntry(entryName, profile, preSharedKey);
    }

    public void DeleteEntry(string entryName) => inner.DeleteEntry(entryName);

    public IReadOnlyList<string> EntryNames() => inner.EntryNames();

    public Task<RasDialResult> DialAsync(string entryName, string userName, ReadOnlyMemory<char> password, string? domain, CancellationToken cancellationToken) =>
        inner.DialAsync(entryName, userName, password, domain, cancellationToken);

    public Task HangUpAsync(RasConnectionHandle handle, CancellationToken cancellationToken) => inner.HangUpAsync(handle, cancellationToken);

    public RasConnectionStatus GetStatus(RasConnectionHandle handle) => inner.GetStatus(handle);

    public IReadOnlyList<RasActiveConnection> FindOwnConnections() => inner.FindOwnConnections();

    public RasProjection GetProjection(RasConnectionHandle handle) => inner.GetProjection(handle);

    public RasStatistics? GetStatistics(RasConnectionHandle handle) => inner.GetStatistics(handle);
}

/// <summary>Журнал службы, который запоминает предупреждения: по ним видно, сколько раз повторялась неудачная операция.</summary>
internal sealed class WarningLog : ILogger
{
    private readonly Lock _lock = new();
    private readonly List<string> _warnings = [];

    public int Count(string fragment)
    {
        lock (_lock)
        {
            return _warnings.Count(w => w.Contains(fragment, StringComparison.Ordinal));
        }
    }

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (logLevel < LogLevel.Warning)
        {
            return;
        }

        lock (_lock)
        {
            _warnings.Add(formatter(state, exception));
        }
    }
}
