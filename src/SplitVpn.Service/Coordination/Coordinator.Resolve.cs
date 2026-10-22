using Microsoft.Extensions.Logging;
using SplitVpn.Core.Net;
using SplitVpn.Core.State;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    internal const int MaxServerResolutions = 4;
    private static readonly TimeSpan ServerResolveRetry = TimeSpan.FromSeconds(10);
    private readonly Dictionary<Guid, ServerResolution> _serverResolutions = [];
    private readonly HashSet<Task> _serverResolveTasks = [];
    private CancellationToken _serverResolveLifetime;

    private sealed class ServerResolution(TunnelFacts tunnel, string host, string context, CancellationTokenSource stop)
    {
        public TunnelFacts Tunnel { get; } = tunnel;
        public string Host { get; } = host;
        public string Context { get; } = context;
        public CancellationTokenSource Stop { get; } = stop;
        public Task Work { get; set; } = Task.CompletedTask;
    }

    /// <summary>Только запускает сеть: очередь актора не ждёт DNS и может принять отключение.</summary>
    private void StartServerResolutions()
    {
        _serverResolveTasks.RemoveWhere(t => t.IsCompleted);
        foreach (var resolution in _serverResolutions.Values.ToList())
        {
            if (!IsCurrentResolution(resolution))
            {
                CancelServerResolution(resolution);
            }
        }

        if (Facts.Primary is not { } primary || _state.Intent == Intent.Off || _state.ProtectionSuspended)
        {
            return;
        }

        foreach (var tunnel in Facts.Tunnels.Values)
        {
            if (_serverResolutions.Count >= MaxServerResolutions)
            {
                break;
            }

            if (tunnel.ServerResolving || !ResolveDue(tunnel)
                || !TryParseServer(_settings.Profile(tunnel.ProfileId), out var server) || server.IsIpLiteral)
            {
                continue;
            }

            var servers = ServiceDnsAddresses();
            var resolution = new ServerResolution(tunnel, server.Host, ServerResolutionContext(tunnel),
                CancellationTokenSource.CreateLinkedTokenSource(_serverResolveLifetime));
            _serverResolutions.Add(tunnel.ProfileId, resolution);
            tunnel.ServerResolving = true;
            tunnel.ServerResolveStartedUtc ??= _deps.Time.GetUtcNow();
            var token = resolution.Stop.Token;
            resolution.Work = Task.Run(async () =>
            {
                IReadOnlyList<uint> addresses = [];
                Exception? failure = null;
                try
                {
                    addresses = await _deps.Resolver.ResolveAsync(server.Host, servers, primary.InterfaceIndex, token).WaitAsync(token);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    failure = ex;
                }

                if (!token.IsCancellationRequested)
                {
                    TryEnqueue("ServerResolved", () => OnServerResolvedAsync(resolution, addresses, failure, _serverResolveLifetime));
                }
            }, CancellationToken.None);
            _serverResolveTasks.Add(resolution.Work);
        }
    }

    private string ServerResolutionContext(TunnelFacts tunnel)
    {
        var profile = _settings.Profile(tunnel.ProfileId);
        var primary = Facts.Primary;
        return $"{profile?.Protocol}|{profile?.Server}|{primary?.Luid}|{primary?.InterfaceIndex}|{primary?.DefaultGateway}|{string.Join(',', primary?.Addresses ?? [])}|{string.Join(',', ServiceDnsAddresses())}";
    }

    private bool IsCurrentResolution(ServerResolution resolution) =>
        _state.Intent != Intent.Off && !_state.ProtectionSuspended && Facts.Primary is not null
        && Facts.Tunnels.TryGetValue(resolution.Tunnel.ProfileId, out var current) && ReferenceEquals(current, resolution.Tunnel)
        && ServerResolutionContext(current) == resolution.Context;

    private async Task OnServerResolvedAsync(ServerResolution resolution, IReadOnlyList<uint> addresses, Exception? failure, CancellationToken token)
    {
        var tunnel = resolution.Tunnel;
        if (!_serverResolutions.TryGetValue(tunnel.ProfileId, out var pending) || !ReferenceEquals(pending, resolution))
        {
            return;
        }

        _serverResolutions.Remove(tunnel.ProfileId);
        tunnel.ServerResolving = false;
        resolution.Stop.Dispose();
        if (!IsCurrentResolution(resolution))
        {
            StartServerResolutions();
            return;
        }

        tunnel.ServerResolvedUtc = _deps.Time.GetUtcNow();
        tunnel.NextServerResolveAt = tunnel.ServerResolvedUtc + (addresses.Count == 0 ? ServerResolveRetry : ServerResolveInterval);
        tunnel.FailedDialsSinceResolve = 0;
        if (failure is not null)
        {
            _deps.Logger.LogWarning(failure, "Не удалось разрешить адрес VPN-сервера {Name}", tunnel.Name);
        }

        if (addresses.Count > 0)
        {
            if (!addresses.Order().SequenceEqual(tunnel.ServerAddresses.Order()))
            {
                Journal("Сведения", $"Адреса VPN-сервера «{tunnel.Name}»: " + string.Join(", ", addresses.Select(Ipv4.Format)));
            }

            tunnel.ServerAddresses = addresses.ToArray();
            _deps.DnsProxy.Pin(resolution.Host, addresses);
            SaveServerCache();
        }

        await ReconcileAsync(token);
    }

    private bool ResolveDue(TunnelFacts tunnel)
    {
        var now = _deps.Time.GetUtcNow();
        if (tunnel.FailedDialsSinceResolve >= 3)
        {
            return true;
        }

        return tunnel.NextServerResolveAt != default
            ? now >= tunnel.NextServerResolveAt
            : tunnel.ServerAddresses.Count == 0 || now - tunnel.ServerResolvedUtc >= ServerResolveInterval;
    }

    private void CancelServerResolution(ServerResolution resolution)
    {
        _serverResolutions.Remove(resolution.Tunnel.ProfileId);
        resolution.Tunnel.ServerResolving = false;
        resolution.Stop.Cancel();
        // Токен живёт до выхода сетевой работы, даже если её реализация не успела заметить отмену.
        _ = resolution.Work.ContinueWith(_ => resolution.Stop.Dispose(), TaskScheduler.Default);
    }

    private void CancelServerResolutions()
    {
        foreach (var resolution in _serverResolutions.Values.ToList())
        {
            CancelServerResolution(resolution);
        }
    }

    private async Task StopServerResolutionsAsync()
    {
        CancelServerResolutions();
        await Task.WhenAll(_serverResolveTasks);
        _serverResolveTasks.Clear();
    }
}
