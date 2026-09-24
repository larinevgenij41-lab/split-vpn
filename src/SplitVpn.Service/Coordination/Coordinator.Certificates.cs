using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    private static readonly TimeSpan CertificateProbeTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Не чаще этого — обычная проба: сертификат сервера меняется днями, а не секундами.</summary>
    private static readonly TimeSpan CertificateProbeInterval = TimeSpan.FromMinutes(10);

    /// <summary>На сколько закрепляется адрес проверки отзыва: с запасом на всё подключение.</summary>
    private static readonly TimeSpan RevocationPinTtl = TimeSpan.FromHours(1);

    /// <summary>Общий предел на разрешение всех узлов проверки отзыва: очередь актора не должна ждать дольше.</summary>
    private static readonly TimeSpan RevocationResolveLimit = TimeSpan.FromSeconds(6);

    /// <summary>
    /// Проба имеет смысл там, где сервер сам говорит по TLS: это SSTP. У IKEv2 и L2TP сертификат
    /// приходит внутри IKE, снаружи его не посмотреть; у AnyConnect сеансом занимается помощник.
    /// </summary>
    private static bool CanProbeCertificate(TunnelFacts tunnel) =>
        tunnel.Protocol == VpnProtocol.Sstp && tunnel.ServerAddresses.Count > 0;

    /// <summary>
    /// Смотрит сертификат сервера в фоне. Нужно до первого дозвона: из сертификата известно, куда Windows
    /// пойдёт за списком отзыва, и только зная это, защита может пропустить проверку отзыва наружу.
    /// </summary>
    private void EnsureCertificateProbe(TunnelFacts tunnel, string reason, bool force = false)
    {
        var now = _deps.Time.GetUtcNow();
        if (!CanProbeCertificate(tunnel) || tunnel.CertificateProbeRunning
            || (!force && tunnel.ServerCertificate is not null && now - tunnel.LastCertificateProbeUtc < CertificateProbeInterval))
        {
            return;
        }

        tunnel.CertificateProbeRunning = true;
        tunnel.LastCertificateProbeUtc = now;
        var profileId = tunnel.ProfileId;
        var address = tunnel.ServerAddresses[0];
        var port = tunnel.ServerPort;
        var host = TryParseServer(_settings.Profile(profileId), out var server) && !server.IsIpLiteral ? server.Host : null;
        _ = Task.Run(async () =>
        {
            ServerCertificateFacts? facts = null;
            try
            {
                facts = await _deps.Probes.ServerCertificateAsync(address, port, host, CertificateProbeTimeout, CancellationToken.None);
            }
            catch (Exception ex)
            {
                _deps.Logger.LogWarning(ex, "Проба сертификата сервера {Address} не удалась", Ipv4.Format(address));
            }

            await EnqueueAsync("CertificateProbe", () => OnCertificateProbedAsync(profileId, facts, reason, CancellationToken.None));
        });
    }

    /// <summary>
    /// Результат пробы. Новые узлы проверки отзыва открываются защитой (правило для домена «напрямую»),
    /// и если дозвон стоял именно из-за отзыва — назначается повтор: причина отказа только что устранена.
    /// </summary>
    internal async Task OnCertificateProbedAsync(Guid profileId, ServerCertificateFacts? facts, string reason, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { } tunnel)
        {
            return;
        }

        tunnel.CertificateProbeRunning = false;
        if (facts is null)
        {
            _deps.Logger.LogInformation("Сервер «{Name}» не ответил по TLS: сертификат не посмотреть ({Reason})", tunnel.Name, reason);
            return;
        }

        var known = tunnel.ServerCertificate;
        tunnel.ServerCertificate = facts;
        if (known?.Thumbprint != facts.Thumbprint)
        {
            Journal("Сведения", $"«{tunnel.Name}»: {facts.Describe(_deps.Time.GetUtcNow())}");
        }

        var learned = facts.RevocationHosts
            .Where(host => !tunnel.RevocationHosts.Contains(host, StringComparer.OrdinalIgnoreCase))
            .ToList();
        if (learned.Count == 0)
        {
            await ReconcileAsync(cancellationToken);
            return;
        }

        tunnel.RevocationHosts = [.. tunnel.RevocationHosts, .. learned];
        tunnel.RevocationRetryUsed = false;
        SaveServerCache();
        Journal("Сведения", $"«{tunnel.Name}»: проверка отзыва сертификата идёт через {string.Join(", ", learned)} — "
            + "защита пропускает эти адреса напрямую.");
        await PinRevocationAddressesAsync(learned, cancellationToken);
        if (tunnel.BlockingError == ErrorCategory.Certificate)
        {
            // Отказ был из-за закрытого адреса проверки отзыва: теперь он открыт, и повтор имеет смысл.
            tunnel.BlockingError = ErrorCategory.None;
            tunnel.NextDialAt = _deps.Time.GetUtcNow();
            tunnel.RevocationRetryUsed = true;
            Journal("Сведения", $"«{tunnel.Name}»: повтор подключения после открытия адресов проверки отзыва.");
        }

        await ReconcileAsync(cancellationToken);
    }

    /// <summary>
    /// Разрешает узлы проверки отзыва и закрепляет адреса за прямым выходом. Одного правила для домена мало:
    /// системный кеш DNS может ответить Windows из старой записи, минуя посредника, — тогда закрепления
    /// по запросу не появится и обращение за списком отзыва упрётся в блокирующий фильтр.
    /// </summary>
    private async Task PinRevocationAddressesAsync(IReadOnlyList<string> hosts, CancellationToken cancellationToken)
    {
        if (Facts.Primary is not { } primary)
        {
            return;
        }

        var expires = _deps.Time.GetUtcNow() + RevocationPinTtl;
        // Разрешение имён идёт в очереди актора: общий предел не даёт ему встать на несколько узлов подряд.
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(RevocationResolveLimit);
        foreach (var host in hosts)
        {
            if (limit.IsCancellationRequested)
            {
                break;
            }

            var addresses = await ResolveQuietlyAsync(host, primary.InterfaceIndex, limit.Token);
            var suffix = SettingsSerializer.NormalizeSuffix(host);
            foreach (var address in addresses)
            {
                PinDirect(suffix, address, expires);
            }

            if (addresses.Count > 0)
            {
                _deps.DnsProxy.Pin(host, addresses);
            }
        }

        // Windows могла ответить себе из кеша до того, как адрес был открыт: без сброса она не переспросит.
        _deps.Dns.FlushCache();
    }

    /// <summary>Имя не разрешилось — не беда: правило для домена закрепит адрес по запросу самой Windows.</summary>
    private async Task<IReadOnlyList<uint>> ResolveQuietlyAsync(string host, uint interfaceIndex, CancellationToken cancellationToken)
    {
        try
        {
            return await _deps.Resolver.ResolveAsync(host, ServiceDnsAddresses(), interfaceIndex, cancellationToken);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or System.Net.Sockets.SocketException)
        {
            _deps.Logger.LogInformation("Узел проверки отзыва {Host} не разрешился: {Error}", host, ex.Message);
            return [];
        }
    }

    /// <summary>Сколько осталось до конца срока, чтобы предупредить заранее. Короткие сертификаты (Let's
    /// Encrypt выдаёт на неделю) не должны давать предупреждение в обычный день — только в последние часы.</summary>
    private static readonly TimeSpan CertificateWarningWindow = TimeSpan.FromHours(12);

    /// <summary>
    /// Сертификат сервера кончается или уже кончился. Сама программа его не продлевает — это делается
    /// на сервере, — но предупреждение появляется до того, как подключение перестанет подниматься.
    /// </summary>
    private IEnumerable<StatusWarning> CertificateWarnings()
    {
        var now = _deps.Time.GetUtcNow();
        foreach (var tunnel in Facts.Tunnels.Values)
        {
            if (tunnel.ServerCertificate is not { } certificate)
            {
                continue;
            }

            if (certificate.Expired(now))
            {
                yield return new StatusWarning("server-certificate-expired",
                    $"«{tunnel.Name}»: срок действия сертификата сервера истёк. {certificate.Describe(now)} Продлите его на сервере.",
                    null) { Subject = tunnel.Name };
            }
            else if (certificate.NotAfter - now <= CertificateWarningWindow)
            {
                yield return new StatusWarning("server-certificate-expiring",
                    $"«{tunnel.Name}»: сертификат сервера скоро истечёт. {certificate.Describe(now)}",
                    null) { Subject = tunnel.Name };
            }
        }
    }

    /// <summary>Расшифровка ошибки того туннеля, чей текст показан в общем состоянии.</summary>
    private ConnectionErrorHelp? FirstTunnelHelp()
    {
        if (Facts.Tunnels.Values.FirstOrDefault(t => t.LastErrorText is not null) is not { } tunnel
            || _settings.Profile(tunnel.ProfileId) is not { } profile)
        {
            return null;
        }

        return ErrorHelp(profile, tunnel);
    }

    /// <summary>Расшифровка последней ошибки туннеля для интерфейса: что значит код и что с ним делать.</summary>
    private ConnectionErrorHelp? ErrorHelp(ConnectionProfile profile, TunnelFacts tunnel)
    {
        var category = tunnel.BlockingError != ErrorCategory.None ? tunnel.BlockingError : tunnel.LastErrorCategory;
        if (category == ErrorCategory.None || tunnel.LastErrorText is null)
        {
            return null;
        }

        return ConnectionErrorGuide.For(category, tunnel.LastErrorCode, profile.Protocol, profile.AuthMethod,
            tunnel.ServerCertificate, _deps.Time.GetUtcNow());
    }
}
