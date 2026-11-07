using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    private static readonly TimeSpan CertificateProbeTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Не чаще этого — обычная проба: сертификат сервера меняется днями, а не секундами.</summary>
    private static readonly TimeSpan CertificateProbeInterval = TimeSpan.FromMinutes(10);

    /// <summary>
    /// На сколько закрепляется адрес проверки отзыва: с запасом на всё подключение. Действует закрепление только
    /// пока проверка нужна (<see cref="RevocationHostsNeeded"/>): с подъёмом туннеля оно снимается.
    /// </summary>
    private static readonly TimeSpan RevocationPinTtl = TimeSpan.FromHours(1);

    /// <summary>Порт ссылки http без явного порта.</summary>
    private const ushort DefaultHttpPort = 80;

    /// <summary>Со скольких ссылок издателя служба пробует скачать промежуточный сертификат.</summary>
    private const int MaxIssuerSources = 2;

    /// <summary>Сколько адресов одного узла издателя открывается службе на время загрузки.</summary>
    private const int MaxIssuerAddresses = 4;

    /// <summary>Предел загрузки промежуточного сертификата с одного узла.</summary>
    private static readonly TimeSpan IntermediateFetchTimeout = TimeSpan.FromSeconds(15);

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
        var generation = tunnel.CertificateProbeGeneration = ++_attemptGeneration;
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
                // С каким именем шла проба: к приходу результата сервер профиля мог смениться.
                facts = facts is null ? null : facts with { ProbedHost = host };
            }
            catch (Exception ex)
            {
                _deps.Logger.LogWarning(ex, "Проба сертификата сервера {Address} не удалась", Ipv4.Format(address));
            }

            await EnqueueAsync("CertificateProbe", () => OnCertificateProbedAsync(profileId, generation, facts, reason, CancellationToken.None));
        });
    }

    /// <summary>
    /// Результат пробы. Новые узлы проверки отзыва открываются защитой (правило для домена «напрямую»),
    /// и если дозвон стоял именно из-за отзыва — назначается повтор: причина отказа только что устранена.
    /// </summary>
    internal async Task OnCertificateProbedAsync(Guid profileId, int generation, ServerCertificateFacts? facts, string reason, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { } tunnel || generation != tunnel.CertificateProbeGeneration)
        {
            return;
        }

        tunnel.CertificateProbeRunning = false;
        if (facts is null)
        {
            _deps.Logger.LogInformation("Сервер «{Name}» не ответил по TLS: сертификат не посмотреть ({Reason})", tunnel.Name, reason);
            return;
        }

        if (!TryParseServer(_settings.Profile(profileId), out var current)
            || !string.Equals(current.IsIpLiteral ? null : current.Host, facts.ProbedHost, StringComparison.OrdinalIgnoreCase))
        {
            // Проба шла к прежнему серверу профиля: её сертификат и адреса к нынешнему не относятся.
            _deps.Logger.LogInformation("«{Name}»: результат пробы сертификата отброшен — сервер профиля сменился", tunnel.Name);
            return;
        }

        var known = tunnel.ServerCertificate;
        tunnel.ServerCertificate = facts;
        if (known?.Thumbprint != facts.Thumbprint)
        {
            Journal("Сведения", $"«{tunnel.Name}»: {facts.Describe(_deps.Time.GetUtcNow())}");
        }

        var trusted = RevocationHostsTrusted(current, facts);
        if (!trusted)
        {
            // Сертификат мог предъявить кто угодно, ответивший на адрес сервера: его адреса отзыва
            // открыли бы наружу чужие имена в обход туннеля. Прежний список тоже снимается: пока сервер
            // предъявляет непроверенный сертификат, держать для него открытые адреса незачем.
            _deps.Logger.LogWarning("«{Name}»: сертификат сервера не прошёл проверку ({Problem}) — адреса отзыва из него не открываются",
                tunnel.Name, facts.ChainProblem ?? "имя не совпадает с сервером профиля");
            if (tunnel.RevocationHosts.Count > 0)
            {
                tunnel.RevocationHosts = [];
                SaveServerCache();
            }

            await ReconcileAsync(cancellationToken);
            if (IssuerFetchAllowed(current, facts))
            {
                // Цепочка не строится только из-за промежуточного сертификата: служба скачивает его сама.
                await StartIntermediateFetchAsync(tunnel, facts, cancellationToken);
            }

            return;
        }

        var fresh = facts.RevocationHosts.Where(IsRevocationHost)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var learned = fresh
            .Where(host => !tunnel.RevocationHosts.Contains(host, StringComparer.OrdinalIgnoreCase))
            .ToList();
        var changed = learned.Count > 0 || fresh.Count != tunnel.RevocationHosts.Count;

        // Список заменяется свежим: узлы прежнего сертификата больше не нужны и не должны копиться.
        tunnel.RevocationHosts = fresh;
        if (changed)
        {
            SaveServerCache();
        }

        if (learned.Count == 0)
        {
            await ReconcileAsync(cancellationToken);
            return;
        }

        tunnel.RevocationRetryUsed = false;
        Journal("Сведения", $"«{tunnel.Name}»: проверка отзыва сертификата идёт через {string.Join(", ", learned)} - пока подключение не поднято, "
            + "защита пропускает к этим адресам напрямую только запросы списка отзыва.");
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
    /// Адресам отзыва можно верить, только если сертификат выдан доверенным издателем: их вписывает
    /// удостоверяющий центр, а не тот, кто ответил на адрес сервера. Сервер задан именем — сертификат
    /// ещё и должен быть выдан на это имя. Сервер задан IP — имени для сверки нет, хватает доверенной
    /// цепочки: адреса отзыва в ней всё равно принадлежат удостоверяющему центру.
    /// </summary>
    private static bool RevocationHostsTrusted(ServerAddress server, ServerCertificateFacts facts) =>
        facts.ChainProblem is null && (server.IsIpLiteral || facts.NameMatches);

    /// <summary>
    /// Цепочка не строится только из-за промежуточного сертификата, который сервер не прислал: служба пробует
    /// скачать его сама. Сервер, заданный IP, так не проверить: имени для сверки нет, а доверенной цепочки ещё нет.
    /// </summary>
    private static bool IssuerFetchAllowed(ServerAddress server, ServerCertificateFacts facts) =>
        facts.MissingIntermediateOnly && !server.IsIpLiteral && facts.NameMatches && facts.LeafRaw is not null;

    /// <summary>
    /// Загрузка промежуточного сертификата самой службой. Адреса издателя взяты из ещё не проверенного
    /// сертификата, поэтому защита открывает их только процессу службы (<see cref="ServiceFetchEndpoints"/>), на
    /// время загрузки, а скачанное принимается, только если с ним цепочка доходит до доверенного корня компьютера.
    /// Тот же лист повторно не скачивается раньше обычной пробы, а после успешной установки - совсем.
    /// </summary>
    private async Task StartIntermediateFetchAsync(TunnelFacts tunnel, ServerCertificateFacts facts, CancellationToken cancellationToken)
    {
        var now = _deps.Time.GetUtcNow();
        if (tunnel.IntermediateFetchRunning || facts.LeafRaw is not { } leaf || Facts.Primary is not { } primary
            || (tunnel.IntermediateFetchThumbprint == facts.Thumbprint
                && (tunnel.IntermediateFetchInstalled || now - tunnel.IntermediateFetchUtc < CertificateProbeInterval)))
        {
            return;
        }

        tunnel.IntermediateFetchThumbprint = facts.Thumbprint;
        tunnel.IntermediateFetchUtc = now;
        tunnel.IntermediateFetchInstalled = false;
        var sources = new List<SplitVpn.Windows.Security.IntermediateSource>();
        using (var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            limit.CancelAfter(RevocationResolveLimit);
            var urls = facts.IssuerUrls
                .Select(url => Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri : null)
                .OfType<Uri>()
                .Where(uri => uri.Scheme == Uri.UriSchemeHttp && uri.Port is > 0 and <= ushort.MaxValue && IsRevocationHost(uri.Host))
                .DistinctBy(uri => uri.AbsoluteUri, StringComparer.OrdinalIgnoreCase)
                .Take(MaxIssuerSources);
            foreach (var url in urls)
            {
                var addresses = await ResolveQuietlyAsync(url.Host, primary.InterfaceIndex, limit.Token);
                if (addresses.Count > 0)
                {
                    sources.Add(new SplitVpn.Windows.Security.IntermediateSource(url, addresses.Take(MaxIssuerAddresses).ToList()));
                }
            }
        }

        if (sources.Count == 0)
        {
            Journal("Предупреждение", $"«{tunnel.Name}»: сервер не прислал промежуточный сертификат, а адрес его издателя не разрешился. "
                + "Подключение не поднимется, пока администратор сервера не настроит отправку полной цепочки.");
            return;
        }

        _serviceFetches[tunnel.ProfileId] = sources
            .SelectMany(s => s.Addresses.Select(a => new RevocationEndpoint(a, (ushort)s.Url.Port)))
            .Distinct()
            .ToList();
        tunnel.IntermediateFetchRunning = true;
        Journal("Сведения", $"«{tunnel.Name}»: сервер не прислал промежуточный сертификат - служба скачивает его сама с "
            + string.Join(", ", sources.Select(s => s.Url.Host)) + "; другим программам этот адрес не открывается.");
        await ReconcileAsync(cancellationToken);

        var profileId = tunnel.ProfileId;
        var interfaceIndex = primary.InterfaceIndex;
        _ = Task.Run(async () =>
        {
            SplitVpn.Windows.Security.IntermediateInstallResult result;
            try
            {
                result = await _deps.Probes.InstallIntermediateAsync(leaf, sources, interfaceIndex, IntermediateFetchTimeout, CancellationToken.None);
            }
            catch (Exception ex)
            {
                result = new SplitVpn.Windows.Security.IntermediateInstallResult(false, "Промежуточный сертификат не получен: " + ex.Message);
            }

            await EnqueueAsync("IntermediateFetched", () => OnIntermediateFetchedAsync(profileId, result, CancellationToken.None));
        }, CancellationToken.None);
    }

    /// <summary>Загрузка закончилась: разрешение службе снимается, при успехе сертификат сервера проверяется заново.</summary>
    internal async Task OnIntermediateFetchedAsync(Guid profileId, SplitVpn.Windows.Security.IntermediateInstallResult result, CancellationToken cancellationToken)
    {
        _serviceFetches.Remove(profileId);
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { } tunnel)
        {
            await ReconcileAsync(cancellationToken);
            return;
        }

        tunnel.IntermediateFetchRunning = false;
        tunnel.IntermediateFetchInstalled = result.Installed;
        Journal(result.Installed ? "Сведения" : "Предупреждение", $"«{tunnel.Name}»: {result.Message}"
            + (result.Installed ? "" : " Подключение не поднимется, пока администратор сервера не настроит отправку полной цепочки."));
        if (result.Installed && tunnel.BlockingError == ErrorCategory.Certificate)
        {
            // Отказ был из-за неполной цепочки: недостающее звено теперь у Windows, и повтор имеет смысл.
            tunnel.BlockingError = ErrorCategory.None;
            tunnel.NextDialAt = _deps.Time.GetUtcNow();
            Journal("Сведения", $"«{tunnel.Name}»: повтор подключения после установки промежуточного сертификата.");
        }

        await ReconcileAsync(cancellationToken);
        if (result.Installed)
        {
            // Теперь цепочка строится: новая проба откроет адреса проверки отзыва уже из проверенного сертификата.
            EnsureCertificateProbe(tunnel, "промежуточный сертификат установлен", force: true);
        }
    }

    /// <summary>Узлы издателя, открытые процессу службы на время загрузки промежуточного сертификата.</summary>
    private readonly Dictionary<Guid, List<RevocationEndpoint>> _serviceFetches = [];

    private List<RevocationEndpoint> ServiceFetchEndpoints() => _serviceFetches.Values.SelectMany(e => e).Distinct().ToList();

    /// <summary>
    /// Узел проверки отзыва — полное имя хотя бы из двух меток: имя из одной метки («com») стало бы
    /// правилом на целую зону и увело бы её мимо туннеля.
    /// </summary>
    internal static bool IsRevocationHost(string host)
    {
        var name = SettingsSerializer.NormalizeSuffix(host);
        return name.Contains('.', StringComparison.Ordinal) && Uri.CheckHostName(name) == UriHostNameType.Dns;
    }

    /// <summary>
    /// Разрешает узлы проверки отзыва и даёт адресам служебное закрепление. Одного правила для домена мало:
    /// системный кеш DNS может ответить Windows из старой записи, минуя посредника, - тогда закрепления
    /// по запросу не появится и обращение за списком отзыва упрётся в блокирующий фильтр. Узлы, которые сейчас
    /// не нужны (туннель уже поднят), не разрешаются: их закрепление всё равно бы не действовало. Имя в кеше
    /// посредника не закрепляется: его ответ шёл бы мимо службы, и, когда проверка понадобится снова, адрес не открылся бы.
    /// </summary>
    private async Task PinRevocationAddressesAsync(IReadOnlyList<string> hosts, CancellationToken cancellationToken)
    {
        var needed = RevocationHostsNeeded().ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (Facts.Primary is not { } primary || !hosts.Any(needed.Contains))
        {
            return;
        }

        var expires = _deps.Time.GetUtcNow() + RevocationPinTtl;
        // Разрешение имён идёт в очереди актора: общий предел не даёт ему встать на несколько узлов подряд.
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(RevocationResolveLimit);
        foreach (var host in hosts.Where(needed.Contains))
        {
            if (limit.IsCancellationRequested)
            {
                break;
            }

            // Пользовательский маршрут важнее служебного: даже начальное разрешение не идёт в обход него.
            if (MatchingDomainRule(host) is not null)
            {
                continue;
            }

            var addresses = await ResolveQuietlyAsync(host, primary.InterfaceIndex, limit.Token);
            if (addresses.Count > 0)
            {
                PinDirect(SettingsSerializer.NormalizeSuffix(host), addresses, expires);
            }
        }

        // Windows могла ответить себе из кеша до того, как адрес был открыт: без сброса она не переспросит.
        _deps.Dns.FlushCache();
    }

    /// <summary>
    /// Узлы проверки отзыва, которые нужны сейчас: их туннель не поднят и будет дозваниваться (VPN включён, туннель
    /// не положен пользователем). Поднятому туннелю они не нужны - его сертификат уже проверен при подключении.
    /// </summary>
    private IEnumerable<string> RevocationHostsNeeded() =>
        _state.Intent != Intent.Connected || _state.ProtectionSuspended
            ? []
            : Facts.Tunnels.Values.Where(t => !t.IsUp && !t.Paused).SelectMany(t => t.RevocationHosts).Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>Служебные закрепления узлов проверки отзыва для защиты: адрес и порт TCP каждой ссылки на узел.</summary>
    private List<RevocationEndpoint> RevocationEndpoints() =>
        Facts.RevocationPins
            .SelectMany(pin => pin.Value.SelectMany(RevocationPorts).Distinct().Select(port => new RevocationEndpoint(pin.Key, port)))
            .ToList();

    /// <summary>
    /// Порты ссылок на узел проверки отзыва в сертификатах серверов (http://узел[:порт]/...). Сертификат ещё не
    /// смотрели (узлы взяты из кеша после перезапуска службы) - 80, порт http по умолчанию.
    /// </summary>
    private List<ushort> RevocationPorts(string suffix)
    {
        // Порт из сертификата с непроверенной цепочкой не берётся: его выбрал тот, кто предъявил сертификат.
        var ports = Facts.Tunnels.Values
            .Where(t => t.ServerCertificate is { ChainProblem: null })
            .SelectMany(t => t.ServerCertificate!.RevocationUrls)
            .Select(url => Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri : null)
            .OfType<Uri>()
            .Where(uri => uri.Port is > 0 and <= ushort.MaxValue && SettingsSerializer.NormalizeSuffix(uri.Host) == suffix)
            .Select(uri => (ushort)uri.Port)
            .Distinct()
            .ToList();
        return ports.Count > 0 ? ports : [DefaultHttpPort];
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
