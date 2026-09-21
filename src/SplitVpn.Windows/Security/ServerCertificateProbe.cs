using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SplitVpn.Core.Net;
using SplitVpn.Core.State;

namespace SplitVpn.Windows.Security;

/// <summary>
/// Смотрит, какой сертификат предъявляет сервер по TLS, и куда ведёт проверка его отзыва. Рукопожатие
/// намеренно не доводится до конца: проба только читает предъявленное, сеанс не устанавливается и доверие
/// никому не выдаётся. Нужна для двух вещей — объяснить отказ по сертификату словами и узнать адреса
/// списков отзыва, которые защита обязана пропустить.
/// </summary>
public static class ServerCertificateProbe
{
    private const string SubjectAlternativeNameOid = "2.5.29.17";
    private const string CrlDistributionPointsOid = "2.5.29.31";
    private const string AuthorityInformationAccessOid = "1.3.6.1.5.5.7.1.1";

    private static readonly byte[] HttpPrefix = "http://"u8.ToArray();

    public static async Task<ServerCertificateFacts?> TryProbeAsync(
        uint address, ushort port, string? host, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(Ipv4.ToAddress(address), port), cts.Token);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return null;
        }

        var presented = new List<byte[]>();
        using var stream = new NetworkStream(socket, ownsSocket: false);
        using var tls = new SslStream(stream, leaveInnerStreamOpen: true, (_, certificate, chain, _) =>
        {
            Collect(presented, certificate, chain);
            // Отказ рукопожатию: проба уже увидела всё, что нужно, а доверять серверу она не вправе.
            return false;
        });

        try
        {
            await tls.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = TargetName(address, host),
                    // Проверка отзыва здесь и не нужна, и невозможна: именно её адреса проба и ищет.
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                },
                cts.Token);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException or OperationCanceledException)
        {
            // Рукопожатие оборвано пробой или сервером: сертификат собран обратным вызовом до обрыва.
        }

        return presented.Count == 0 ? null : Facts(presented);
    }

    /// <summary>Имя для SNI: без него сервер с несколькими сайтами предъявит не тот сертификат.</summary>
    private static string TargetName(uint address, string? host) =>
        host is { Length: > 0 } name && Uri.CheckHostName(name) == UriHostNameType.Dns ? name : Ipv4.Format(address);

    /// <summary>
    /// Сертификаты копируются байтами: объекты обратного вызова живут только на время рукопожатия
    /// и после возврата уже освобождены.
    /// </summary>
    private static void Collect(List<byte[]> presented, X509Certificate? certificate, X509Chain? chain)
    {
        if (certificate is not null)
        {
            presented.Add(certificate.GetRawCertData());
        }

        foreach (var element in chain?.ChainElements ?? (IEnumerable<X509ChainElement>)[])
        {
            presented.Add(element.Certificate.RawData);
        }
    }

    private static ServerCertificateFacts Facts(List<byte[]> presented)
    {
        var chain = presented.Select(X509CertificateLoader.LoadCertificate).DistinctBy(c => c.Thumbprint).ToList();
        try
        {
            var leaf = chain[0];
            var urls = chain.SelectMany(RevocationUrls).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            return new ServerCertificateFacts
            {
                Subject = leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                Issuer = leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: true),
                Names = Names(leaf),
                NotBefore = leaf.NotBefore,
                NotAfter = leaf.NotAfter,
                Thumbprint = leaf.Thumbprint,
                RevocationUrls = urls,
                RevocationHosts = Hosts(urls),
                ChainProblem = ChainProblem(leaf, chain),
                ProbedUtc = DateTimeOffset.UtcNow,
            };
        }
        finally
        {
            foreach (var certificate in chain)
            {
                certificate.Dispose();
            }
        }
    }

    private static List<string> Names(X509Certificate2 certificate)
    {
        var names = new List<string>();
        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value == SubjectAlternativeNameOid)
            {
                names.AddRange(new X509SubjectAlternativeNameExtension(extension.RawData).EnumerateDnsNames());
            }
        }

        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Адреса списков отзыва и OCSP. Разбираются по тексту: в обоих расширениях это ASCII-ссылки.</summary>
    private static IEnumerable<string> RevocationUrls(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value is CrlDistributionPointsOid or AuthorityInformationAccessOid)
            {
                foreach (var url in ExtractUrls(extension.RawData))
                {
                    yield return url;
                }
            }
        }
    }

    private static IEnumerable<string> ExtractUrls(byte[] raw)
    {
        for (var index = 0; index + HttpPrefix.Length <= raw.Length; index++)
        {
            if (!raw.AsSpan(index, HttpPrefix.Length).SequenceEqual(HttpPrefix))
            {
                continue;
            }

            var end = index;
            while (end < raw.Length && raw[end] is > 0x20 and < 0x7F)
            {
                end++;
            }

            yield return Encoding.ASCII.GetString(raw, index, end - index);
            index = end;
        }
    }

    private static List<string> Hosts(IEnumerable<string> urls) => urls
        .Select(url => Uri.TryCreate(url, UriKind.Absolute, out var parsed) ? parsed.Host : "")
        .Where(host => host.Length > 0 && Uri.CheckHostName(host) == UriHostNameType.Dns)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    /// <summary>
    /// Что не так с цепочкой, если смотреть без проверки отзыва: срок, недоверенный корень, нехватка
    /// промежуточных. Отзыв здесь не проверяется — за него отвечает отдельная ошибка подключения.
    /// </summary>
    private static string? ChainProblem(X509Certificate2 leaf, List<X509Certificate2> presented)
    {
        using var chain = new X509Chain(useMachineContext: true);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        foreach (var certificate in presented.Skip(1))
        {
            chain.ChainPolicy.ExtraStore.Add(certificate);
        }

        if (chain.Build(leaf))
        {
            return null;
        }

        var problems = chain.ChainStatus
            .Where(status => status.Status != X509ChainStatusFlags.NoError)
            .Select(status => Describe(status.Status))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return problems.Count == 0 ? null : string.Join("; ", problems);
    }

    private static string Describe(X509ChainStatusFlags status) => status switch
    {
        X509ChainStatusFlags.NotTimeValid => "срок действия истёк или ещё не начался",
        X509ChainStatusFlags.UntrustedRoot => "корневой сертификат издателя не установлен в хранилище компьютера",
        X509ChainStatusFlags.PartialChain => "цепочка неполная: сервер не прислал промежуточный сертификат",
        X509ChainStatusFlags.Revoked => "сертификат отозван",
        X509ChainStatusFlags.RevocationStatusUnknown or X509ChainStatusFlags.OfflineRevocation => "состояние отзыва неизвестно",
        X509ChainStatusFlags.NotValidForUsage => "сертификат не предназначен для проверки подлинности сервера",
        X509ChainStatusFlags.CtlNotTimeValid or X509ChainStatusFlags.NotTimeNested => "нарушены сроки в цепочке",
        _ => "проверка цепочки: " + status,
    };
}
