using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
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
        var nameMatches = false;
        using var stream = new NetworkStream(socket, ownsSocket: false);
        using var tls = new SslStream(stream, leaveInnerStreamOpen: true, (_, certificate, chain, errors) =>
        {
            Collect(presented, certificate, chain);
            nameMatches = certificate is not null && (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
            // Отказ рукопожатию: проба уже увидела всё, что нужно, а доверять серверу она не вправе.
            return false;
        });

        try
        {
            await tls.AuthenticateAsClientAsync(ClientOptions(TargetName(address, host)), cts.Token);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException or OperationCanceledException)
        {
            // Рукопожатие оборвано пробой или сервером: сертификат собран обратным вызовом до обрыва.
        }

        return presented.Count == 0 ? null : Facts(presented, nameMatches);
    }

    /// <summary>
    /// Параметры рукопожатия пробы. Цепочка строится без загрузок: иначе CryptoAPI от имени SYSTEM сам скачал бы
    /// недостающий промежуточный по AIA (запрос службы в сеть по адресу из чужого сертификата), и нехватку
    /// промежуточного, которую проба должна объяснить, было бы не увидеть. Проверка отзыва здесь и не нужна,
    /// и невозможна: именно её адреса проба и ищет. Решение о доверии от этого не меняется - обратный вызов
    /// отказывает рукопожатию всегда.
    /// </summary>
    internal static SslClientAuthenticationOptions ClientOptions(string targetHost) => new()
    {
        TargetHost = targetHost,
        CertificateChainPolicy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
        },
    };

    /// <summary>Имя для SNI: без него сервер с несколькими сайтами предъявит не тот сертификат.</summary>
    private static string TargetName(uint address, string? host) =>
        host is { Length: > 0 } name && Uri.CheckHostName(name) == UriHostNameType.Dns ? name : Ipv4.Format(address);

    /// <summary>
    /// Лист и то, что сервер прислал сам: SslStream кладёт присланные сертификаты в ExtraStore политики цепочки.
    /// ChainElements не годятся: это цепочка, достроенная локально (из хранилищ компьютера), и промежуточный,
    /// которого сервер не прислал, выглядел бы присланным - нехватку его проба не заметила бы. Сертификаты
    /// копируются байтами: объекты обратного вызова живут только на время рукопожатия и после возврата уже освобождены.
    /// </summary>
    internal static void Collect(List<byte[]> presented, X509Certificate? certificate, X509Chain? chain)
    {
        if (certificate is not null)
        {
            presented.Add(certificate.GetRawCertData());
        }

        foreach (var sent in chain?.ChainPolicy.ExtraStore ?? [])
        {
            presented.Add(sent.RawData);
        }
    }

    internal static ServerCertificateFacts Facts(List<byte[]> presented, bool nameMatches)
    {
        var chain = presented.DistinctBy(raw => Convert.ToHexString(SHA256.HashData(raw))).Select(X509CertificateLoader.LoadCertificate).ToList();
        try
        {
            var leaf = chain[0];
            var urls = chain.SelectMany(RevocationUrls).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var (problem, missingIntermediate) = ChainProblem(leaf, chain);
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
                ChainProblem = problem,
                MissingIntermediateOnly = missingIntermediate,
                IssuerHosts = Hosts(IssuerUrls(leaf)),
                IssuerUrls = IssuerUrls(leaf),
                LeafRaw = leaf.RawData,
                NameMatches = nameMatches,
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
                var san = new X509SubjectAlternativeNameExtension(extension.RawData);
                names.AddRange(san.EnumerateDnsNames());
                names.AddRange(san.EnumerateIPAddresses().Select(address => address.ToString()));
            }
        }

        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Адреса списков отзыва (CRL), OCSP и издателя (AIA).</summary>
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

    /// <summary>
    /// Адреса издателя листа (AIA caIssuers): оттуда служба скачивает промежуточный сертификат, который
    /// сервер не прислал. OCSP из того же расширения сюда не входит.
    /// </summary>
    private static List<string> IssuerUrls(X509Certificate2 leaf)
    {
        var urls = new List<string>();
        foreach (var extension in leaf.Extensions)
        {
            if (extension.Oid?.Value != AuthorityInformationAccessOid)
            {
                continue;
            }

            try
            {
                urls.AddRange(new X509AuthorityInformationAccessExtension(extension.RawData, extension.Critical).EnumerateCAIssuersUris()
                    .Where(url => Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https"));
            }
            catch (CryptographicException)
            {
                // Повреждённое расширение: адресов издателя нет.
            }
        }

        return urls;
    }

    /// <summary>
    /// Ссылки из расширения — значения URI (GeneralName [6]) на любой глубине DER. Поиск «http://» по байтам
    /// склеивал ссылку со следующими байтами разметки, если они печатные («...lencr.org0"»): так терялся OCSP,
    /// за которым идёт адрес издателя.
    /// </summary>
    private static List<string> ExtractUrls(byte[] raw)
    {
        var urls = new List<string>();
        try
        {
            CollectUris(new AsnReader(raw, AsnEncodingRules.DER), urls);
        }
        catch (Exception ex) when (ex is AsnContentException or ArgumentException)
        {
            // Повреждённое или неожиданное расширение: что успели разобрать - остаётся. ArgumentException бросает
            // чтение конструкции с универсальным тегом не того вида: проба не должна из-за этого вернуть ничего.
        }

        return urls.Where(url => Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https").ToList();
    }

    private static readonly Asn1Tag UriTag = new(TagClass.ContextSpecific, 6);

    private static void CollectUris(AsnReader reader, List<string> urls)
    {
        while (reader.HasData)
        {
            var tag = reader.PeekTag();
            if (tag.HasSameClassAndValue(UriTag) && !tag.IsConstructed)
            {
                urls.Add(Encoding.ASCII.GetString(reader.ReadOctetString(UriTag)));
            }
            else if (tag.IsConstructed && tag.HasSameClassAndValue(Asn1Tag.SetOf))
            {
                // SET встречается в имени DirName (cRLIssuer, имя точки распространения): ReadSequence его не читает.
                // Порядок элементов не проверяется - сертификаты с несортированным SET в DER встречаются.
                CollectUris(reader.ReadSetOf(skipSortOrderValidation: true, tag), urls);
            }
            else if (tag.IsConstructed && (tag.TagClass != TagClass.Universal || tag.HasSameClassAndValue(Asn1Tag.Sequence)))
            {
                CollectUris(reader.ReadSequence(tag), urls);
            }
            else
            {
                reader.ReadEncodedValue();
            }
        }
    }

    private static List<string> Hosts(IEnumerable<string> urls) => urls
        .Select(url => Uri.TryCreate(url, UriKind.Absolute, out var parsed) ? parsed.Host : "")
        // Имя из одной метки («com») стало бы правилом на целую зону: такие не берутся.
        .Where(host => host.Contains('.', StringComparison.Ordinal) && Uri.CheckHostName(host) is UriHostNameType.Dns or UriHostNameType.IPv4)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    /// <summary>
    /// Что не так с цепочкой, если смотреть без проверки отзыва: срок, недоверенный корень, нехватка
    /// промежуточных. Отзыв здесь не проверяется — за него отвечает отдельная ошибка подключения. Второе
    /// значение — цепочка не строится только из-за отсутствующего промежуточного (кроме неполноты — разве что
    /// неизвестный отзыв), а не из-за недоверенного корня или срока.
    /// </summary>
    private static (string? Problem, bool MissingIntermediateOnly) ChainProblem(X509Certificate2 leaf, List<X509Certificate2> presented)
    {
        using var chain = new X509Chain(useMachineContext: true);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        foreach (var certificate in presented.Skip(1))
        {
            chain.ChainPolicy.ExtraStore.Add(certificate);
        }

        if (chain.Build(leaf))
        {
            return (null, false);
        }

        var flags = chain.ChainStatus
            .Select(status => status.Status)
            .Where(status => status != X509ChainStatusFlags.NoError)
            .ToList();
        var problems = flags.Select(Describe).Distinct(StringComparer.Ordinal).ToList();
        var missingIntermediate = flags.Contains(X509ChainStatusFlags.PartialChain)
            && flags.TrueForAll(status => status is X509ChainStatusFlags.PartialChain
                or X509ChainStatusFlags.RevocationStatusUnknown or X509ChainStatusFlags.OfflineRevocation);
        return problems.Count == 0 ? (null, false) : (string.Join("; ", problems), missingIntermediate);
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
