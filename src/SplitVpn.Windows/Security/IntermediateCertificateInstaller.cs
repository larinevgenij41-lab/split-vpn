using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SplitVpn.Core.Net;

namespace SplitVpn.Windows.Security;

/// <summary>Откуда скачать издателя листа: ссылка AIA caIssuers и уже разрешённые службой адреса её узла.</summary>
public sealed record IntermediateSource(Uri Url, IReadOnlyList<uint> Addresses);

/// <summary>Итог: промежуточный сертификат проверен и лежит в хранилище компьютера, или почему нет.</summary>
public sealed record IntermediateInstallResult(bool Installed, string Message, string? Subject = null);

/// <summary>
/// Сервер SSTP не прислал промежуточный сертификат. Windows скачала бы его сама по ссылке издателя (AIA), но
/// проверяет сертификат системная служба RAS, и разрешить ей это за защитой можно только для всех программ сразу:
/// адрес издателя берётся из ещё не проверенного сертификата, и подменивший сервер открыл бы так себе путь мимо
/// блокировки. Поэтому сертификат скачивает сама служба «Раздельного VPN» (защита пропускает только её процесс),
/// проверяет, что с ним цепочка листа доходит до доверенного корня компьютера, и кладёт его в хранилище
/// промежуточных центров сертификации компьютера: оттуда его берёт любая проверка цепочки, в том числе RAS.
/// Промежуточный сертификат доверия не добавляет: доверие по-прежнему дают только корни компьютера.
/// </summary>
public static class IntermediateCertificateInstaller
{
    /// <summary>Сертификат весит пару килобайт, набор PKCS#7 - десятки: больше - не то, что нужно.</summary>
    private const int MaxDownloadBytes = 256 * 1024;

    public static async Task<IntermediateInstallResult> InstallAsync(
        byte[] leafRaw, IReadOnlyList<IntermediateSource> sources, uint? interfaceIndex, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(leafRaw);
        ArgumentNullException.ThrowIfNull(sources);
        using var leaf = X509CertificateLoader.LoadCertificate(leafRaw);
        var problems = new List<string>();
        foreach (var source in sources)
        {
            byte[] downloaded;
            try
            {
                downloaded = await DownloadAsync(source, interfaceIndex, timeout, cancellationToken);
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException or InvalidDataException
                || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
            {
                problems.Add($"{source.Url.Host}: {(ex is OperationCanceledException ? "не ответил вовремя" : ex.Message)}");
                continue;
            }

            using var intermediate = SelectIntermediate(leaf, downloaded, customRoots: null);
            if (intermediate is null)
            {
                problems.Add($"{source.Url.Host}: скачанный файл не дополняет цепочку сертификата сервера до доверенного корня");
                continue;
            }

            try
            {
                using var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                store.Add(intermediate);
            }
            catch (CryptographicException ex)
            {
                return new IntermediateInstallResult(false, "Не удалось добавить промежуточный сертификат в хранилище компьютера: " + ex.Message);
            }

            var subject = intermediate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            return new IntermediateInstallResult(true, $"Промежуточный сертификат «{subject}» скачан с {source.Url.Host}, проверен и добавлен в хранилище компьютера.", subject);
        }

        return new IntermediateInstallResult(false, problems.Count == 0
            ? "В сертификате сервера нет ссылки на издателя."
            : "Промежуточный сертификат не получен: " + string.Join("; ", problems));
    }

    /// <summary>
    /// Соединение идёт только на адреса, которые служба разрешила сама и открыла в защите для своего процесса:
    /// системный DNS и прокси здесь не участвуют. Перенаправления не выполняются - новый узел защита не пропустит.
    /// </summary>
    private static async Task<byte[]> DownloadAsync(IntermediateSource source, uint? interfaceIndex, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (source.Addresses.Count == 0)
        {
            throw new InvalidDataException("адрес узла не разрешился");
        }

        var port = source.Url.Port;
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = timeout,
            ConnectCallback = async (_, token) =>
            {
                Exception? last = null;
                foreach (var address in source.Addresses)
                {
                    // Защита пропускает службу к узлу издателя только через основной адаптер.
                    var socket = Dns.UnicastSocket.CreateTcp(interfaceIndex);
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(Ipv4.ToAddress(address), port), token);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (SocketException ex)
                    {
                        socket.Dispose();
                        last = ex;
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }

                throw last ?? new SocketException((int)SocketError.HostUnreachable);
            },
        };
        using var client = new HttpClient(handler) { Timeout = timeout, MaxResponseContentBufferSize = MaxDownloadBytes };
        using var response = await client.GetAsync(source.Url, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidDataException($"ответ HTTP {(int)response.StatusCode}");
        }

        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    /// <summary>
    /// Сертификат из скачанного файла (DER, PEM или набор PKCS#7), с которым цепочка листа строится до доверенного
    /// корня без загрузок из сети. Он должен быть центром сертификации и прямым издателем листа. <paramref name="customRoots"/> -
    /// корни вместо хранилища компьютера (для тестов).
    /// </summary>
    internal static X509Certificate2? SelectIntermediate(X509Certificate2 leaf, byte[] downloaded, X509Certificate2Collection? customRoots)
    {
        var candidates = Parse(downloaded);
        X509Certificate2? selected = null;
        foreach (var candidate in candidates)
        {
            if (selected is null && IsIssuerOf(candidate, leaf) && Completes(leaf, candidate, customRoots))
            {
                selected = candidate;
                continue;
            }

            candidate.Dispose();
        }

        return selected;
    }

    private static bool IsIssuerOf(X509Certificate2 candidate, X509Certificate2 leaf) =>
        candidate.SubjectName.RawData.AsSpan().SequenceEqual(leaf.IssuerName.RawData)
        && candidate.Extensions.OfType<X509BasicConstraintsExtension>().Any(b => b.CertificateAuthority);

    private static bool Completes(X509Certificate2 leaf, X509Certificate2 intermediate, X509Certificate2Collection? customRoots)
    {
        using var chain = new X509Chain(useMachineContext: true);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ExtraStore.Add(intermediate);
        if (customRoots is not null)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(customRoots);
        }

        // Лист подписан именно этим сертификатом: второе звено цепочки - он, а не одноимённый из хранилища.
        return chain.Build(leaf)
            && chain.ChainElements.Count >= 3
            && chain.ChainElements[1].Certificate.RawData.AsSpan().SequenceEqual(intermediate.RawData);
    }

    private static List<X509Certificate2> Parse(byte[] data)
    {
        try
        {
            return [X509CertificateLoader.LoadCertificate(data)];
        }
        catch (CryptographicException)
        {
            // Не одиночный сертификат: издатели часто отдают набор PKCS#7 (.p7c).
        }

        try
        {
            var collection = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057 // X509CertificateLoader не читает наборы PKCS#7, а сертификаты из них только сверяются.
            collection.Import(data);
#pragma warning restore SYSLIB0057
            return [.. collection];
        }
        catch (CryptographicException)
        {
            return [];
        }
    }
}
