using System.Globalization;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.NetworkManagement.Rras;
using static SplitVpn.Windows.Ras.RasConstants;

namespace SplitVpn.Windows.Ras;

public sealed record RasEntrySpec(string EntryName, string Server, uint? DnsServer = null)
{
    public VpnProtocol Protocol { get; init; } = VpnProtocol.Sstp;
    public AuthMethod AuthMethod { get; init; } = AuthMethod.MsChapV2;
    public IpsecAuthentication IpsecAuthentication { get; init; }
}

/// <summary>Запись VPN в собственном файле телефонной книги приложения.</summary>
public static unsafe class RasPhonebook
{
    /// <summary>Создаёт или перезаписывает запись. Пароли в телефонную книгу не пишутся.</summary>
    public static void Save(string phonebookPath, RasEntrySpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(phonebookPath))!);
        var entry = Build(spec);
        var code = PInvoke.RasSetEntryProperties(phonebookPath, spec.EntryName, entry, (uint)sizeof(RASENTRYW), default, 0);
        NativeCallException.ThrowIfFailed(code, "RasSetEntryProperties");
        if (spec.Protocol == VpnProtocol.Ikev2)
        {
            ApplyIkev2Policy(phonebookPath, spec.EntryName);
        }
    }

    // Политика IKEv2 по умолчанию в Windows (3DES/SHA1/DH2) отклоняется современными серверами (ошибка 628):
    // IKE и дочерняя SA — AES-256, SHA-256, группа DH 14; PFS выключен. Порядок слов — как в телефонной книге Windows.
    private const string Ikev2PolicyHex = "020000000400000003000000060000000300000000000000";

    /// <summary>
    /// В RASENTRY пользовательской политики IPsec нет, поэтому правим раздел записи в файле телефонной книги.
    /// Кодировку книги выбирает RAS (UTF-8, UTF-16 с BOM или ANSI-кодировка системы — на стенде не проверено):
    /// файл читается в его кодировке и пишется в ней же, с тем же BOM и теми же переводами строк, иначе раздел
    /// с кириллическим именем записи не находился бы, а перезапись меняла бы кодировку чужих записей.
    /// <paramref name="ansiCodePage"/> — кодовая страница ANSI (для тестов); по умолчанию системная.
    /// </summary>
    internal static void ApplyIkev2Policy(string phonebookPath, string entryName, int? ansiCodePage = null)
    {
        var bytes = File.ReadAllBytes(phonebookPath);
        var (text, encoding, preamble) = DecodePhonebook(bytes, entryName, ansiCodePage ?? (int)PInvoke.GetACP());
        var updated = WithIkev2Policy(text, entryName);
        WritePhonebook(phonebookPath, updated, encoding, preamble);
    }

    /// <summary>
    /// Текст книги, её кодировка и BOM. BOM UTF-8 или UTF-16 определяет кодировку сам. Без BOM — строгий UTF-8,
    /// а если байты им не являются или раздела записи в таком прочтении нет — ANSI-кодировка системы. Книга, которую
    /// не удалось прочесть ни так, ни так, не трогается: ошибка с понятным текстом.
    /// </summary>
    internal static (string Text, System.Text.Encoding Encoding, byte[] Preamble) DecodePhonebook(byte[] bytes, string entryName, int ansiCodePage)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        var strictUtf8 = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        var boms = new (byte[] Preamble, System.Text.Encoding Encoding)[]
        {
            ([0xEF, 0xBB, 0xBF], strictUtf8),
            ([0xFF, 0xFE], new System.Text.UnicodeEncoding(bigEndian: false, byteOrderMark: false, throwOnInvalidBytes: true)),
            ([0xFE, 0xFF], new System.Text.UnicodeEncoding(bigEndian: true, byteOrderMark: false, throwOnInvalidBytes: true)),
        };
        foreach (var (preamble, encoding) in boms)
        {
            if (bytes.AsSpan().StartsWith(preamble))
            {
                return (Decode(encoding, bytes.AsSpan(preamble.Length)) ?? throw Unreadable(), encoding, preamble);
            }
        }

        if (Decode(strictUtf8, bytes) is { } utf8 && FindSection(SplitLines(utf8), entryName) >= 0)
        {
            return (utf8, strictUtf8, []);
        }

        var ansi = AnsiEncoding(ansiCodePage);
        if (ansi is not null && Decode(ansi, bytes) is { } text)
        {
            return (text, ansi, []);
        }

        // Байты — UTF-8, но раздела нет и в ANSI: пусть WithIkev2Policy сообщит, что записи нет.
        return Decode(strictUtf8, bytes) is { } plain ? (plain, strictUtf8, []) : throw Unreadable();

        static InvalidOperationException Unreadable() =>
            new("Кодировка телефонной книги не распознана: политика IKEv2 не записана, книга не изменена.");
    }

    /// <summary>ANSI-кодировка со строгой проверкой байтов; null — кодовая страница недоступна или это UTF-8.</summary>
    private static System.Text.Encoding? AnsiEncoding(int codePage)
    {
        if (codePage is <= 0 or 65001)
        {
            return null;
        }

        try
        {
            return System.Text.CodePagesEncodingProvider.Instance.GetEncoding(codePage, System.Text.EncoderFallback.ExceptionFallback, System.Text.DecoderFallback.ExceptionFallback)
                ?? System.Text.Encoding.GetEncoding(codePage, System.Text.EncoderFallback.ExceptionFallback, System.Text.DecoderFallback.ExceptionFallback);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    private static string? Decode(System.Text.Encoding encoding, ReadOnlySpan<byte> bytes)
    {
        try
        {
            return encoding.GetString(bytes);
        }
        catch (System.Text.DecoderFallbackException)
        {
            return null;
        }
    }

    /// <summary>Запись книги через временный файл и замену: оборванная запись не оставляет книгу всех профилей усечённой.</summary>
    private static void WritePhonebook(string phonebookPath, string text, System.Text.Encoding encoding, byte[] preamble)
    {
        byte[] body;
        try
        {
            body = encoding.GetBytes(text);
        }
        catch (System.Text.EncoderFallbackException)
        {
            throw new InvalidOperationException("Политика IKEv2 не помещается в кодировку телефонной книги: книга не изменена.");
        }

        var temp = string.Create(CultureInfo.InvariantCulture, $"{phonebookPath}.{Environment.ProcessId}-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(preamble);
                stream.Write(body);
                stream.Flush(flushToDisk: true);
            }

            FileRetry.Run(() => File.Move(temp, phonebookPath, overwrite: true));
        }
        finally
        {
            try
            {
                File.Delete(temp);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Временный файл занят: книга уже записана или осталась прежней.
            }
        }
    }

    /// <summary>Строки текста вместе со своими переводами строк: при записи все строки, кроме изменённых, остаются побайтно.</summary>
    private static List<(string Line, string End)> SplitLines(string text)
    {
        var result = new List<(string, string)>();
        var position = 0;
        while (position < text.Length)
        {
            var newline = text.IndexOf('\n', position);
            if (newline < 0)
            {
                result.Add((text[position..], ""));
                break;
            }

            var end = newline > position && text[newline - 1] == '\r' ? newline - 1 : newline;
            result.Add((text[position..end], text[end..(newline + 1)]));
            position = newline + 1;
        }

        return result;
    }

    private static int FindSection(List<(string Line, string End)> lines, string entryName) =>
        lines.FindIndex(l => l.Line == "[" + entryName + "]");

    /// <summary>Текст телефонной книги с политикой IKEv2 в разделе записи; прочие строки и переводы строк не меняются.</summary>
    internal static string WithIkev2Policy(string text, string entryName)
    {
        ArgumentNullException.ThrowIfNull(text);
        var lines = SplitLines(text);
        var start = FindSection(lines, entryName);
        if (start < 0)
        {
            throw new InvalidOperationException("Запись IKEv2 не найдена в телефонной книге.");
        }

        var newline = lines.Select(l => l.End).FirstOrDefault(e => e.Length > 0) ?? Environment.NewLine;
        var end = lines.FindIndex(start + 1, l => l.Line.StartsWith('[')) is var next and >= 0 ? next : lines.Count;

        // Пустые строки в конце раздела отделяют его от следующего: новые ключи встают перед ними.
        while (end - 1 > start && lines[end - 1].Line.Length == 0)
        {
            end--;
        }

        var values = new (string Key, string Value)[]
        {
            ("DataEncryption", "256"), ("NumCustomPolicy", "1"), ("CustomIPSecPolicies", Ikev2PolicyHex),
        };
        foreach (var (key, value) in values)
        {
            var at = lines.FindIndex(start + 1, end - start - 1, l => l.Line.StartsWith(key + "=", StringComparison.Ordinal));
            if (at >= 0)
            {
                lines[at] = (key + "=" + value, lines[at].End);
                continue;
            }

            // Последняя строка файла могла быть без перевода строки: новая строка за ней пойдёт с новой строки.
            if (lines[end - 1].End.Length == 0)
            {
                lines[end - 1] = (lines[end - 1].Line, newline);
            }

            lines.Insert(end++, (key + "=" + value, newline));
        }

        return string.Concat(lines.Select(l => l.Line + l.End));
    }

    public static bool Exists(string? phonebookPath, string entryName) => TryRead(phonebookPath, entryName, out _) == ErrorSuccess;

    /// <summary>Адрес сервера записи (поле «Имя или адрес назначения»); null — запись не прочитана.</summary>
    public static string? TryReadServer(string? phonebookPath, string entryName) =>
        TryRead(phonebookPath, entryName, out var e) == ErrorSuccess
            ? e.szLocalPhoneNumber.AsReadOnlySpan().SliceAtNull().ToString()
            : null;

    /// <summary>Имена всех записей своей телефонной книги: по ним чистятся записи удалённых профилей.</summary>
    public static IReadOnlyList<string> EnumerateEntryNames(string phonebookPath)
    {
        if (!File.Exists(phonebookPath))
        {
            return [];
        }

        var count = 8;
        while (true)
        {
            var buffer = new RASENTRYNAMEW[count];
            buffer[0].dwSize = (uint)sizeof(RASENTRYNAMEW);
            var size = (uint)(sizeof(RASENTRYNAMEW) * count);
            var code = PInvoke.RasEnumEntries(null, phonebookPath, ref buffer[0], ref size, out var returned);
            if (code == ErrorBufferTooSmall)
            {
                count = (int)(size / sizeof(RASENTRYNAMEW)) + 1;
                continue;
            }

            NativeCallException.ThrowIfFailed(code, "RasEnumEntries");
            return buffer.Take((int)returned).Select(e => e.szEntryName.AsReadOnlySpan().SliceAtNull().ToString()).ToList();
        }
    }

    public static void Delete(string phonebookPath, string entryName)
    {
        var code = PInvoke.RasDeleteEntry(phonebookPath, entryName);
        if (code is not ErrorSuccess and not ErrorCannotFindPhonebookEntry)
        {
            throw new NativeCallException("RasDeleteEntry", code);
        }
    }

    /// <summary>Сводка ключевых полей записи — для сравнения своей записи с рабочим профилем пользователя.</summary>
    public static IReadOnlyDictionary<string, string> Describe(string? phonebookPath, string entryName)
    {
        var code = TryRead(phonebookPath, entryName, out var e);
        NativeCallException.ThrowIfFailed(code, "RasGetEntryProperties");
        return new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["dwType"] = Hex(e.dwType),
            ["dwfOptions"] = Hex(e.dwfOptions),
            ["dwfOptions2"] = Hex(e.dwfOptions2),
            ["dwfOptions3"] = Hex(e.dwfOptions3),
            ["dwVpnStrategy"] = Hex(e.dwVpnStrategy),
            ["dwEncryptionType"] = Hex(e.dwEncryptionType),
            ["dwfNetProtocols"] = Hex(e.dwfNetProtocols),
            ["dwFramingProtocol"] = Hex(e.dwFramingProtocol),
            ["dwCustomAuthKey"] = Hex(e.dwCustomAuthKey),
            ["dwRedialCount"] = Hex(e.dwRedialCount),
            ["dwIdleDisconnectSeconds"] = Hex(e.dwIdleDisconnectSeconds),
            ["dwIPv4InterfaceMetric"] = Hex(e.dwIPv4InterfaceMetric),
            ["szDeviceType"] = e.szDeviceType.AsReadOnlySpan().SliceAtNull().ToString(),
            ["szDeviceName"] = e.szDeviceName.AsReadOnlySpan().SliceAtNull().ToString(),
            ["szLocalPhoneNumber"] = e.szLocalPhoneNumber.AsReadOnlySpan().SliceAtNull().ToString(),
            ["ipaddrDns"] = string.Create(CultureInfo.InvariantCulture, $"{e.ipaddrDns.a}.{e.ipaddrDns.b}.{e.ipaddrDns.c}.{e.ipaddrDns.d}"),
        };
    }

    internal static RASENTRYW Build(RasEntrySpec spec)
    {
        if (!VpnProtocols.Supports(spec.Protocol, spec.AuthMethod) || !VpnProtocols.TryParseServer(spec.Server, spec.Protocol, out var server))
        {
            throw new InvalidOperationException("Недопустимые параметры VPN-записи.");
        }

        var entry = new RASENTRYW
        {
            dwSize = (uint)sizeof(RASENTRYW),
            dwType = RasetVpn,
            dwVpnStrategy = spec.Protocol switch { VpnProtocol.Sstp => VsSstpOnly, VpnProtocol.L2tpIpsec => 3, VpnProtocol.Ikev2 => 7, _ => 1 },
            // У SSTP с PAP или CHAP шифрования PPP (MPPE) нет, его даёт TLS: «требовать» нельзя. У L2TP тот же
            // параметр задаёт шифрование IPsec, и «без шифрования» означало бы ESP без шифрования: требуется всегда.
            dwEncryptionType = spec.AuthMethod is AuthMethod.Pap or AuthMethod.Chap && spec.Protocol != VpnProtocol.L2tpIpsec ? 0u : EtRequire,
            dwFramingProtocol = RasfpPpp,
            dwfNetProtocols = RasnpIp,
            dwIdleDisconnectSeconds = RasidsDisabled,
            dwRedialCount = 0,
            dwfOptions = AuthenticationOptions(spec.AuthMethod),
            dwCustomAuthKey = VpnProtocols.IsEap(spec.AuthMethod) ? EapConfiguration.TypeId(spec.AuthMethod) : 0,
            dwfOptions2 = Raseo2DontUseRasCredentials
                | Raseo2DisableClassBasedStaticRoute
                | Raseo2DontNegotiateMultilink
                | Raseo2DisableNbtOverIp
                | Raseo2SecureFileAndPrint
                | Raseo2SecureClientForMsNet,
        };

        if (spec.Protocol == VpnProtocol.L2tpIpsec && spec.IpsecAuthentication == IpsecAuthentication.PreSharedKey)
        {
            entry.dwfOptions2 |= PInvoke.RASEO2_UsePreSharedKey;
        }

        if (spec.AuthMethod == AuthMethod.MachineCertificate)
        {
            entry.dwfOptions2 |= PInvoke.RASEO2_RequireMachineCertificates;
        }

        // Маршрут по умолчанию через VPN RAS не ставит: маршрутами управляет служба.
        Copy(server.ForPhonebook, entry.szLocalPhoneNumber.AsSpan());
        Copy(DeviceTypeVpn, entry.szDeviceType.AsSpan());
        Copy(spec.Protocol switch
        {
            VpnProtocol.Sstp => DeviceNameSstp, VpnProtocol.L2tpIpsec => "WAN Miniport (L2TP)",
            VpnProtocol.Ikev2 => "WAN Miniport (IKEv2)", _ => "WAN Miniport (PPTP)",
        }, entry.szDeviceName.AsSpan());
        if (spec.DnsServer is { } dns)
        {
            entry.dwfOptions |= RaseoSpecificNameServers;
            entry.ipaddrDns = new RASIPADDR { a = (byte)(dns >> 24), b = (byte)(dns >> 16), c = (byte)(dns >> 8), d = (byte)dns };
        }

        return entry;
    }

    private static uint AuthenticationOptions(AuthMethod method) => method switch
    {
        // PAP/CHAP не вырабатывают MPPE-ключи; шифрование обеспечивается SSTP TLS или обязательным IPsec.
        AuthMethod.Pap => PInvoke.RASEO_RequirePAP,
        AuthMethod.Chap => PInvoke.RASEO_RequireCHAP,
        AuthMethod.MachineCertificate => RaseoRequireDataEncryption,
        AuthMethod.MsChapV2 => RaseoRequireDataEncryption | RaseoRequireMsChap2,
        _ => RaseoRequireDataEncryption | PInvoke.RASEO_RequireEAP,
    };

    public static void SetPreSharedKey(string phonebook, string entryName, ReadOnlySpan<char> key)
    {
        var credentials = new RASCREDENTIALSW { dwSize = (uint)sizeof(RASCREDENTIALSW), dwMask = PInvoke.RASCM_PreSharedKey };
        try
        {
            if (key.Length > 256 || key.Contains('\0')) { throw new InvalidOperationException("Недопустимый ключ IPsec."); }
            key.CopyTo(credentials.szPassword.AsSpan());
            NativeCallException.ThrowIfFailed(PInvoke.RasSetCredentials(phonebook, entryName, credentials, key.IsEmpty), "RasSetCredentials PSK");
        }
        finally { credentials.szPassword.AsSpan().Clear(); }
    }

    public static void SetEapConfiguration(string phonebook, string entryName, byte[] config)
    {
        fixed (byte* data = config)
        fixed (char* book = phonebook)
        fixed (char* name = entryName)
        {
            NativeCallException.ThrowIfFailed(PInvoke.RasSetCustomAuthData(book, name, data, (uint)config.Length), "RasSetCustomAuthData");
        }
    }

    /// <summary>RAS: телефонная книга не открывается.</summary>
    private const uint ErrorCannotOpenPhonebook = 615;

    /// <summary>
    /// Путь книги можно передать RAS: пустой (книга по умолчанию) или полный локальный на несъёмном диске. Путь
    /// чужой книги приходит из RasEnumConnections, то есть от пользователя: \\server\share\x.pbk служба (SYSTEM)
    /// открыла бы с учётной записью компьютера, отдав её NTLM-аутентификацию чужому узлу.
    /// </summary>
    internal static bool IsAcceptablePhonebook(string? phonebookPath, Func<string, DriveType>? driveType = null) =>
        string.IsNullOrEmpty(phonebookPath)
        || (driveType is null ? Security.LocalPath.IsLocalFixed(phonebookPath) : Security.LocalPath.IsLocalFixed(phonebookPath, driveType));

    private static uint TryRead(string? phonebookPath, string entryName, out RASENTRYW entry)
    {
        entry = new RASENTRYW { dwSize = (uint)sizeof(RASENTRYW) };
        if (!IsAcceptablePhonebook(phonebookPath))
        {
            return ErrorCannotOpenPhonebook;
        }

        // RasGetEntryProperties читает книгу в этом процессе (SYSTEM): ссылка в пути на сетевой ресурс увела бы туда
        // учётную запись компьютера. Путь без ссылок закрепляется на время чтения.
        using var pin = string.IsNullOrEmpty(phonebookPath) ? null : PinPhonebook(phonebookPath);
        if (!string.IsNullOrEmpty(phonebookPath) && pin is null)
        {
            return ErrorCannotOpenPhonebook;
        }

        var size = (uint)sizeof(RASENTRYW);
        uint deviceInfoSize = 0;
        var code = PInvoke.RasGetEntryProperties(phonebookPath, entryName, ref entry, ref size, default, ref deviceInfoSize);
        while (code == 603 && size > sizeof(RASENTRYW) && size <= 16 * 1024 * 1024)
        {
            var bytes = new byte[size];
            fixed (byte* memory = bytes)
            {
                var data = (RASENTRYW*)memory;
                data->dwSize = (uint)sizeof(RASENTRYW);
                code = PInvoke.RasGetEntryProperties(phonebookPath, entryName, ref *data, ref size, default, ref deviceInfoSize);
                if (code == 0) { entry = *data; }
                if (size <= bytes.Length) { break; }
            }
        }

        return code;
    }

    /// <summary>
    /// Закрепляет путь книги без точек повторного анализа, включая сам файл; null - в пути ссылка или путь не открылся.
    /// Файла ещё нет - закрепляются только каталоги, и об отсутствии книги, как прежде, отвечает RAS.
    /// </summary>
    internal static Security.ReparseFreePath? PinPhonebook(string phonebookPath)
    {
        try
        {
            try
            {
                return Security.ReparseFreePath.Pin(phonebookPath, includeFile: true);
            }
            catch (FileNotFoundException)
            {
                return Security.ReparseFreePath.Pin(phonebookPath, includeFile: false);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static void Copy(string value, Span<char> target)
    {
        if (value.Length >= target.Length)
        {
            throw new ArgumentException("Значение не помещается в поле RAS.", nameof(value));
        }

        target.Clear();
        value.AsSpan().CopyTo(target);
    }

    private static string Hex(uint value) => string.Create(CultureInfo.InvariantCulture, $"0x{value:X8}");
}
