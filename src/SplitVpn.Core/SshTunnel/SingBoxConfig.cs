using System.Buffers;
using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.SshTunnel;

/// <summary>Параметры одного запуска движка «VPN поверх SSH».</summary>
public sealed record SingBoxParameters
{
    public required string InterfaceName { get; init; }

    /// <summary>Адрес сервера SSH: всегда IP, имя разрешает служба. Один адрес - тот же, что в фильтрах защиты.</summary>
    public required uint Server { get; init; }

    public required ushort Port { get; init; }

    public required string User { get; init; }

    public required SshHostKey HostKey { get; init; }

    public uint TunAddress { get; init; } = SshTunnelDefaults.TunAddress;

    public int Mtu { get; init; } = SshTunnelDefaults.Mtu;

    /// <summary>
    /// Серверы DNS за туннелем. Служба обращается к ним по служебным адресам туннеля
    /// (<see cref="SshTunnelDefaults.DnsAddress"/>), движок подменяет служебный адрес настоящим. Так запрос идёт
    /// в туннель, даже когда настоящий адрес сервера DNS правилами маршрутизации направлен в другое место.
    /// </summary>
    public IReadOnlyList<uint> DnsServers { get; init; } = [];

    /// <summary>
    /// Подробный вывод движка: включается вместе с подробным журналом службы. В нём есть адреса назначения
    /// соединений, поэтому в обычном режиме движок пишет только предупреждения и ошибки.
    /// </summary>
    public bool VerboseLog { get; init; }
}

public static class SshTunnelDefaults
{
    /// <summary>
    /// Адрес адаптера туннеля. Конец 198.18.0.0/15 (диапазон для стендов): начало этого диапазона другие
    /// программы занимают под подставные адреса DNS.
    /// </summary>
    public static readonly uint TunAddress = Ipv4.Parse("198.19.255.1");

    public const int Mtu = 9000;

    /// <summary>Сколько серверов DNS получает служебные адреса туннеля.</summary>
    public const int MaxDnsServers = 4;

    /// <summary>
    /// Служебный адрес сервера DNS с этим номером: соседи адреса адаптера. За пределами компьютера они не
    /// существуют, маршрут на них служба ставит только в адаптер туннеля.
    /// </summary>
    public static uint DnsAddress(int index) => TunAddress + 1 + (uint)index;

    public const string InterfacePrefix = "SplitVpn SSH ";

    /// <summary>Имя адаптера постоянно для профиля, как у AnyConnect.</summary>
    public static string InterfaceName(Guid profileId) => InterfacePrefix + profileId.ToString("N")[..8];
}

/// <summary>
/// Настройки движка для одного туннеля. Движок только переносит TCP из своего адаптера в соединение SSH:
/// маршруты, DNS и защита остаются у службы (auto_route выключен), прямого выхода в настройках нет вовсе,
/// поэтому мимо SSH движок ничего отправить не может. Локальных слушателей нет.
/// </summary>
public static class SingBoxConfig
{
    private static readonly JsonWriterOptions s_options = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>
    /// Пишет настройки в UTF-8 в готовый массив и возвращает их длину. Ключ попадает только в этот массив:
    /// промежуточных строк нет, вызывающий затирает массив после передачи движку.
    /// </summary>
    public static int Write(byte[] destination, SingBoxParameters parameters, ReadOnlySpan<char> privateKey)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(parameters);
        var buffer = new FixedBuffer(destination);
        using (var json = new Utf8JsonWriter(buffer, s_options))
        {
            json.WriteStartObject();

            // Уровень warn всегда: на info движок пишет адрес каждого соединения, то есть историю посещений.
            json.WriteStartObject("log");
            json.WriteString("level", parameters.VerboseLog ? "debug" : "warn");
            json.WriteBoolean("timestamp", false);
            json.WriteEndObject();

            json.WriteStartArray("inbounds");
            json.WriteStartObject();
            json.WriteString("type", "tun");
            json.WriteString("tag", "tun-in");
            json.WriteString("interface_name", parameters.InterfaceName);
            json.WriteStartArray("address");
            json.WriteStringValue(Ipv4.Format(parameters.TunAddress) + "/32");
            json.WriteEndArray();
            json.WriteNumber("mtu", parameters.Mtu);
            json.WriteBoolean("auto_route", false);
            json.WriteString("stack", "gvisor");
            json.WriteEndObject();
            json.WriteEndArray();

            json.WriteStartArray("outbounds");
            json.WriteStartObject();
            json.WriteString("type", "ssh");
            json.WriteString("tag", "ssh");
            json.WriteString("server", Ipv4.Format(parameters.Server));
            json.WriteNumber("server_port", parameters.Port);
            json.WriteString("user", parameters.User);
            json.WriteString("private_key", privateKey);
            json.WriteStartArray("host_key");
            json.WriteStringValue(parameters.HostKey.Text);
            json.WriteEndArray();
            json.WriteStartArray("host_key_algorithms");
            foreach (var algorithm in parameters.HostKey.Algorithms)
            {
                json.WriteStringValue(algorithm);
            }

            json.WriteEndArray();
            json.WriteEndObject();
            json.WriteEndArray();

            // UDP через SSH не передаётся: отказ сразу, без перехода в молчаливое отбрасывание (no_drop),
            // чтобы программы не ждали ответа.
            json.WriteStartObject("route");
            json.WriteStartArray("rules");
            for (var i = 0; i < Math.Min(parameters.DnsServers.Count, SshTunnelDefaults.MaxDnsServers); i++)
            {
                // Служебный адрес DNS подменяется настоящим; правило не конечное, дальше соединение идёт в SSH.
                json.WriteStartObject();
                json.WriteStartArray("ip_cidr");
                json.WriteStringValue(Ipv4.Format(SshTunnelDefaults.DnsAddress(i)) + "/32");
                json.WriteEndArray();
                json.WriteString("action", "route-options");
                json.WriteString("override_address", Ipv4.Format(parameters.DnsServers[i]));
                json.WriteEndObject();
            }

            json.WriteStartObject();
            json.WriteString("network", "udp");
            json.WriteString("action", "reject");
            json.WriteBoolean("no_drop", true);
            json.WriteEndObject();
            json.WriteEndArray();
            json.WriteString("final", "ssh");
            json.WriteEndObject();

            json.WriteEndObject();
        }

        return buffer.Written;
    }

    /// <summary>Размер массива с запасом под экранирование ключа.</summary>
    public static int BufferSize(int privateKeyChars) => checked(privateKeyChars * 6 + 4096);

    /// <summary>Запись в один заранее выделенный массив: растущий буфер оставлял бы в памяти копии ключа.</summary>
    private sealed class FixedBuffer(byte[] buffer) : IBufferWriter<byte>
    {
        public int Written { get; private set; }

        public void Advance(int count) => Written = checked(Written + count);

        public Memory<byte> GetMemory(int sizeHint = 0) => Rest(sizeHint);

        public Span<byte> GetSpan(int sizeHint = 0) => Rest(sizeHint).Span;

        private Memory<byte> Rest(int sizeHint)
        {
            var rest = buffer.AsMemory(Written);
            return rest.Length >= Math.Max(sizeHint, 1)
                ? rest
                : throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture, $"Настройки движка не помещаются в {buffer.Length} байт."));
        }
    }
}
