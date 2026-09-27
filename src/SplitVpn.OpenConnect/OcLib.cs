using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;

namespace SplitVpn.OpenConnect;

/// <summary>
/// Узкая обёртка над libopenconnect, которую использует <see cref="OcSession"/>. Реализация —
/// <see cref="NativeOcLib"/>; в тестах — сценарный фейк без нативных библиотек.
/// Коды возврата — как у библиотеки: 0 успех, отрицательные — -errno.
/// </summary>
internal interface IOcLib : IDisposable
{
    string Version { get; }

    /// <summary>Создаёт экземпляр библиотеки с колбэками. Вызывается один раз до остальных методов.</summary>
    void Create(IOcCallbacks callbacks, string userAgent, bool verbose);

    int ParseUrl(string url);

    int SetClientCertificate(string certificateUrl, string keyUrl);

    int ObtainCookie();

    int MakeCstpConnection();

    int SetupDtls();

    int DisableDtls();

    int SetupTunDevice(string interfaceName);

    SessionInfo ReadSession();

    bool DtlsActive { get; }

    void SetupCommandPipe();

    int Mainloop();

    /// <summary>Отправить команду OC_CMD_* в mainloop (потокобезопасно).</summary>
    void SendCommand(byte command);

    int WebviewLoadChanged(string uri, IReadOnlyList<SsoCookie> cookies);
}

/// <summary>Колбэки libopenconnect, приведённые к управляемым типам. Вызываются из потока библиотеки.</summary>
internal interface IOcCallbacks
{
    /// <summary>Сертификат шлюза не прошёл системную проверку: 0 — принять, иначе отклонить.</summary>
    int ValidatePeerCertificate(string reason);

    int ProcessForm(OcForm form);

    void Log(int level, string message);

    int OpenWebview(string uri);

    /// <summary>Адрес узла для подключения; null — не разрешился.</summary>
    string? Resolve(string host);

    void Reconnected();

    void Stats(ulong bytesSent, ulong bytesReceived);
}

internal static class OcCodes
{
    public const int PrgErr = 0, PrgInfo = 1, PrgDebug = 2;
    public const int FormErr = -1, FormOk = 0, FormCancelled = 1, FormNewGroup = 2;

    // errno MinGW (UCRT).
    public const int Eperm = 1, Eintr = 4, Einval = 22, Eagain = 11, Epipe = 32, Ecanceled = 105, Econnaborted = 106, Etimedout = 138;
}

internal enum OcFieldKind
{
    Text,
    Password,
    Select,
    Hidden,
    SsoToken,
    Other,
}

/// <summary>Поле формы шлюза. Значение ставится через <see cref="Set"/> — память поля принадлежит библиотеке.</summary>
internal sealed class OcField(string name, string label, OcFieldKind kind, bool ignored, IReadOnlyList<AuthChoiceDto> choices, Action<string> set)
{
    public string Name { get; } = name;

    public string Label { get; } = label;

    public OcFieldKind Kind { get; } = kind;

    public bool Ignored { get; } = ignored;

    public IReadOnlyList<AuthChoiceDto> Choices { get; } = choices;

    public void Set(string value) => set(value);
}

internal sealed record OcForm
{
    public string? AuthId { get; init; }

    public string? Banner { get; init; }

    public string? Message { get; init; }

    public string? Error { get; init; }

    public IReadOnlyList<OcField> Fields { get; init; } = [];

    /// <summary>Поле выбора группы (authgroup), если оно есть; входит и в <see cref="Fields"/>.</summary>
    public OcField? Group { get; init; }

    public int GroupSelection { get; init; }
}
