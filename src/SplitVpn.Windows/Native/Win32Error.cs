using System.ComponentModel;
using System.Globalization;
using Windows.Win32;
using static SplitVpn.Windows.Ras.RasConstants;

namespace SplitVpn.Windows.Native;

/// <summary>Исключение с системным кодом ошибки Win32/WFP/RAS.</summary>
public sealed class NativeCallException : Exception
{
    public NativeCallException(string operation, uint code)
        : base(string.Create(CultureInfo.InvariantCulture, $"{operation}: код 0x{code:X8} ({Describe(code)})"))
    {
        Operation = operation;
        Code = code;
    }

    public string Operation { get; }

    public uint Code { get; }

    /// <summary>
    /// Текст ошибки по коду. Коды RAS (600…950) пересекаются с системными, и FormatMessage выдаёт для них
    /// чужие строки: для 668 — «Произошла ошибка подтверждения» вместо «Подключение разорвано». Такие коды
    /// расшифровывает сам RAS, и только если он отказался — берётся системный текст.
    /// </summary>
    public static string Describe(uint code)
    {
        return code switch
        {
            0x80320009 => "FWP_E_ALREADY_EXISTS",
            0x80320008 => "FWP_E_NOT_FOUND",
            0x8032000D => "FWP_E_NO_TXN_IN_PROGRESS",
            0x80320017 => "FWP_E_TXN_IN_PROGRESS",
            >= RasErrorFirst and <= RasErrorLast => RasText(code) ?? SystemText(code),
            _ => SystemText(code),
        };
    }

    private static string SystemText(uint code) => new Win32Exception(unchecked((int)code)).Message;

    private static string? RasText(uint code)
    {
        Span<char> buffer = stackalloc char[512];
        return PInvoke.RasGetErrorString(code, buffer) == 0 ? buffer.SliceAtNull().ToString() : null;
    }

    public static void ThrowIfFailed(uint code, string operation)
    {
        if (code != 0)
        {
            throw new NativeCallException(operation, code);
        }
    }
}
