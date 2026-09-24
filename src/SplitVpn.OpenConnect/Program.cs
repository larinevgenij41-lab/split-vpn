using System.IO.Pipes;
using SplitVpn.OpenConnect.Native;

namespace SplitVpn.OpenConnect;

/// <summary>
/// Помощник протокола AnyConnect. Запускается службой: «--pipes &lt;вход&gt; &lt;выход&gt;» — дескрипторы
/// анонимных труб, унаследованные от службы. «--version» — проверка поставки нативных библиотек.
/// </summary>
internal static class Program
{
    private static unsafe int Main(string[] args)
    {
        if (args is ["--version"])
        {
            try
            {
                OcNative.HardenPkcs11();
                if (OcNative.InitSsl() != 0)
                {
                    Console.Error.WriteLine("openconnect_init_ssl: ошибка");
                    return 2;
                }

                Console.WriteLine($"libopenconnect {OcNative.Utf8(OcNative.GetVersion())}; ocshim {OcNative.ShimVersion()}");
                return 0;
            }
            catch (DllNotFoundException ex)
            {
                Console.Error.WriteLine("Нативные библиотеки не найдены: " + ex.Message);
                return 3;
            }
        }

        if (args.Length >= 3 && args[0] == "--pipes")
        {
            var verbose = args.Contains("--verbose", StringComparer.Ordinal);
            using var input = new AnonymousPipeClientStream(PipeDirection.In, args[1]);
            using var output = new AnonymousPipeClientStream(PipeDirection.Out, args[2]);
            HelperHost? host = null;
            host = new HelperHost(input, output, () => new OcSession(new NativeOcLib(), host!, new WindowsHelperSystem()) { Verbose = verbose });
            return host.Run();
        }

        Console.Error.WriteLine("Помощник запускается службой «Раздельный VPN». Проверка поставки: --version");
        return 1;
    }
}
