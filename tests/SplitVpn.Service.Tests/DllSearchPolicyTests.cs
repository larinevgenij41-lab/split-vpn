using System.Reflection;
using System.Runtime.InteropServices;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// src/SplitVpn.Windows/Native/DllSearchPolicy.cs: системные библиотеки объявлений сборки SplitVpn.Windows ищутся только
/// в System32 - подложенная в каталог программы DLL не загрузится в службу LocalSystem. Исключение - wintun.dll,
/// которая поставляется рядом с программой.
/// </summary>
public sealed class DllSearchPolicyTests
{
    private static readonly Assembly WindowsAssembly = typeof(DnsProxyServer).Assembly;

    [Fact]
    public void WindowsAssembly_SearchesSystem32Only()
    {
        var attribute = WindowsAssembly.GetCustomAttribute<DefaultDllImportSearchPathsAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal(DllImportSearchPath.System32, attribute.Paths);
    }

    /// <summary>
    /// Каждое объявление P/Invoke сборки (и сгенерированное LibraryImport, и обёртки CsWin32) в итоге ищет библиотеку в
    /// System32: своё значение на методе или типе не ослабляет политику сборки. wintun.dll - только из каталога программы.
    /// </summary>
    [Fact]
    public void EveryPInvoke_ResolvesToSystem32_ExceptWintun()
    {
        var assemblyPaths = WindowsAssembly.GetCustomAttribute<DefaultDllImportSearchPathsAttribute>()?.Paths;
        var checkedImports = 0;
        foreach (var type in WindowsAssembly.GetTypes())
        {
            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                if (method.GetCustomAttribute<DllImportAttribute>() is not { } import)
                {
                    continue;
                }

                checkedImports++;
                var effective = method.GetCustomAttribute<DefaultDllImportSearchPathsAttribute>()?.Paths
                    ?? type.GetCustomAttribute<DefaultDllImportSearchPathsAttribute>()?.Paths
                    ?? assemblyPaths;
                var library = Path.GetFileName(import.Value);
                var expected = string.Equals(library, "wintun.dll", StringComparison.OrdinalIgnoreCase)
                    ? DllImportSearchPath.ApplicationDirectory
                    : DllImportSearchPath.System32;
                Assert.True(effective == expected, $"{type.FullName}.{method.Name} ({library}): поиск {effective}, ожидается {expected}");
            }
        }

        Assert.True(checkedImports > 20, $"найдено объявлений P/Invoke: {checkedImports}");
    }
}
