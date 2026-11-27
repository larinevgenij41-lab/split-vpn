using System.Text.RegularExpressions;
using SplitVpn.Core.Ipc;

namespace SplitVpn.Core.Update;

/// <summary>
/// Проверка команды установки обновления, присланной службой, перед запуском с повышением прав. Общая для интерфейса
/// и командной строки: оба запускают её через «runas», и второй рубеж после проверки подлинности службы при подключении
/// к каналу должен быть одинаковым.
/// </summary>
public static class UpdateInstallCommand
{
    /// <summary>
    /// Аргументы msiexec для установки пакета с журналом. Служба строит команду только так: формат живёт рядом с
    /// проверкой (<see cref="Arguments"/>), и правка одного без другого ломает тесты, а не установку обновлений у всех.
    /// </summary>
    public static string BuildArguments(string package, string log)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(log);
        return $"/i \"{package}\" /passive /norestart REBOOT=ReallySuppress /L*v \"{log}\"";
    }

    /// <summary>
    /// Командная строка, которую собирает служба (<see cref="BuildArguments"/>): пакет и журнал установки в кавычках,
    /// остальные ключи постоянные. Любое отличие — отказ.
    /// </summary>
    private static readonly Regex Arguments = new(
        "^/i \"(?<package>[^\"]+)\" /passive /norestart REBOOT=ReallySuppress /L\\*v \"(?<log>[^\"]+)\"$",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, TimeSpan.FromSeconds(1));

    /// <summary>Имя пакета и журнала: как в проверке манифеста — только латиница, цифры, точка, дефис и подчёркивание.</summary>
    private static readonly Regex SafeName = new("^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>Каталог обновлений службы: каталог её данных в ProgramData (<c>ServicePaths.Update</c>).</summary>
    public static string UpdateDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitVpn", "update");

    /// <summary>Каталог Windows (%SystemRoot%).</summary>
    public static string SystemRoot => Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    /// <summary>Проверка для этой машины: %SystemRoot% и каталог обновлений службы.</summary>
    public static string? Problem(UpdateInstallDto install) => Problem(install, SystemRoot, UpdateDirectory);

    /// <summary>
    /// С повышением прав запускается только %SystemRoot%\System32\msiexec.exe и только для пакета из каталога
    /// обновлений службы. null — команда годится, иначе — причина отказа для пользователя.
    /// </summary>
    public static string? Problem(UpdateInstallDto install, string systemRoot, string updateDirectory)
    {
        ArgumentNullException.ThrowIfNull(install);
        const string Refused = "Команда установки обновления отклонена: ";
        var msiexec = Path.GetFullPath(Path.Combine(systemRoot, "System32", "msiexec.exe"));
        if (install.FileName is not { Length: > 0 } file || !Path.IsPathFullyQualified(file)
            || !string.Equals(Path.GetFullPath(file), msiexec, StringComparison.OrdinalIgnoreCase))
        {
            return Refused + "запускать можно только установщик Windows " + msiexec + ".";
        }

        var match = install.Arguments is { } arguments ? Arguments.Match(arguments) : Match.Empty;
        if (!match.Success)
        {
            return Refused + "неожиданные параметры установщика.";
        }

        if (!InDirectory(match.Groups["package"].Value, updateDirectory, ".msi"))
        {
            return Refused + "пакет обновления не из каталога обновлений службы.";
        }

        return InDirectory(match.Groups["log"].Value, updateDirectory, ".log")
            ? null
            : Refused + "журнал установки не в каталоге обновлений службы.";
    }

    /// <summary>Полный путь прямо в каталоге (без вложенных папок, «..» и префиксов \\?\) с безопасным именем и расширением.</summary>
    private static bool InDirectory(string path, string directory, string extension)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return false;
        }

        var full = Path.GetFullPath(path);
        var name = Path.GetFileName(full);
        return string.Equals(full, path, StringComparison.OrdinalIgnoreCase)
            && string.Equals(Path.GetDirectoryName(full), Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)), StringComparison.OrdinalIgnoreCase)
            && SafeName.IsMatch(name)
            && name.EndsWith(extension, StringComparison.OrdinalIgnoreCase);
    }
}
