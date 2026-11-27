using System.ComponentModel;
using System.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Update;

namespace SplitVpn.App.Services;

/// <summary>
/// Запуск установщика обновления с правами администратора. Команду собирает служба: она проверила
/// подпись выпуска и контрольную сумму файла и отдала путь к нему. Интерфейс показывает согласие в
/// окне контроля учётных записей, запускает msiexec и закрывается, освобождая свои файлы для замены.
/// </summary>
public static class UpdateLauncher
{
    /// <summary>ERROR_CANCELLED: пользователь отказался в окне контроля учётных записей.</summary>
    private const int Cancelled = 1223;

    /// <summary>
    /// Сколько держать открытым описатель запущенного msiexec. Пока он открыт, Windows не отдаёт номер процесса
    /// другой программе, даже если установщик уже завершился (например, сразу с кодом 1618): служба, получив
    /// номер, не примет чужой процесс за установщик. Интерфейс закрывается через пару секунд после запуска,
    /// и описатель тогда закрывается вместе с ним; срок - запас на случай, если интерфейс остался открыт.
    /// </summary>
    private static readonly TimeSpan KeepHandle = TimeSpan.FromMinutes(1);

    /// <summary>Последний запущенный установщик: держит его описатель до сообщения службе (см. <see cref="KeepHandle"/>).</summary>
    private static Process? _installer;

    /// <summary>
    /// Второй рубеж после проверки подлинности службы при подключении к каналу: с повышением прав запускается только
    /// %SystemRoot%\System32\msiexec.exe и только для пакета из каталога обновлений службы. null — команда годится,
    /// иначе — причина отказа для пользователя. Та же проверка — у командной строки (<see cref="UpdateInstallCommand"/>).
    /// </summary>
    internal static string? CommandProblem(UpdateInstallDto install, string systemRoot, string updateDirectory) =>
        UpdateInstallCommand.Problem(install, systemRoot, updateDirectory);

    /// <summary>Номер процесса установщика для службы; ноль — запуск не состоялся, текст — для пользователя.</summary>
    public static (int ProcessId, string? Error) Start(UpdateInstallDto install)
    {
        ArgumentNullException.ThrowIfNull(install);
        if (UpdateInstallCommand.Problem(install) is { } problem)
        {
            SplitVpn.Core.Diagnostics.Verbose.Write("Update", "установщик не запущен: " + problem + " (" + install.FileName + " " + install.Arguments + ")");
            return (0, problem);
        }

        try
        {
            var process = Process.Start(new ProcessStartInfo(install.FileName, install.Arguments)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Environment.SystemDirectory,
            });
            if (process is null)
            {
                return (0, "Установщик обновления не запустился.");
            }

            var processId = process.Id;
            Interlocked.Exchange(ref _installer, process)?.Dispose();
            _ = Task.Delay(KeepHandle).ContinueWith(_ => Release(process), CancellationToken.None,
                TaskContinuationOptions.None, TaskScheduler.Default);
            return (processId, null);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == Cancelled)
        {
            return (0, "Установка отменена: для обновления нужны права администратора.");
        }
        catch (Win32Exception ex)
        {
            SplitVpn.Core.Diagnostics.Verbose.Write("Update", "установщик не запущен: " + ex.Message);
            return (0, $"Установщик обновления не запустился (код {ex.NativeErrorCode}). Повторите установку позже.");
        }
    }

    /// <summary>Закрывает описатель установщика, если его не сменил более поздний запуск.</summary>
    private static void Release(Process process)
    {
        if (ReferenceEquals(Interlocked.CompareExchange(ref _installer, null, process), process))
        {
            process.Dispose();
        }
    }
}
