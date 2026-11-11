using System.ComponentModel;
using System.Diagnostics;
using SplitVpn.Core.Ipc;

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

    /// <summary>Номер процесса установщика для службы; ноль — запуск не состоялся, текст — для пользователя.</summary>
    public static (int ProcessId, string? Error) Start(UpdateInstallDto install)
    {
        ArgumentNullException.ThrowIfNull(install);
        try
        {
            using var process = Process.Start(new ProcessStartInfo(install.FileName, install.Arguments)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Environment.SystemDirectory,
            });
            return process is null ? (0, "Установщик обновления не запустился.") : (process.Id, null);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == Cancelled)
        {
            return (0, "Установка отменена: для обновления нужны права администратора.");
        }
        catch (Win32Exception ex)
        {
            return (0, "Установщик обновления не запустился: " + ex.Message);
        }
    }
}
