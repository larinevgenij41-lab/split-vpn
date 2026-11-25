using System.IO;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Ipc;

namespace SplitVpn.App.ViewModels;

/// <summary>
/// Файл ручного импорта RU-базы. Список уходит службе одним сообщением канала управления, поэтому предел файла -
/// меньший из предела импорта и предела сообщения: больший файл служба не получит, и без проверки ошибка выглядела бы
/// как недоступность службы.
/// </summary>
internal static class GeoImportFile
{
    public static long MaxBytes { get; } = Math.Min(GeoValidationOptions.MaxImportBytes, FrameCodec.MaxFrameBytes);

    public static string TooLarge { get; } = $"Файл слишком большой для списка сетей: служба принимает файл не больше {MaxBytes / (1024 * 1024)} МБ.";

    /// <summary>Запрос импорта из файла; слишком большой файл - <see cref="FormatException"/> с понятным текстом.</summary>
    public static async Task<GeoImportRequest> ReadAsync(string path)
    {
        string text;
        try
        {
            if (new FileInfo(path).Length > MaxBytes)
            {
                throw new FormatException(TooLarge);
            }

            text = await File.ReadAllTextAsync(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Сообщение .NET английское: пользователю — имя файла и что с ним, исходное — в журнал.
            throw new UserFacingException(UiText.FileError(ex, path), ex);
        }

        var request = new GeoImportRequest(text);
        return FrameCodec.Fits(request)
            ? request
            : throw new FormatException(TooLarge + " При передаче переводы строк занимают вдвое больше места, чем в файле: уберите из файла комментарии и пустые строки.");
    }
}
