using SplitVpn.Windows.Ras;
using SplitVpn.Windows.Security;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Аудит 24.11.2026: служба (SYSTEM) открывала пути из данных пользователя - телефонную книгу из
/// RasEnumConnections и AppData из HKU. Сетевой путь отдал бы чужому узлу NTLM-аутентификацию компьютера.
/// </summary>
public sealed class LocalPathTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-localpath-tests", Guid.NewGuid().ToString("N"));

    public LocalPathTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        // Рекурсивное удаление корня спотыкается о junction (отказ в доступе): ссылки убираются по одной.
        foreach (var link in Directory.EnumerateDirectories(_root, "*", SearchOption.TopDirectoryOnly)
            .Where(d => File.GetAttributes(d).HasFlag(FileAttributes.ReparsePoint)).ToList())
        {
            Directory.Delete(link);
        }

        Directory.Delete(_root, recursive: true);
    }

    /// <summary>Шов типа диска: вызов означал бы обращение к системе, для этих путей его быть не должно.</summary>
    private static DriveType NoAccess(string root) => throw new InvalidOperationException("обращение к диску " + root);

    [Theory]
    [InlineData(@"\\attacker\share\x.pbk")]
    [InlineData(@"//attacker/share/x.pbk")]
    [InlineData(@"\\?\UNC\attacker\share\x.pbk")]
    [InlineData(@"\\?\GLOBALROOT\Device\Mup\attacker\share\x.pbk")]
    [InlineData(@"\\.\pipe\x")]
    [InlineData(@"\\?\C:\Users\u\rasphone.pbk")]
    [InlineData(@"\??\UNC\attacker\share\x.pbk")]
    [InlineData(@"rasphone.pbk")]
    [InlineData(@"..\rasphone.pbk")]
    [InlineData(@"C:rasphone.pbk")]
    [InlineData(@"\Users\u\rasphone.pbk")]
    [InlineData("C:\\x\0\\y")]
    [InlineData("")]
    [InlineData(null)]
    public void NonLocalPaths_AreRejectedWithoutTouchingFileSystem(string? path)
    {
        Assert.False(LocalPath.IsLocalFixed(path, NoAccess));
        if (!string.IsNullOrEmpty(path))
        {
            Assert.False(RasPhonebook.IsAcceptablePhonebook(path, NoAccess));
        }
    }

    [Theory]
    [InlineData(@"\\attacker\share\x.pbk")]
    [InlineData(@"\\?\UNC\attacker\share\x.pbk")]
    public void RasPhonebook_RejectsUncPhonebook(string path)
    {
        Assert.False(RasPhonebook.IsAcceptablePhonebook(path, NoAccess));
    }

    [Fact]
    public void RasPhonebook_AcceptsDefaultPhonebook()
    {
        Assert.True(RasPhonebook.IsAcceptablePhonebook(null, NoAccess));
        Assert.True(RasPhonebook.IsAcceptablePhonebook("", NoAccess));
    }

    [Theory]
    [InlineData(DriveType.Fixed, true)]
    [InlineData(DriveType.Network, false)]
    [InlineData(DriveType.Removable, false)]
    [InlineData(DriveType.CDRom, false)]
    [InlineData(DriveType.NoRootDirectory, false)]
    public void DriveLetterPath_DependsOnDriveType(DriveType type, bool expected)
    {
        string? asked = null;
        Assert.Equal(expected, LocalPath.IsLocalFixed(@"z:\Users\u\AppData\Roaming\x.pbk", root => { asked = root; return type; }));
        Assert.Equal(@"Z:\", asked);
    }

    [Fact]
    public void SystemDrivePath_IsLocalFixed()
    {
        Assert.True(LocalPath.IsLocalFixed(Environment.SystemDirectory));
    }

    [Theory]
    [InlineData(@"\\?\UNC\attacker\share\profile\x.pbk", @"C:\profile", false)]
    [InlineData(@"\\attacker\share\profile\x.pbk", @"C:\profile", false)]
    [InlineData(@"\\?\Volume{00000000-0000-0000-0000-000000000000}\profile\x.pbk", @"C:\profile", false)]
    [InlineData(@"\\?\C:\other\x.pbk", @"C:\profile", false)]
    [InlineData(@"\\?\C:\profile\x.pbk", @"C:\profile", true)]
    public void FinalPath_MustBeLocalAndInsideRoot(string final, string root, bool expected)
    {
        Assert.Equal(expected, ConfinedFile.IsFinalPathConfined(final, root));
    }

    /// <summary>
    /// Решает тег точки повторного анализа: сжатые WOF и дедуплицированные файлы читаются (после обычного открытия),
    /// ссылки, облачные заглушки и незнакомые теги отвергаются.
    /// </summary>
    [Theory]
    [InlineData(0x20u, 0u, "Plain")] // FILE_ATTRIBUTE_ARCHIVE
    [InlineData(0x80u, 0u, "Plain")] // FILE_ATTRIBUTE_NORMAL
    [InlineData(0x10u, 0u, "Reject")] // FILE_ATTRIBUTE_DIRECTORY
    [InlineData(0x410u, 0x80000017u, "Reject")] // каталог с тегом WOF - всё равно каталог
    [InlineData(0x420u, 0x80000017u, "Transparent")] // IO_REPARSE_TAG_WOF
    [InlineData(0x400u, 0x80000013u, "Transparent")] // IO_REPARSE_TAG_DEDUP
    [InlineData(0x400u, 0xA000000Cu, "Reject")] // IO_REPARSE_TAG_SYMLINK
    [InlineData(0x400u, 0xA0000003u, "Reject")] // IO_REPARSE_TAG_MOUNT_POINT
    [InlineData(0x400u, 0x9000001Au, "Reject")] // IO_REPARSE_TAG_CLOUD
    [InlineData(0x400u, 0x9000601Au, "Reject")] // IO_REPARSE_TAG_CLOUD_6
    [InlineData(0x400u, 0x8000001Bu, "Reject")] // IO_REPARSE_TAG_APPEXECLINK
    [InlineData(0x400u, 0x12345678u, "Reject")] // незнакомый тег
    [InlineData(0x400u, 0u, "Reject")]
    public void ReparseTag_DecidesWhetherFileIsRead(uint attributes, uint tag, string expected)
    {
        Assert.Equal(expected, ConfinedFile.Classify(attributes, tag).ToString());
    }

    /// <summary>
    /// Ошибки открытия - исключения ввода-вывода и доступа, которые ловят обнаружение конфликтов и сбор диагностики,
    /// а не COMException.
    /// </summary>
    [Theory]
    [InlineData(2, typeof(FileNotFoundException))]
    [InlineData(3, typeof(DirectoryNotFoundException))]
    [InlineData(5, typeof(UnauthorizedAccessException))]
    [InlineData(32, typeof(IOException))] // ERROR_SHARING_VIOLATION
    [InlineData(1920, typeof(IOException))] // ERROR_CANT_ACCESS_FILE
    [InlineData(4390, typeof(IOException))] // ERROR_NOT_A_REPARSE_POINT
    public void OpenError_IsIoOrAccessException(int error, Type expected)
    {
        var exception = ConfinedFile.OpenError(error);

        Assert.IsType(expected, exception);
        if (expected == typeof(IOException))
        {
            Assert.Equal(unchecked((int)0x80070000 | error), exception.HResult);
        }
    }

    /// <summary>
    /// Файл, сжатый WOF (compact /exe), несёт атрибут точки повторного анализа, но это обычный файл: он читается, и
    /// читаются его данные, а не заглушка.
    /// </summary>
    [Fact]
    public void ConfinedFile_ReadsWofCompressedFile()
    {
        var file = Path.Combine(_root, "compressed.txt");
        var text = string.Concat(Enumerable.Repeat("строка журнала для сжатия WOF\r\n", 2000));
        File.WriteAllText(file, text);
        var start = new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "compact.exe"), $"/c /exe:xpress4k \"{file}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            WorkingDirectory = Environment.SystemDirectory,
        };
        using (var compact = System.Diagnostics.Process.Start(start)!)
        {
            compact.StandardOutput.ReadToEnd();
            if (!compact.WaitForExit(30_000))
            {
                // Процесс запущен этим тестом: его и останавливаем, иначе ExitCode бросил бы InvalidOperationException.
                compact.Kill();
                Assert.Skip("compact.exe не завершился за 30 с");
                return;
            }

            if (compact.ExitCode != 0)
            {
                Assert.Skip("Том не поддерживает сжатие WOF");
                return;
            }
        }

        // При подключённом wof.sys атрибут точки повторного анализа обычно скрыт, без него (или у дедупликации) - виден;
        // в обоих случаях читаться должны данные файла.
        using var stream = ConfinedFile.OpenRead(file, _root);
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream);
        Assert.Equal(text, reader.ReadToEnd());
    }

    [Fact]
    public void ConfinedFile_MissingFile_ThrowsFileNotFound()
    {
        Assert.Throws<FileNotFoundException>(() => ConfinedFile.OpenRead(Path.Combine(_root, "нет-файла.txt"), _root));
    }

    [Fact]
    public void ConfinedFile_RejectsUncPath()
    {
        Assert.Null(ConfinedFile.OpenRead(@"\\?\UNC\localhost\c$\Windows\win.ini", _root));
        Assert.Null(ConfinedFile.OpenRead(Path.Combine(_root, "x.txt"), @"\\localhost\c$"));
    }

    /// <summary>Junction создаётся без особых прав (в отличие от символической ссылки): им и проверяется проход пути.</summary>
    private static string CreateJunctionOrSkip(string link, string target)
    {
        var start = new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"), $"/c mklink /J \"{link}\" \"{target}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var mklink = System.Diagnostics.Process.Start(start)!;
        mklink.StandardOutput.ReadToEnd();
        mklink.StandardError.ReadToEnd();
        if (!mklink.WaitForExit(30_000))
        {
            mklink.Kill();
            Assert.Skip("mklink не завершился за 30 с");
        }

        Assert.SkipUnless(mklink.ExitCode == 0 && Directory.Exists(link), "Не удалось создать junction на этом томе");
        return link;
    }

    [Fact]
    public void ReparseFreePath_PinsOrdinaryPath()
    {
        var file = Path.Combine(_root, "dir", "file.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, "x");

        using (var pin = ReparseFreePath.Pin(file, includeFile: true))
        {
            Assert.NotNull(pin);
            // Пока путь закреплён, каталог нельзя переименовать и подставить вместо него ссылку.
            Assert.ThrowsAny<IOException>(() => Directory.Move(Path.Combine(_root, "dir"), Path.Combine(_root, "moved")));
        }

        Directory.Move(Path.Combine(_root, "dir"), Path.Combine(_root, "moved"));
        Assert.Throws<DirectoryNotFoundException>(() => ReparseFreePath.Pin(Path.Combine(_root, "нет", "file.txt"), includeFile: true));
        Assert.Throws<FileNotFoundException>(() => ReparseFreePath.Pin(Path.Combine(_root, "moved", "нет.txt"), includeFile: true));
        Assert.Null(ReparseFreePath.Pin(@"\\localhost\c$\Windows\win.ini", includeFile: true));
    }

    /// <summary>
    /// Аудит, итерация 10: путь, локальный на вид, мог вести на сетевой ресурс через ссылку каталога в середине, и
    /// открытие от имени SYSTEM отдало бы туда NTLM-аутентификацию компьютера. Точка повторного анализа в любом
    /// каталоге пути отвергается до открытия файла - даже если настоящий путь остаётся внутри корня.
    /// </summary>
    [Fact]
    public void ReparsePointInMiddleOfPath_IsRejectedBeforeOpening()
    {
        var real = Path.Combine(_root, "real");
        Directory.CreateDirectory(real);
        File.WriteAllText(Path.Combine(real, "rasphone.pbk"), "[Запись]\r\n");
        var junction = CreateJunctionOrSkip(Path.Combine(_root, "junction"), real);
        var viaJunction = Path.Combine(junction, "rasphone.pbk");

        Assert.Null(ReparseFreePath.Pin(viaJunction, includeFile: true));
        Assert.Null(ReparseFreePath.Pin(viaJunction, includeFile: false));
        Assert.Null(ReparseFreePath.Pin(Path.Combine(junction, "нет-такого.pbk"), includeFile: false));
        // Прежде настоящий путь (внутри корня) проходил сверку, и файл читался через junction.
        Assert.Null(ConfinedFile.OpenRead(viaJunction, _root));
        Assert.Null(RasPhonebook.PinPhonebook(viaJunction));

        using (var direct = ConfinedFile.OpenRead(Path.Combine(real, "rasphone.pbk"), _root))
        {
            Assert.NotNull(direct);
        }

        using var pinned = RasPhonebook.PinPhonebook(Path.Combine(real, "rasphone.pbk"));
        Assert.NotNull(pinned);
        // Книги ещё нет: закрепляются каталоги, об отсутствии отвечает RAS, как прежде.
        using var missing = RasPhonebook.PinPhonebook(Path.Combine(real, "new.pbk"));
        Assert.NotNull(missing);
    }

    /// <summary>Символическая ссылка каталога (так её направили бы на \\attacker\share) отвергается так же.</summary>
    [Fact]
    public void DirectorySymlinkInPath_IsRejected()
    {
        var real = Path.Combine(_root, "real");
        Directory.CreateDirectory(real);
        File.WriteAllText(Path.Combine(real, "file.txt"), "x");
        var link = Path.Combine(_root, "link");
        try
        {
            Directory.CreateSymbolicLink(link, real);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Assert.Skip("Нет права создавать символические ссылки: " + ex.Message);
        }

        Assert.Null(ReparseFreePath.Pin(Path.Combine(link, "file.txt"), includeFile: true));
        Assert.Null(ConfinedFile.OpenRead(Path.Combine(link, "file.txt"), _root));
    }

    /// <summary>Symlink на последнем компоненте не разыменовывается даже внутри корня: файл-ссылка отвергается.</summary>
    [Fact]
    public void ConfinedFile_RejectsSymlinkOnLastComponent()
    {
        var target = Path.Combine(_root, "target.txt");
        File.WriteAllText(target, "внутри корня");
        var link = Path.Combine(_root, "link.txt");
        try
        {
            File.CreateSymbolicLink(link, target);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Без права SeCreateSymbolicLinkPrivilege и режима разработчика ссылку не создать: проверку
            // атрибута покрывает LinkOrDirectoryAttributes_AreRejected.
            Assert.Skip("Нет права создавать символические ссылки: " + ex.Message);
            return;
        }

        using (var direct = ConfinedFile.OpenRead(target, _root))
        {
            Assert.NotNull(direct);
        }

        using var viaLink = ConfinedFile.OpenRead(link, _root);
        Assert.Null(viaLink);
    }
}
