using System.Security.Cryptography;
using System.Text;
using SplitVpn.Core.Update;

namespace SplitVpn.Cli;

/// <summary>
/// Ключ выпуска и подпись манифеста обновлений. Команды только для разработки: утилита в поставку
/// не входит. Проверка идёт тем же кодом, что и в службе, поэтому форматы разойтись не могут.
/// </summary>
internal static class ReleaseCommands
{
    private const string PasswordVariable = "SPLITVPN_SIGNING_KEY_PASSWORD";

    /// <summary>release-keygen --out &lt;файл&gt; [--kid &lt;идентификатор&gt;]</summary>
    public static Task<int> KeygenAsync(CliArgs args)
    {
        var path = args.Option("--out");
        if (path is null)
        {
            Console.WriteLine("release-keygen --out <файл ключа> [--kid <идентификатор>]");
            return Task.FromResult(2);
        }

        if (File.Exists(path))
        {
            Console.Error.WriteLine($"Файл {path} уже существует: перезаписывать ключ выпуска нельзя.");
            return Task.FromResult(1);
        }

        var password = Supplied(args) ?? ReadPassword("Пароль для ключа выпуска: ", confirm: true);
        if (password.Length == 0)
        {
            Console.Error.WriteLine("Пустой пароль не принимается: ключ выпуска хранится зашифрованным.");
            return Task.FromResult(1);
        }

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000);
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(path, ecdsa.ExportEncryptedPkcs8PrivateKeyPem(password, pbe));
        var kid = args.Option("--kid") ?? "sv-" + DateTime.UtcNow.ToString("yyyy-MM", System.Globalization.CultureInfo.InvariantCulture);
        Console.WriteLine("Закрытый ключ: " + Path.GetFullPath(path));
        Console.WriteLine("Сохраните его копию вне этого компьютера: без ключа новые выпуски не примет ни одна установленная копия.");
        Console.WriteLine();
        Console.WriteLine("Впишите в src\\SplitVpn.Core\\Update\\UpdateTrust.cs:");
        Console.WriteLine($"        [\"{kid}\"] = \"{Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo())}\",");
        return Task.FromResult(0);
    }

    /// <summary>release-sign --manifest &lt;update.json&gt; --key &lt;файл&gt; [--out &lt;update.json.sig&gt;]</summary>
    public static Task<int> SignAsync(CliArgs args)
    {
        var manifestPath = args.Option("--manifest");
        var keyPath = args.Option("--key");
        if (manifestPath is null || keyPath is null)
        {
            Console.WriteLine("release-sign --manifest <update.json> --key <файл ключа> [--out <update.json.sig>]");
            return Task.FromResult(2);
        }

        var manifest = File.ReadAllBytes(manifestPath);
        var parsed = UpdateManifestParser.Parse(manifest);
        if (parsed.Release is null)
        {
            Console.Error.WriteLine("Манифест не проходит проверку: " + parsed.Error);
            return Task.FromResult(1);
        }

        var password = Supplied(args) ?? ReadPassword("Пароль ключа выпуска: ", confirm: false);
        using var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromEncryptedPem(File.ReadAllText(keyPath), password);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            Console.Error.WriteLine("Ключ выпуска не прочитан: " + ex.Message);
            return Task.FromResult(1);
        }

        // Формат подписи задан явно: служба проверяет ровно IEEE P1363, а не DER-последовательность.
        var signature = ecdsa.SignData(manifest, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var outPath = args.Option("--out") ?? manifestPath + ManifestDownloader.SignatureSuffix;
        File.WriteAllText(outPath, Convert.ToBase64String(signature));
        Console.WriteLine($"Подписан выпуск {parsed.Release.VersionText}: {Path.GetFullPath(outPath)}");
        return Task.FromResult(0);
    }

    /// <summary>release-verify --manifest &lt;файл&gt; --signature &lt;файл&gt; [--package &lt;msi&gt;]</summary>
    public static async Task<int> VerifyAsync(CliArgs args)
    {
        var manifestPath = args.Option("--manifest");
        var signaturePath = args.Option("--signature");
        if (manifestPath is null || signaturePath is null)
        {
            Console.WriteLine("release-verify --manifest <update.json> --signature <update.json.sig> [--package <msi>]");
            return 2;
        }

        var manifest = File.ReadAllBytes(manifestPath);
        var signature = Convert.FromBase64String(File.ReadAllText(signaturePath).Trim());
        if (EcdsaManifestVerifier.Default.Verify(manifest, signature, UpdateManifestParser.ReadKeyId(manifest)) is { } problem)
        {
            Console.Error.WriteLine("Подпись не принята службой: " + problem);
            return 1;
        }

        var parsed = UpdateManifestParser.Parse(manifest);
        if (parsed.Release is not { } release)
        {
            Console.Error.WriteLine("Манифест не проходит проверку: " + parsed.Error);
            return 1;
        }

        Console.WriteLine($"Подпись верна: версия {release.VersionText}, тег {release.Manifest.Tag}");
        if (args.Option("--package") is not { } package)
        {
            return 0;
        }

        var info = new FileInfo(package);
        if (!info.Exists)
        {
            Console.Error.WriteLine("Установщик не найден: " + package);
            return 1;
        }

        if (info.Length != release.Manifest.Package.Size)
        {
            Console.Error.WriteLine($"Размер установщика {info.Length} не совпал с манифестом {release.Manifest.Package.Size}.");
            return 1;
        }

        await using var stream = info.OpenRead();
        var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, CancellationToken.None));
        if (!string.Equals(hash, release.Manifest.Package.Sha256, StringComparison.Ordinal))
        {
            Console.Error.WriteLine("SHA-256 установщика не совпал с манифестом.");
            return 1;
        }

        Console.WriteLine($"Установщик сходится: {info.Name}, {info.Length} байт, SHA-256 {hash}");
        return 0;
    }

    /// <summary>
    /// Пароль из файла (--password-file) или из переменной окружения: нужен для выпуска из скрипта,
    /// где консольного ввода нет. Пароль в командной строке не принимается — он остался бы в истории.
    /// </summary>
    private static string? Supplied(CliArgs args)
    {
        if (args.Option("--password-file") is { } file && File.Exists(file))
        {
            return File.ReadAllText(file).Trim();
        }

        var variable = Environment.GetEnvironmentVariable(PasswordVariable);
        return string.IsNullOrEmpty(variable) ? null : variable;
    }

    /// <summary>Ввод пароля без эха; повторный ввод — при создании ключа.</summary>
    private static string ReadPassword(string prompt, bool confirm)
    {
        var first = Prompt(prompt);
        if (!confirm)
        {
            return first;
        }

        var second = Prompt("Повторите пароль: ");
        if (!string.Equals(first, second, StringComparison.Ordinal))
        {
            Console.Error.WriteLine("Пароли не совпали.");
            return "";
        }

        return first;
    }

    private static string Prompt(string prompt)
    {
        Console.Write(prompt);
        var builder = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return builder.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (builder.Length > 0)
                {
                    builder.Length--;
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                builder.Append(key.KeyChar);
            }
        }
    }
}
