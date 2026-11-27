using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using SplitVpn.Core.Settings;

namespace SplitVpn.Cli.Proto;

internal sealed record ScenarioCheck(string Name, bool Passed, string Details);

/// <summary>
/// Отчёт сценария: замеры, проверки и ошибки. Персональные данные маскируются при записи.
/// Каждая запись шага — точка прерывания: после Ctrl+C она бросает OperationCanceledException, сценарий
/// попадает в свой catch и finally, и очистка (маршруты, DNS, RAS) выполняется. С <see cref="BeginCleanup"/>
/// записи больше не прерываются, чтобы очистка дошла до конца.
/// </summary>
internal sealed class ScenarioReport
{
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private bool _cleanup;

    public ScenarioReport(string scenario)
    {
        Scenario = scenario;
        CliCancellation.Cooperate();
    }

    public string Scenario { get; }

    public string Account { get; } = WindowsIdentity.GetCurrent().Name;

    public DateTimeOffset StartedUtc { get; } = DateTimeOffset.UtcNow;

    public Dictionary<string, object?> Measurements { get; } = [];

    public List<ScenarioCheck> Checks { get; } = [];

    public List<string> Errors { get; } = [];

    public List<string> Log { get; } = [];

    public bool Passed => Errors.Count == 0 && Checks.All(c => c.Passed);

    public void Note(string text)
    {
        Write(text);
        if (!_cleanup)
        {
            CliCancellation.ThrowIfInterrupted();
        }
    }

    /// <summary>Начало очистки (блок finally): дальнейшие записи не прерываются по Ctrl+C.</summary>
    public void BeginCleanup()
    {
        _cleanup = true;
        if (CliCancellation.IsInterrupted)
        {
            Write("Прервано пользователем — выполняется очистка.");
        }
    }

    private void Write(string text)
    {
        var line = $"[{_clock.Elapsed:mm\\:ss\\.f}] {text}";
        Log.Add(line);
        Console.WriteLine(line);
    }

    public void Measure(string name, object? value)
    {
        Measurements[name] = value;
        Note($"{name} = {JsonSerializer.Serialize(value, JsonDefaults.Compact)}");
    }

    public bool Check(string name, bool passed, string details)
    {
        Checks.Add(new ScenarioCheck(name, passed, details));
        Note($"{(passed ? "ОК  " : "СБОЙ")} {name}: {details}");
        return passed;
    }

    public void Fail(string text, Exception? ex = null)
    {
        var message = ex is null ? text : $"{text}: {ex.GetType().Name}: {ex.Message}";
        Errors.Add(message);
        // Без точки прерывания: Fail вызывается из catch сценария, и запись ошибки не должна бросать снова.
        Write("ОШИБКА " + message);
    }

    public async Task<int> SaveAsync(CliArgs args, IEnumerable<string?> secrets)
    {
        var directory = ProtoContext.ReportDirectory(args);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"{StartedUtc:yyyyMMdd-HHmmss}-{Scenario}.json");
        var json = JsonSerializer.Serialize(new
        {
            Scenario,
            Account,
            StartedUtc,
            Duration = _clock.Elapsed,
            Passed,
            Checks,
            Errors,
            Measurements,
            Log,
        }, JsonDefaults.Options);
        json = Mask(json, secrets);
        await File.WriteAllTextAsync(path, json);
        Console.WriteLine();
        Console.WriteLine($"Итог {Scenario}: {(Passed ? "ПРОЙДЕН" : "НЕ ПРОЙДЕН")}; проверок {Checks.Count}, сбоев {Checks.Count(c => !c.Passed)}, ошибок {Errors.Count}");
        Console.WriteLine("Отчёт: " + path);
        return Passed ? 0 : 1;
    }

    /// <summary>
    /// Скрывает значения в готовом JSON отчёта. IP-адреса нужны для разбора маршрутов, поэтому скрываются только
    /// имя пользователя и имя сервера. Ищется форма значения так, как её записал сериализатор (тем же кодировщиком):
    /// «corp\ivan» в JSON лежит как «corp\\ivan», и простая замена исходной строки его бы пропустила.
    /// </summary>
    internal static string Mask(string json, IEnumerable<string?> secrets)
    {
        foreach (var secret in secrets.Where(s => !string.IsNullOrWhiteSpace(s)).OrderByDescending(s => s!.Length))
        {
            var encoded = JsonSerializer.Serialize(secret, JsonDefaults.Options)[1..^1];
            json = json.Replace(encoded, "<скрыто>", StringComparison.OrdinalIgnoreCase);
        }

        return json;
    }
}
