using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using SplitVpn.Core.Settings;

namespace SplitVpn.Cli.Proto;

internal sealed record ScenarioCheck(string Name, bool Passed, string Details);

/// <summary>Отчёт сценария: замеры, проверки и ошибки. Персональные данные маскируются при записи.</summary>
internal sealed class ScenarioReport(string scenario)
{
    private readonly Stopwatch _clock = Stopwatch.StartNew();

    public string Scenario { get; } = scenario;

    public string Account { get; } = WindowsIdentity.GetCurrent().Name;

    public DateTimeOffset StartedUtc { get; } = DateTimeOffset.UtcNow;

    public Dictionary<string, object?> Measurements { get; } = [];

    public List<ScenarioCheck> Checks { get; } = [];

    public List<string> Errors { get; } = [];

    public List<string> Log { get; } = [];

    public bool Passed => Errors.Count == 0 && Checks.All(c => c.Passed);

    public void Note(string text)
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
        Note("ОШИБКА " + message);
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
        // IP-адреса нужны для разбора маршрутов, поэтому скрываются только имя пользователя и имя сервера.
        foreach (var secret in secrets.Where(s => !string.IsNullOrWhiteSpace(s)))
        {
            json = json.Replace(secret!, "<скрыто>", StringComparison.OrdinalIgnoreCase);
        }

        await File.WriteAllTextAsync(path, json);
        Console.WriteLine();
        Console.WriteLine($"Итог {Scenario}: {(Passed ? "ПРОЙДЕН" : "НЕ ПРОЙДЕН")}; проверок {Checks.Count}, сбоев {Checks.Count(c => !c.Passed)}, ошибок {Errors.Count}");
        Console.WriteLine("Отчёт: " + path);
        return Passed ? 0 : 1;
    }
}
