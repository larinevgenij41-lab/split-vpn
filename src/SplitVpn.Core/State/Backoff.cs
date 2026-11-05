namespace SplitVpn.Core.State;

/// <summary>Экспоненциальная задержка повторов с небольшим случайным разбросом (PLAN §8).</summary>
public static class Backoff
{
    public const double Jitter = 0.2;

    public static TimeSpan Delay(int attempt, TimeSpan maxDelay, Random random)
    {
        ArgumentNullException.ThrowIfNull(random);
        var baseSeconds = Math.Min(Math.Pow(2, Math.Clamp(attempt, 0, 30)), maxDelay.TotalSeconds);
        var factor = 1 + ((random.NextDouble() * 2) - 1) * Jitter;
        return TimeSpan.FromSeconds(Math.Max(0.5, baseSeconds * factor));
    }
}
