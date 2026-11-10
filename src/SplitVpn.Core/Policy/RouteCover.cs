using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

/// <summary>Маршрут покрытия: подсеть и номер цели (0 — «остальное», путь по умолчанию).</summary>
public readonly record struct CoverRoute(Ipv4Cidr Cidr, int Target);

/// <summary>Свойства цели покрытия.</summary>
/// <param name="Emittable">Маршрут к цели можно поставить. Цель 0 — путь по умолчанию: маршрут-исключение к ней
/// возможен, только если у неё есть интерфейс (туннель пары /1).</param>
/// <param name="OnLink">Маршрут без шлюза (туннель). На такой маршрут шире /31 Windows сам ставит маршрут /32 на
/// последний адрес подсети в тот же интерфейс, и он перекрывает любые более узкие исключения.</param>
/// <param name="HoldsDefault">Маршрут цели может накрывать адреса цели 0 с исключениями к ней. Нельзя для другого
/// туннеля, когда цель 0 — туннель: при его обрыве исключения снимаются, и его адреса ушли бы в чужой туннель,
/// который защита пропускает. Прямой маршрут можно: адреса, ушедшие напрямую, защита блокирует.</param>
public readonly record struct CoverTarget(bool Emittable, bool OnLink = false, bool HoldsDefault = true);

/// <summary>
/// Наименьший набор маршрутов, который отправляет каждый адрес туда же, что и точное CIDR-покрытие каждой цели.
/// Windows выбирает самый длинный подходящий префикс, поэтому широкую подсеть можно отдать одной цели, а
/// немногие адреса внутри неё вернуть более узкими маршрутами-исключениями. Например, при «остальном
/// интернете через VPN» тысячи российских сетей покрываются меньшим числом прямых маршрутов с исключениями
/// в туннель. Решение для каждого адреса не меняется: меняется только запись таблицы маршрутов.
/// Алгоритм — динамика по дереву префиксов (как ORTC): для каждой подсети и унаследованной цели считается
/// наименьшее число маршрутов внутри неё.
/// </summary>
public static class RouteCover
{
    /// <summary>Маршрут не шире /8: короче только пара /1 туннеля «остального интернета».</summary>
    public const int MinPrefix = 8;

    /// <summary>Самый длинный префикс, на который Windows ещё ставит маршрут последнего адреса (у /31 и /32 его нет).</summary>
    public const int MaxBroadcastPrefix = 30;

    private const int Infinity = 1 << 28;

    /// <summary>Цели без особенностей: маршруты через шлюз, вложения не ограничены.</summary>
    public static List<CoverRoute> Build(IReadOnlyList<(RangeSet Ranges, int Target)> layers, IReadOnlyList<bool> emittable, RangeSet avoid)
    {
        ArgumentNullException.ThrowIfNull(emittable);
        return Build(layers, emittable.Select(e => new CoverTarget(e)).ToList(), avoid);
    }

    /// <param name="layers">Адреса каждой цели (1..targetCount-1); наборы не пересекаются. Остальное — цель 0.</param>
    /// <param name="targets">Свойства каждой цели, по номеру.</param>
    /// <param name="avoid">Адреса, которые маршруты не должны задевать (локальные сети): они остаются на системных маршрутах.</param>
    public static List<CoverRoute> Build(IReadOnlyList<(RangeSet Ranges, int Target)> layers, IReadOnlyList<CoverTarget> targets, RangeSet avoid)
    {
        ArgumentNullException.ThrowIfNull(layers);
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentNullException.ThrowIfNull(avoid);
        var builder = new Builder(Segments(layers), targets, avoid.ToArray());
        var root = builder.Solve(0, 0);
        var result = new List<CoverRoute>();
        if (builder.Cost(root, 0, 0, 0) >= Infinity)
        {
            throw new InvalidOperationException("Покрытие маршрутами невозможно: цель без интерфейса внутри чужой подсети.");
        }

        builder.Emit(root, 0, 0, 0, result);
        return result;
    }

    /// <summary>Всё адресное пространство отрезками одной цели, соседние отрезки одной цели слиты.</summary>
    private static (uint Start, uint End, int Target)[] Segments(IReadOnlyList<(RangeSet Ranges, int Target)> layers)
    {
        var painted = layers.SelectMany(l => l.Ranges.Select(r => (r.Start, r.End, l.Target))).OrderBy(s => s.Start).ToList();
        var segments = new List<(uint Start, uint End, int Target)>();
        ulong next = 0;
        foreach (var (start, end, target) in painted)
        {
            if (start < next)
            {
                throw new ArgumentException("Наборы целей пересекаются.", nameof(layers));
            }

            if (start > next)
            {
                Append(segments, (uint)next, start - 1, 0);
            }

            Append(segments, start, end, target);
            next = (ulong)end + 1;
        }

        if (next <= uint.MaxValue)
        {
            Append(segments, (uint)next, uint.MaxValue, 0);
        }

        return [.. segments];
    }

    private static void Append(List<(uint Start, uint End, int Target)> segments, uint start, uint end, int target)
    {
        if (segments.Count > 0 && segments[^1].Target == target && segments[^1].End + 1 == start)
        {
            segments[^1] = (segments[^1].Start, end, target);
        }
        else
        {
            segments.Add((start, end, target));
        }
    }

    private sealed class Builder((uint Start, uint End, int Target)[] segments, IReadOnlyList<CoverTarget> targets, Ipv4Range[] avoid)
    {
        private readonly int _targets = targets.Count;

        // Узлы с несколькими целями: дети и стоимости для каждой унаследованной цели. Однородные узлы не хранятся.
        private readonly List<int> _left = [];
        private readonly List<int> _right = [];
        private readonly List<int> _costs = [];

        /// <summary>Номер узла (≥ 0) или -1 - цель однородного узла (≤ -1, цель = -(n+1)).</summary>
        public int Solve(uint network, int length)
        {
            var last = Last(network, length);
            var index = SegmentAt(network);
            if (segments[index].End >= last)
            {
                return -(segments[index].Target + 1);
            }

            var half = 1u << (31 - length);
            var left = Solve(network, length + 1);
            var right = Solve(network | half, length + 1);
            var id = _left.Count;
            _left.Add(left);
            _right.Add(right);
            for (var inherited = 0; inherited < _targets; inherited++)
            {
                _costs.Add(Choose(left, right, inherited, network, length).Cost);
            }

            return id;
        }

        public int Cost(int node, int inherited, uint network, int length)
        {
            if (node >= 0)
            {
                return _costs[(node * _targets) + inherited];
            }

            var target = -node - 1;
            if (target == inherited)
            {
                return 0;
            }

            if (!targets[target].Emittable || !MayNest(inherited, target) || Overlaps(network, Last(network, length)))
            {
                return Infinity;
            }

            // Однородная подсеть шире предела: столько маршрутов предельной длины. Последний адрес однородной
            // подсети — её же цели, так что маршрут последнего адреса ничего не портит, но тоже занимает запись.
            var count = length >= MinPrefix ? 1 : 1 << (MinPrefix - length);
            return count * RouteCost(target, Math.Max(length, MinPrefix));
        }

        public void Emit(int node, int inherited, uint network, int length, List<CoverRoute> result)
        {
            if (node < 0)
            {
                var target = -node - 1;
                if (target != inherited)
                {
                    EmitUniform(network, length, target, result);
                }

                return;
            }

            var half = 1u << (31 - length);
            var left = _left[node];
            var right = _right[node];
            var chosen = Choose(left, right, inherited, network, length).Target;
            if (chosen != inherited)
            {
                result.Add(new CoverRoute(new Ipv4Cidr(network, length), chosen));
            }

            Emit(left, chosen, network, length + 1, result);
            Emit(right, chosen, network | half, length + 1, result);
        }

        /// <summary>Лучший выбор в узле: оставить унаследованную цель или поставить маршрут к другой. При равенстве — без маршрута.</summary>
        private (int Cost, int Target) Choose(int left, int right, int inherited, uint network, int length)
        {
            var half = 1u << (31 - length);
            var best = Add(Cost(left, inherited, network, length + 1), Cost(right, inherited, network | half, length + 1));
            var chosen = inherited;
            if (!CanEmit(network, length))
            {
                return (best, chosen);
            }

            var last = Last(network, length);
            for (var target = 0; target < _targets; target++)
            {
                if (target == inherited || !targets[target].Emittable || !MayNest(inherited, target)
                    || (Broadcasts(target, length) && segments[SegmentAt(last)].Target != target))
                {
                    continue;
                }

                var cost = Add(RouteCost(target, length), Add(Cost(left, target, network, length + 1), Cost(right, target, network | half, length + 1)));
                if (cost < best)
                {
                    best = cost;
                    chosen = target;
                }
            }

            return (best, chosen);
        }

        /// <summary>Маршрут к цели 0 внутри маршрута цели, которой нельзя накрывать адреса цели 0.</summary>
        private bool MayNest(int inherited, int target) => target != 0 || targets[inherited].HoldsDefault;

        /// <summary>Windows добавит к маршруту запись последнего адреса.</summary>
        private bool Broadcasts(int target, int length) => targets[target].OnLink && length <= MaxBroadcastPrefix;

        /// <summary>Сколько записей таблицы занимает маршрут: с маршрутом последнего адреса — две.</summary>
        private int RouteCost(int target, int length) => Broadcasts(target, length) ? 2 : 1;

        private static void EmitUniform(uint network, int length, int target, List<CoverRoute> result)
        {
            if (length >= MinPrefix)
            {
                result.Add(new CoverRoute(new Ipv4Cidr(network, length), target));
                return;
            }

            var half = 1u << (31 - length);
            EmitUniform(network, length + 1, target, result);
            EmitUniform(network | half, length + 1, target, result);
        }

        private bool CanEmit(uint network, int length) => length >= MinPrefix && !Overlaps(network, Last(network, length));

        private int SegmentAt(uint address)
        {
            int low = 0, high = segments.Length - 1;
            while (low < high)
            {
                var middle = low + ((high - low + 1) / 2);
                if (segments[middle].Start <= address)
                {
                    low = middle;
                }
                else
                {
                    high = middle - 1;
                }
            }

            return low;
        }

        private bool Overlaps(uint first, uint last)
        {
            int low = 0, high = avoid.Length - 1, found = -1;
            while (low <= high)
            {
                var middle = low + ((high - low) / 2);
                if (avoid[middle].Start <= last)
                {
                    found = middle;
                    low = middle + 1;
                }
                else
                {
                    high = middle - 1;
                }
            }

            return found >= 0 && avoid[found].End >= first;
        }

        private static uint Last(uint network, int length) => length switch
        {
            0 => uint.MaxValue,
            32 => network,
            _ => network | (uint.MaxValue >> length),
        };

        private static int Add(int a, int b) => Math.Min(Infinity, a + b);
    }
}
