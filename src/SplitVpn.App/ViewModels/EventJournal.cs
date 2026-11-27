using System.Collections.ObjectModel;
using System.Globalization;
using SplitVpn.Core.Ipc;

namespace SplitVpn.App.ViewModels;

/// <summary>
/// Журнал событий службы на странице «Диагностика»: новые события вставляются в начало одного и того же списка,
/// а не пересоздают его на каждом опросе — иначе прокрутка сбрасывалась, и читаемая строка уезжала.
/// Хранится не больше <see cref="Limit"/> событий; фильтр «Только ошибки и предупреждения» меняет только видимое.
/// </summary>
public sealed class EventJournal
{
    public const int Limit = 500;

    /// <summary>Все события, новые первыми.</summary>
    private readonly List<ServiceEvent> _all = [];

    private bool _onlyProblems;

    /// <summary>Видимые события, новые первыми: источник списка на странице, не пересоздаётся.</summary>
    public ObservableCollection<ServiceEvent> Visible { get; } = [];

    /// <summary>Номера всех хранимых событий: по ним отсекаются повторы.</summary>
    public IEnumerable<long> Ids => _all.Select(e => e.Id);

    public int Count => _all.Count;

    /// <summary>Показывать только ошибки и предупреждения.</summary>
    public bool OnlyProblems
    {
        get => _onlyProblems;
        set
        {
            if (_onlyProblems == value)
            {
                return;
            }

            _onlyProblems = value;
            Visible.Clear();
            foreach (var item in _all.Where(Shown))
            {
                Visible.Add(item);
            }
        }
    }

    public static bool IsProblem(ServiceEvent item) =>
        item is { Level: "Ошибка" or "Предупреждение" };

    private bool Shown(ServiceEvent item) => !_onlyProblems || IsProblem(item);

    public void Clear()
    {
        _all.Clear();
        Visible.Clear();
    }

    /// <summary>
    /// Добавляет новые события (новые первыми) в начало. Самые старые сверх <see cref="Limit"/> убираются с конца,
    /// поэтому строки, которые пользователь сейчас читает, остаются теми же объектами на тех же местах от конца.
    /// </summary>
    public void Prepend(IReadOnlyList<ServiceEvent> newestFirst)
    {
        ArgumentNullException.ThrowIfNull(newestFirst);
        if (newestFirst.Count == 0)
        {
            return;
        }

        _all.InsertRange(0, newestFirst);
        var at = 0;
        foreach (var item in newestFirst.Where(Shown))
        {
            Visible.Insert(at++, item);
        }

        if (_all.Count > Limit)
        {
            var dropped = _all.GetRange(Limit, _all.Count - Limit);
            _all.RemoveRange(Limit, _all.Count - Limit);
            // Убираемые — самые старые, они в конце видимого списка.
            for (var i = Visible.Count - 1; i >= 0 && dropped.Count > 0; i--)
            {
                if (dropped.Remove(Visible[i]))
                {
                    Visible.RemoveAt(i);
                }
            }
        }
    }

    /// <summary>Строка события для буфера обмена: время и текст.</summary>
    public static string Format(ServiceEvent item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return item.TimeUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss", CultureInfo.GetCultureInfo("ru-RU")) + "  " + item.Text;
    }

    /// <summary>Видимые события одним текстом, новые первыми — как на экране.</summary>
    public string FormatVisible() => string.Join(Environment.NewLine, Visible.Select(Format));
}
