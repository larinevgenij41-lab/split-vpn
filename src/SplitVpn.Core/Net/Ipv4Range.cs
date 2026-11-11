namespace SplitVpn.Core.Net;

/// <summary>Непустой включающий диапазон IPv4-адресов [Start, End].</summary>
public readonly record struct Ipv4Range
{
    public Ipv4Range(uint start, uint end)
    {
        if (end < start)
        {
            throw new ArgumentException("Конец диапазона меньше начала.");
        }

        Start = start;
        End = end;
    }

    public uint Start { get; }

    public uint End { get; }

    /// <summary>Количество адресов (до 2^32, поэтому ulong).</summary>
    public ulong Size => (ulong)End - Start + 1;

    public bool Contains(uint address) => address >= Start && address <= End;

    public bool Overlaps(Ipv4Range other) => Start <= other.End && other.Start <= End;

    public static Ipv4Range Host(uint address) => new(address, address);

    public override string ToString() => Start == End ? Ipv4.Format(Start) : $"{Ipv4.Format(Start)}-{Ipv4.Format(End)}";
}
