using System.Runtime.InteropServices;

namespace SplitVpn.Windows.Native;

/// <summary>Неуправляемая память на время одного вызова API; освобождается целиком.</summary>
internal sealed unsafe class NativeArena : IDisposable
{
    private readonly List<nint> _blocks = [];
    private readonly List<Action> _releases = [];

    public T* Alloc<T>(int count = 1)
        where T : unmanaged
    {
        var pointer = (T*)NativeMemory.AllocZeroed((nuint)(sizeof(T) * Math.Max(1, count)));
        _blocks.Add((nint)pointer);
        return pointer;
    }

    public T* Value<T>(T value)
        where T : unmanaged
    {
        var pointer = Alloc<T>();
        *pointer = value;
        return pointer;
    }

    public char* String(string value)
    {
        var pointer = (char*)Marshal.StringToHGlobalUni(value);
        _releases.Add(() => Marshal.FreeHGlobal((nint)pointer));
        return pointer;
    }

    /// <summary>Регистрирует освобождение ресурса, выделенного системным API.</summary>
    public void OnDispose(Action release) => _releases.Add(release);

    public void Dispose()
    {
        foreach (var block in _blocks)
        {
            NativeMemory.Free((void*)block);
        }

        foreach (var release in _releases)
        {
            release();
        }

        _blocks.Clear();
        _releases.Clear();
    }
}
