using System.IO.Compression;

namespace SplitVpn.Core.Diagnostics;

public static class ArchiveTime
{
    public static void Set(ZipArchiveEntry entry, DateTime time, ICollection<string> problems)
    {
        if (time.Year is >= 1980 and <= 2107)
        {
            entry.LastWriteTime = time;
            return;
        }

        entry.LastWriteTime = new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
        problems.Add(entry.FullName + ": дата файла вне диапазона ZIP, заменена на 1980-01-01");
    }
}
