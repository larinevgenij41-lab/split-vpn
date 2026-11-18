using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.System.JobObjects;

namespace SplitVpn.Windows.Operations;

/// <summary>Общее для дочерних процессов службы: помощников AnyConnect и движка «VPN поверх SSH».</summary>
internal static class ChildProcessJob
{
    /// <summary>
    /// Очередь запусков дочерних процессов. У помощника AnyConnect наследуемые концы труб существуют до его
    /// запуска: любой другой процесс, запущенный службой в это мгновение, унаследовал бы их и держал открытыми.
    /// </summary>
    public static Lock StartGate { get; } = new();

    /// <summary>Job, который завершает свои процессы, когда служба закрывает его или падает.</summary>
    public static unsafe SafeFileHandle CreateKillOnClose(string owner)
    {
        var job = PInvoke.CreateJobObject(null, null);
        if (job.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Не удалось создать Job для " + owner);
        }

        var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!PInvoke.SetInformationJobObject((global::Windows.Win32.Foundation.HANDLE)job.DangerousGetHandle(), JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation, &limits, (uint)sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)))
        {
            var error = Marshal.GetLastPInvokeError();
            job.Dispose();
            throw new Win32Exception(error, "Не удалось настроить Job для " + owner);
        }

        return job;
    }

    public static void KillQuietly(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            // Уже завершился.
        }
    }
}
