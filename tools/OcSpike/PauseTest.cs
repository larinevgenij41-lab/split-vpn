using System.Text.Json.Nodes;

namespace OcSpike;

/// <summary>
/// Опыт: переподключение внутри того же экземпляра библиотеки (OC_CMD_PAUSE и повторный mainloop).
/// Так ведёт себя служба при смене сети без перезапуска помощника.
/// </summary>
internal static unsafe partial class Program
{
    private static int RunPauseTest(ShimCallbacks callbacks)
    {
        var ctx = Oc.ShimNew(_opt.UserAgent, &callbacks, 0);
        _vpninfo = Oc.ShimVpninfo(ctx);
        var row = new JsonObject();
        Report["pauseTest"] = row;
        try
        {
            Prepare(_opt.Url);
            row["obtain"] = Oc.ObtainCookie(_vpninfo);
            if ((int)row["obtain"]! != 0)
                return 2;
            row["cstp"] = Oc.MakeCstpConnection(_vpninfo);
            if ((int)row["cstp"]! != 0)
                return 3;
            row["dtls"] = Oc.SetupDtls(_vpninfo, 60);
            var cmd = Oc.SetupCmdPipe(_vpninfo);
            row["tun"] = Oc.SetupTunDevice(_vpninfo, null, _opt.IfName);

            row["loop1"] = RunLoopFor(cmd, TimeSpan.FromSeconds(10), Oc.CmdPause);
            row["adapterWhilePaused"] = PowerShell($"Get-NetAdapter -IncludeHidden -Name '{_opt.IfName}' -ErrorAction SilentlyContinue | ForEach-Object Status");
            Thread.Sleep(TimeSpan.FromSeconds(5));
            Log("===== возобновление mainloop после паузы");
            row["loop2"] = RunLoopFor(cmd, TimeSpan.FromSeconds(10), Oc.CmdCancel);
            row["dtlsCipherEnd"] = Oc.Str(Oc.GetDtlsCipher(_vpninfo));
            return 0;
        }
        finally
        {
            Oc.ShimFree(ctx);
        }
    }

    private static int RunLoopFor(nint cmd, TimeSpan duration, byte stopCommand)
    {
        var rc = int.MinValue;
        var loop = new Thread(() => rc = Oc.Mainloop(_vpninfo, 30, 5)) { IsBackground = true };
        loop.Start();
        Thread.Sleep(duration);
        Log($"===== команда {(char)stopCommand}, поток жив: {loop.IsAlive}");
        Oc.ShimSendCmd(cmd, stopCommand);
        loop.Join(TimeSpan.FromSeconds(20));
        Log($"===== mainloop вернул {rc}");
        return rc;
    }
}
