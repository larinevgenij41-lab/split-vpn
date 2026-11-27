using System.Security.AccessControl;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Recovery;
using SplitVpn.Core.SshTunnel;

namespace SplitVpn.Core.Tests;

/// <summary>Итерация 12: строки журнала, файлы процессов журнала интерфейса, монотонные сроки DNS, WOF у файла службы.</summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class Iteration12CoreTests
{
    [Theory]
    [InlineData("обычная строка", "обычная строка")]
    [InlineData("a\r\nb", "a ⏎ b")]
    [InlineData("a\nb\rc", "a ⏎ b ⏎ c")]
    [InlineData("a\u2028b", "a ⏎ b")]
    [InlineData("tab\tкак есть", "tab\tкак есть")]
    [InlineData("bell\u0007", "bell\\u0007")]
    [InlineData("esc\u001b[31m", "esc\\u001B[31m")]
    [InlineData("c1\u0085x\u009b", "c1\\u0085x\\u009B")]
    [InlineData("bidi\u202Etxt.exe\u2066\u2069", "bidi\\u202Etxt.exe\\u2066\\u2069")]
    [InlineData("", "")]
    public void SingleLine_NeutralisesLineBreaksAndControls(string input, string expected) =>
        Assert.Equal(expected, LogText.SingleLine(input));

    [Fact]
    public void SingleLine_ForgedEntryStaysOnOneLine()
    {
        var forged = LogText.SingleLine("ошибка входа\r\n2026-11-25 10:00:00 [INF] Сведения: всё хорошо");
        Assert.DoesNotContain('\n', forged);
        Assert.DoesNotContain('\r', forged);
        Assert.Equal("", LogText.SingleLine(null));
    }

    [Fact]
    public void EncryptedSshKeyAdvice_DoesNotStripPassphraseFromOriginal()
    {
        var text = SshPrivateKey.Describe(SshPrivateKeyCheck.Encrypted);
        Assert.Contains("copy key key.nopass", text, StringComparison.Ordinal);
        Assert.Contains("ssh-keygen -p -f key.nopass", text, StringComparison.Ordinal);
        Assert.Contains("удалите", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("ui-verbose.1234.log", true, 1234)]
    [InlineData("ui-verbose.1234.log.1", true, 1234)]
    [InlineData("ui-verbose.log", false, 0)]
    [InlineData("ui-verbose.log.1", false, 0)]
    [InlineData("ui-verbose.abc.log", false, 0)]
    [InlineData("ui-other.12.log", false, 0)]
    public void ProcessFileNames_AreRecognised(string name, bool expected, int pid)
    {
        Assert.Equal(expected, RollingTextLog.IsProcessFile(name, "ui-verbose", out var parsed));
        Assert.Equal(pid, parsed);
    }

    [Fact]
    public void OldProcessFiles_ArePruned_SharedAndFreshFilesStay()
    {
        var folder = Directory.CreateTempSubdirectory("splitvpn-rolling-prune-").FullName;
        try
        {
            var time = new FakeTimeProvider(new DateTimeOffset(2026, 11, 25, 10, 0, 0, TimeSpan.Zero));
            var log = Path.Combine(folder, "ui-verbose.log");
            string Make(string name, int ageDays)
            {
                var path = Path.Combine(folder, name);
                File.WriteAllText(path, "x");
                File.SetLastWriteTimeUtc(path, time.GetUtcNow().UtcDateTime - TimeSpan.FromDays(ageDays));
                return path;
            }

            var shared = Make("ui-verbose.log", 30);
            var old = Make("ui-verbose.111.log", 8);
            var oldRotated = Make("ui-verbose.111.log.1", 9);
            var fresh = Make("ui-verbose.222.log", 1);
            var own = Make($"ui-verbose.{Environment.ProcessId}.log", 30);

            Assert.Equal(2, RollingTextLog.PruneProcessFiles(log, TimeSpan.FromDays(7), time));

            Assert.True(File.Exists(shared));
            Assert.False(File.Exists(old));
            Assert.False(File.Exists(oldRotated));
            Assert.True(File.Exists(fresh));
            Assert.True(File.Exists(own));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void LogMutex_CreatedWithExplicitRights_CanBeOpenedAgain()
    {
        var name = RollingTextLog.MutexName(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "ui-verbose.log"));
        using var first = RollingTextLog.CreateMutex(name);
        using var second = RollingTextLog.CreateMutex(name);
        Assert.True(second.WaitOne(TimeSpan.FromSeconds(5)));
        second.ReleaseMutex();

        if (OperatingSystem.IsWindows())
        {
            var rules = first.GetAccessControl().GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            Assert.Contains(rules.Cast<MutexAccessRule>(), r => r.IdentityReference.Equals(identity.User) && r.MutexRights.HasFlag(MutexRights.Synchronize));
        }
    }

    /// <summary>Часы, которые переводят вручную; монотонное время идёт отдельно.</summary>
    private sealed class JumpingClock(FakeTimeProvider inner) : TimeProvider
    {
        public TimeSpan Jump { get; set; }

        public override DateTimeOffset GetUtcNow() => inner.GetUtcNow() + Jump;

        public override long GetTimestamp() => inner.GetTimestamp();

        public override long TimestampFrequency => inner.TimestampFrequency;
    }

    [Fact]
    public void TemporaryPin_ExpiresByMonotonicTime_NotByWallClock()
    {
        var fake = new FakeTimeProvider(new DateTimeOffset(2026, 11, 25, 10, 0, 0, TimeSpan.Zero));
        var clock = new JumpingClock(fake);
        var cache = new DnsCache(clock);
        cache.Pin("temp.example", [0x01020304], TimeSpan.FromMinutes(1));

        // Часы перевели на сутки вперёд: закрепление не истекает раньше срока.
        clock.Jump = TimeSpan.FromDays(1);
        Assert.True(cache.TryGetPinned("temp.example", out _, out var remaining));
        Assert.Equal(TimeSpan.FromMinutes(1), remaining);

        // ...и назад: не живёт дольше срока.
        clock.Jump = -TimeSpan.FromDays(1);
        fake.Advance(TimeSpan.FromMinutes(1));
        Assert.False(cache.TryGetPinned("temp.example", out _));
    }

    [Fact]
    public void CanonicalLink_ExpiresByMonotonicTime_NotByWallClock()
    {
        var fake = new FakeTimeProvider(new DateTimeOffset(2026, 11, 25, 10, 0, 0, TimeSpan.Zero));
        var clock = new JumpingClock(fake);
        var cache = new DnsCache(clock);
        Assert.True(cache.LinkCanonical("cdn.example.net", "example.org", TimeSpan.FromMinutes(5)));

        clock.Jump = TimeSpan.FromDays(1);
        Assert.Equal("example.org", cache.TryGetCanonicalLink("cdn.example.net"));

        clock.Jump = -TimeSpan.FromDays(1);
        fake.Advance(TimeSpan.FromMinutes(5));
        Assert.Null(cache.TryGetCanonicalLink("cdn.example.net"));
    }

    [Theory]
    [InlineData(FileAttributes.Archive | FileAttributes.ReparsePoint, AdminOnlyAccess.ReparseTagWof, FileAttributes.Archive)]
    [InlineData(FileAttributes.Archive | FileAttributes.ReparsePoint, 0xA000000Cu, FileAttributes.Archive | FileAttributes.ReparsePoint)] // symlink
    [InlineData(FileAttributes.Archive | FileAttributes.ReparsePoint, 0xA0000003u, FileAttributes.Archive | FileAttributes.ReparsePoint)] // junction
    [InlineData(FileAttributes.Archive | FileAttributes.ReparsePoint, 0x80000013u, FileAttributes.Archive | FileAttributes.ReparsePoint)] // дедупликация
    [InlineData(FileAttributes.Archive | FileAttributes.ReparsePoint, 0u, FileAttributes.Archive | FileAttributes.ReparsePoint)]
    [InlineData(FileAttributes.Directory | FileAttributes.ReparsePoint, AdminOnlyAccess.ReparseTagWof, FileAttributes.Directory | FileAttributes.ReparsePoint)]
    [InlineData(FileAttributes.Archive, AdminOnlyAccess.ReparseTagWof, FileAttributes.Archive)]
    public void OnlyWofTagIsTransparent(FileAttributes attributes, uint tag, FileAttributes expected) =>
        Assert.Equal(expected, AdminOnlyAccess.FileAttributesForCheck(attributes, tag));

    /// <summary>Сжатый WOF файл службы проверяется как обычный; каталог с той же меткой — нет.</summary>
    [Fact]
    public void ElevationTarget_WofCompressedFileIsAccepted_DirectoriesStayStrict()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var file = @"C:\Program Files\SplitVpn\SplitVpn.Service.exe";
        var security = new FileSecurity();
        security.SetOwner(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null));
        var directorySecurity = new DirectorySecurity();
        directorySecurity.SetOwner(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null));

        (FileAttributes, FileSystemSecurity)? Read(string path, bool directory, bool reparseDirectory) => directory
            ? (FileAttributes.Directory | (reparseDirectory && path.EndsWith("SplitVpn", StringComparison.Ordinal) ? FileAttributes.ReparsePoint : 0), directorySecurity)
            : (FileAttributes.Archive | FileAttributes.ReparsePoint, security);

        Assert.Null(AdminOnlyAccess.ElevationTargetProblem(file, (p, d) => Read(p, d, false), _ => AdminOnlyAccess.ReparseTagWof));
        Assert.Contains("ссылкой", AdminOnlyAccess.ElevationTargetProblem(file, (p, d) => Read(p, d, false), _ => 0xA000000C), StringComparison.Ordinal);
        Assert.Contains("ссылкой", AdminOnlyAccess.ElevationTargetProblem(file, (p, d) => Read(p, d, false)), StringComparison.Ordinal);
        Assert.Contains(@"SplitVpn: оказался ссылкой", AdminOnlyAccess.ElevationTargetProblem(file, (p, d) => Read(p, d, true), _ => AdminOnlyAccess.ReparseTagWof), StringComparison.Ordinal);
    }
}
