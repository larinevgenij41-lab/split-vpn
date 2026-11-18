using SplitVpn.Cli;

namespace SplitVpn.Service.Tests;

public sealed class ReviewRegressionTests
{
    [Fact]
    public void MissingProfileValueCannotSelectPrimaryProfile()
    {
        Assert.True(ServiceCommands.TryProfileOption(new CliArgs([]), out var usePrimary));
        Assert.Null(usePrimary);
        Assert.False(ServiceCommands.TryProfileOption(new CliArgs(["--profile"]), out _));
        Assert.False(ServiceCommands.TryProfileOption(new CliArgs(["--profile", "--another-option"]), out _));
        var expected = Guid.NewGuid();
        Assert.True(ServiceCommands.TryProfileOption(new CliArgs(["--profile", expected.ToString()]), out var selected));
        Assert.Equal(expected, selected);
    }

    [Fact]
    public async Task ReleaseKeyCannotReplaceExistingFile()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "existing", TestContext.Current.CancellationToken);
            Assert.Throws<IOException>(() => ReleaseCommands.WriteNewKey(path, "replacement"));
            Assert.NotEqual(0, await ReleaseCommands.KeygenAsync(new CliArgs(["--out", path])));
            Assert.Equal("existing", await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
