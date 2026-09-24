using SplitVpn.Core.Ipc;

namespace SplitVpn.Core.Tests.Ipc;

public sealed class RequestTimeoutsTests
{
    [Fact]
    public void QueriesAreShortCommandsAreLong()
    {
        Assert.Equal(RequestTimeouts.Query, RequestTimeouts.For(new GetStatusRequest()));
        Assert.Equal(RequestTimeouts.Query, RequestTimeouts.For(new GetEventsRequest(0)));
        Assert.Equal(RequestTimeouts.Recover, RequestTimeouts.For(new RecoverNetworkRequest()));
        Assert.Equal(RequestTimeouts.Test, RequestTimeouts.For(new TestProfileRequest(Guid.NewGuid())));
        Assert.Equal(RequestTimeouts.Command, RequestTimeouts.For(new GeoImportRequest("")));
        Assert.Equal(RequestTimeouts.Command, RequestTimeouts.For(new DisconnectRequest(KeepProtection: true)));
    }

    [Fact]
    public void SignInAndAddressCheckWaitAsLongAsLookups()
    {
        Assert.Equal(RequestTimeouts.Lookup, RequestTimeouts.For(new CheckAddressRequest("example.org")));
        Assert.Equal(RequestTimeouts.Lookup, RequestTimeouts.For(new BeginSignInRequest(Guid.NewGuid())));
        Assert.Equal(RequestTimeouts.Lookup, RequestTimeouts.For(new CancelSignInRequest(Guid.NewGuid(), Guid.NewGuid())));
    }

    [Fact]
    public void RecoverIsShorterThanCommandsSoEmergencyPathIsReachable()
    {
        Assert.True(RequestTimeouts.Recover < RequestTimeouts.Command);
        Assert.True(RequestTimeouts.Query < RequestTimeouts.Recover);
        // Восстановление идёт по своему соединению, но в очереди актора ждёт идущую сверку: слишком короткий
        // предел уводил бы к остановке службы с правами администратора там, где хватило бы нескольких секунд.
        Assert.True(RequestTimeouts.Recover >= TimeSpan.FromSeconds(20));
    }

    [Fact]
    public void UnavailableExceptionDefaultsToNotRunning()
    {
        Assert.Equal(ServiceUnavailableReason.NotRunning, new ServiceUnavailableException("x").Reason);
        Assert.Equal(ServiceUnavailableReason.Timeout, new ServiceUnavailableException("x", null, ServiceUnavailableReason.Timeout).Reason);
    }
}
