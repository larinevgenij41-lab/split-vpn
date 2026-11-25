using System.Security.Cryptography;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Итерация 12: тексты ошибок службы без исходного текста исключения, успех сохранения при сбое переподключения,
/// отдельный код отказа «идёт дозвон», расшифровка новых кодов RAS и IKE.
/// </summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public void ErrorText_MapsExceptionTypesToRussianAdvice_WithoutRawMessage()
    {
        var full = new IOException("There is not enough space on the disk.", unchecked((int)0x80070070));
        var shared = new IOException("The process cannot access the file because it is being used by another process.", unchecked((int)0x80070020));
        Assert.Contains("нет места", ServiceErrorText.Describe(full), StringComparison.Ordinal);
        Assert.Contains("занят другой программой", ServiceErrorText.Describe(shared), StringComparison.Ordinal);
        Assert.Contains("нет доступа", ServiceErrorText.Describe(new UnauthorizedAccessException("Access to the path is denied.")), StringComparison.Ordinal);
        Assert.Contains("DPAPI", ServiceErrorText.Describe(new CryptographicException("Key not valid for use in specified state.")), StringComparison.Ordinal);
        Assert.Contains("вовремя", ServiceErrorText.Describe(new TimeoutException("The operation has timed out.")), StringComparison.Ordinal);
        Assert.Contains("0x00000005", ServiceErrorText.Describe(new NativeCallException("RasHangUp", 5)), StringComparison.Ordinal);
        Assert.Contains("прервана", ServiceErrorText.Describe(new OperationCanceledException()), StringComparison.Ordinal);
        Assert.Contains("непредвиденная", ServiceErrorText.Describe(new NullReferenceException("Object reference not set")), StringComparison.Ordinal);
        Assert.StartsWith("Недопустимые параметры VPN-записи", ServiceErrorText.Describe(new InvalidOperationException("Недопустимые параметры VPN-записи.")), StringComparison.Ordinal);
        Assert.Contains("непредвиденная", ServiceErrorText.Describe(new InvalidOperationException("Sequence contains no elements")), StringComparison.Ordinal);

        var text = ServiceErrorText.Format("Настройки не сохранены", full, "0A1B2C3D");
        Assert.DoesNotContain("not enough space", text, StringComparison.Ordinal);
        Assert.EndsWith("Код для поддержки: 0A1B2C3D.", text, StringComparison.Ordinal);
        Assert.Matches("^[0-9A-F]{8}$", ServiceErrorText.NewId());
    }

    /// <summary>Файл настроек занят: пользователь видит причину и код для поддержки, а не английский текст .NET.</summary>
    [Fact]
    public async Task SaveSettings_FileLocked_ShowsAdviceAndSupportCode()
    {
        var coordinator = await StartAsync();
        IpcResponse response;
        using (new FileStream(_world.Paths.Settings, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with { SequentialDial = !coordinator.Settings.SequentialDial }), CancellationToken.None);
        }

        Assert.False(response.Ok);
        Assert.Contains("Настройки не сохранены", response.ErrorMessage, StringComparison.Ordinal);
        Assert.Contains("Код для поддержки:", response.ErrorMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("process", response.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Пароль не записался: текст называет подключение и что делать, без исходного текста исключения.</summary>
    [Fact]
    public async Task SaveConnection_SecretWriteFails_ShowsAdviceWithoutRawMessage()
    {
        var coordinator = await StartAsync();
        _world.Secrets.FailSave = true;
        try
        {
            var response = await coordinator.HandleRequestAsync(new SaveConnectionRequest(coordinator.Settings, _profile.Id, "новый пароль", null), CancellationToken.None);
            Assert.False(response.Ok);
            Assert.Contains($"Не удалось сохранить пароль для «{_profile.Name}»", response.ErrorMessage, StringComparison.Ordinal);
            Assert.DoesNotContain("диск недоступен", response.ErrorMessage, StringComparison.Ordinal);
            Assert.Contains("Код для поддержки:", response.ErrorMessage, StringComparison.Ordinal);
        }
        finally
        {
            _world.Secrets.FailSave = false;
        }
    }

    /// <summary>
    /// Сервер сменён, а разрыв прежнего сеанса не удался: настройки уже записаны, поэтому ответ — успех с предупреждением,
    /// а переподключение повторит сверка.
    /// </summary>
    [Fact]
    public async Task SaveConnection_ReconnectFails_ReturnsSuccessWithNotice()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 668);
        var settings = coordinator.Settings with
        {
            Profiles = coordinator.Settings.Profiles.Select(p => p.Id == _profile.Id ? p with { Server = "198.51.100.20:4443" } : p).ToList(),
        };

        var response = await coordinator.HandleRequestAsync(new SaveConnectionRequest(settings, _profile.Id, null, null), CancellationToken.None);

        Assert.True(response.Ok, response.ErrorMessage);
        Assert.Contains(response.ResultAs<List<string>>()!, w => w.StartsWith(Coordinator.ReconnectDeferredNotice, StringComparison.Ordinal));
        Assert.Equal("198.51.100.20:4443", coordinator.Settings.Profile(_profile.Id)!.Server);
        Assert.NotNull(coordinator.Facts.PartialError);
        _world.Ras.HangUpFailure = null;
    }

    /// <summary>Отказ «идёт дозвон» — свой код: приложение отличает его от устаревшей ревизии и повторяет само.</summary>
    [Fact]
    public async Task ProfileRoleAndKey_DuringDial_UseDialInProgressCode()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        coordinator.Facts.Tunnels.Values.First().Dialing = true;

        var role = await coordinator.HandleRequestAsync(new SetProfileRoleRequest(_profile.Id, ProfileRole.Secondary), CancellationToken.None);
        var key = await coordinator.HandleRequestAsync(new SetPreSharedKeyRequest(_profile.Id, "ключ"), CancellationToken.None);

        Assert.Equal(IpcErrorCodes.DialInProgress, role.ErrorCode);
        Assert.Equal(IpcErrorCodes.DialInProgress, key.ErrorCode);
    }

    [Theory]
    [InlineData(13868, ErrorCategory.Authentication, false)]
    [InlineData(13843, ErrorCategory.Authentication, false)]
    [InlineData(734, ErrorCategory.Authentication, false)]
    [InlineData(13809, ErrorCategory.ServerUnreachable, true)]
    [InlineData(619, ErrorCategory.ServerUnreachable, true)]
    [InlineData(735, ErrorCategory.Other, true)]
    [InlineData(732, ErrorCategory.Other, true)]
    [InlineData(unchecked((int)0x80092012), ErrorCategory.Certificate, false)]
    [InlineData(unchecked((int)0x800B010A), ErrorCategory.Certificate, false)]
    public void NewErrorCodes_AreClassifiedAndExplained(int code, ErrorCategory category, bool retryable)
    {
        var info = RasErrorClassifier.Classify(code);
        Assert.Equal(category, info.Category);
        Assert.Equal(retryable, info.Retryable);

        var help = ConnectionErrorGuide.For(category, code, VpnProtocol.Ikev2, AuthMethod.EapMsChapV2, null, DateTimeOffset.UtcNow);
        var generic = ConnectionErrorGuide.For(category, null, VpnProtocol.Ikev2, AuthMethod.EapMsChapV2, null, DateTimeOffset.UtcNow);
        Assert.NotEqual(generic.Summary, help.Summary);
        Assert.NotEmpty(help.Steps);
    }
}
