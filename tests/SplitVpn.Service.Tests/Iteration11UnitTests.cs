using System.IO.Pipes;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Diagnostics;

namespace SplitVpn.Service.Tests;

/// <summary>Итерация 11: проверка совместимости при подключении, пределы предупреждений, прерывание зависшего чтения.</summary>
public sealed class Iteration11UnitTests
{
    [Fact]
    public void Handshake_OnlyBadRequestMeansOtherVersion()
    {
        Assert.Null(IpcClient.HandshakeProblem(IpcResponse.Success(Array.Empty<AdapterDto>())));
        Assert.Equal(ServiceUnavailableReason.VersionMismatch, IpcClient.HandshakeProblem(IpcResponse.Failure(IpcErrorCodes.BadRequest, "версия")));
        Assert.Equal(ServiceUnavailableReason.Denied, IpcClient.HandshakeProblem(IpcResponse.Failure(IpcErrorCodes.Denied, "права")));
        // Служба сверяет версию первой: занятость или сбой — версия принята.
        Assert.Null(IpcClient.HandshakeProblem(IpcResponse.Failure(IpcErrorCodes.Busy, "настройки не прочитаны")));
        Assert.Null(IpcClient.HandshakeProblem(IpcResponse.Failure(IpcErrorCodes.Failed, "ответ больше кадра")));
    }

    [Fact]
    public void ServerNetworksRequest_RoundTripsThroughStrictParser()
    {
        var id = Guid.NewGuid();
        var parsed = IpcSerializer.TryDeserializeRequest(IpcSerializer.SerializeRequest(new GetServerNetworksRequest(id, 1024)));
        Assert.Equal(new GetServerNetworksRequest(id, 1024), parsed);
        Assert.Equal(RequestTimeouts.Query, RequestTimeouts.For(parsed!));
    }

    [Fact]
    public void Warnings_BoundedPerCodeWithSummaryAndShortText()
    {
        var warnings = Enumerable.Range(0, 500).Select(i => new StatusWarning("public-onlink", "сеть " + i, null))
            .Append(new StatusWarning("long", new string('x', 100_000), null))
            .Append(new StatusWarning("ipv6-restricted", "IPv6", null))
            .ToList();

        var bounded = Coordinator.BoundWarnings(warnings);

        Assert.Equal(Coordinator.MaxWarningsPerCode, bounded.Count(w => w.Code == "public-onlink"));
        Assert.Contains(bounded, w => w.Code == "ipv6-restricted");
        Assert.True(bounded.Single(w => w.Code == "long").Text.Length <= Coordinator.MaxWarningText + 1);
        Assert.Contains("480", bounded.Single(w => w.Code == "warnings-truncated").Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Чтение зависло в синхронном вводе-выводе (как открытие файла под чужим oplock): по сроку оно прерывается,
    /// место освобождается, и следующие сборы читают файлы пользователей, а не пропускают их до перезапуска службы.
    /// </summary>
    [Fact]
    public void HungSynchronousRead_IsCancelledAndFreesSlot()
    {
        var reader = new DiagnosticsFileReader(1);
        for (var round = 0; round < 3; round++)
        {
            using var server = new AnonymousPipeServerStream(PipeDirection.Out);
            using var client = new AnonymousPipeClientStream(PipeDirection.In, server.ClientSafePipeHandle);
            var result = reader.Read(_ =>
            {
                // Синхронное чтение пустого канала: ждёт, пока его не прервёт CancelSynchronousIo.
                client.ReadByte();
                return null;
            }, TimeSpan.FromMilliseconds(100), out var problem);

            Assert.Null(result);
            Assert.Equal("истёк срок чтения пользовательского файла", problem);
        }

        var next = WaitForSlot(reader);
        Assert.NotNull(next);
    }

    private static CollectedFile? WaitForSlot(DiagnosticsFileReader reader)
    {
        CollectedFile? result = null;
        for (var i = 0; i < 100 && result is null; i++)
        {
            result = reader.Read(_ => new CollectedFile([1], DateTime.Now), TimeSpan.FromSeconds(1), out _);
            if (result is null) Thread.Sleep(10);
        }

        return result;
    }
}
