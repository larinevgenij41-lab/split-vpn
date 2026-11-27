using Serilog;

namespace SplitVpn.Service.Diagnostics;

/// <summary>
/// Необработанные исключения процесса службы. Исключение на собственном потоке (события помощника AnyConnect, сбор
/// диагностики) завершает процесс, и без обработчика причина видна только в системном событии .NET Runtime: здесь она
/// пишется в журнал службы, и журнал сбрасывается на диск до завершения процесса. Процесс по-прежнему завершается
/// аварийно — диспетчер служб перезапускает службу по действиям при сбое.
/// </summary>
internal static class ServiceCrash
{
    /// <summary>AppDomain.UnhandledException: запись Fatal и сброс журнала.</summary>
    internal static void OnUnhandled(object exceptionObject) =>
        OnUnhandled(exceptionObject, Log.Logger, Log.CloseAndFlush, text => ServiceInstance.ReportEarly(text, isWindowsService: false));

    /// <summary>
    /// Шов для тестов: <paramref name="flush"/> сбрасывает журнал, <paramref name="console"/> пишет мимо него (журнала может
    /// ещё не быть; системное событие .NET Runtime о сбое Windows запишет и так).
    /// </summary>
    internal static void OnUnhandled(object exceptionObject, Serilog.ILogger logger, Action flush, Action<string> console)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(flush);
        ArgumentNullException.ThrowIfNull(console);
        try
        {
            var exception = exceptionObject as Exception;
            console("Служба завершается из-за необработанного исключения: " + (exception?.ToString() ?? exceptionObject?.ToString()));
            logger.Fatal(exception, "Служба завершается из-за необработанного исключения {Type}",
                exception?.GetType().FullName ?? exceptionObject?.GetType().FullName ?? "null");
        }
        catch (Exception)
        {
            // Обработчик не должен бросать сам: процесс и так завершается, причина остаётся в событии .NET Runtime.
        }
        finally
        {
            try
            {
                flush();
            }
            catch (Exception)
            {
                // Сбой сброса журнала не должен подменять исходную причину.
            }
        }
    }

    /// <summary>TaskScheduler.UnobservedTaskException: предупреждение, исключение помечается наблюдённым.</summary>
    internal static void OnUnobserved(UnobservedTaskExceptionEventArgs e) => OnUnobserved(e, Log.Logger);

    internal static void OnUnobserved(UnobservedTaskExceptionEventArgs e, Serilog.ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(e);
        ArgumentNullException.ThrowIfNull(logger);
        try
        {
            logger.Warning(e.Exception, "Необработанное исключение фоновой задачи");
        }
        catch (Exception)
        {
            // Запись в журнал не должна мешать пометке исключения наблюдённым.
        }
        finally
        {
            e.SetObserved();
        }
    }
}
