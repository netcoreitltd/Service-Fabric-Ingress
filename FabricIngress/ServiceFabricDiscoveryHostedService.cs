using Microsoft.Extensions.Hosting;

namespace ServiceFabricIngress;

public sealed class ServiceFabricDiscoveryHostedService : BackgroundService
{
    private readonly ServiceFabricPropertyConfigProvider _provider;
    private readonly ILogger<ServiceFabricDiscoveryHostedService> _logger;

    public ServiceFabricDiscoveryHostedService(
        ServiceFabricPropertyConfigProvider provider,
        ILogger<ServiceFabricDiscoveryHostedService> logger)
    {
        _provider = provider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Primo load subito: se fallisce, logga e ritenta.
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _provider.RefreshAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Discovery refresh failed.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }
}
