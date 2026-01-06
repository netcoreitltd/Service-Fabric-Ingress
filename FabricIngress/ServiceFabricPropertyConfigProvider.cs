using FabricIngress.SSL;
using Microsoft.Extensions.Primitives;
using Microsoft.ServiceFabric.Services.Client;
using System.Fabric;
using System.Fabric.Description;
using System.Fabric.Query;
using System.Text.Json;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder; // Per ForwarderRequestConfig

namespace ServiceFabricIngress;

// 1) Provider YARP: contiene solo l'ultima snapshot + change token signaling.
public sealed class ServiceFabricPropertyConfigProvider : IProxyConfigProvider
{
    private readonly FabricClient _fabricClient;
    private readonly ILogger<ServiceFabricPropertyConfigProvider> _logger;
    private readonly StatelessServiceContext _sfContext;
    private readonly AllowedSSLHosts _allowedSslHosts;
    private readonly IHostApplicationLifetime _appLifetime;

    // snapshot of hosts known at startup. This is our "Immutable Baseline".
    private readonly HashSet<string> _startupSslHosts;

    public DateTimeOffset LastRefreshUtc { get; private set; } = DateTimeOffset.MinValue;
    public string? LastRefreshError { get; private set; }

    // Snapshot corrente (volatile per letture lock-free da parte di YARP)
    private volatile ProxyConfigSnapshot _current;

    // Token usato per notificare a YARP "config cambiata"
    private CancellationTokenSource _changeCts = new();

    public ServiceFabricPropertyConfigProvider(
        AllowedSSLHosts allowedSslHosts,
        IHostApplicationLifetime appLifetime,
        StatelessServiceContext sfContext,
        ILogger<ServiceFabricPropertyConfigProvider> logger)
    {
        _sfContext = sfContext;
        _logger = logger;
        _fabricClient = new FabricClient();
        _allowedSslHosts = allowedSslHosts;
        _appLifetime = appLifetime;

        // capture the startup state immediately. 
        // we will compare against THIS set to decide if we need to restart.
        _startupSslHosts = _allowedSslHosts.GetAll().ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Config iniziale: valida e "vuota", ma con ChangeToken NON nullo
        _current = new ProxyConfigSnapshot(
            routes: Array.Empty<RouteConfig>(),
            clusters: Array.Empty<ClusterConfig>(),
            changeToken: new CancellationChangeToken(_changeCts.Token));
    }

    public IProxyConfig GetConfig() => _current;

    /// <summary>
    /// Richiamato dal polling service. Carica config e, se diversa, segnala change.
    /// </summary>
    //public async Task RefreshAsync(CancellationToken ct)
    //{
    //    ct.ThrowIfCancellationRequested();

    //    var (routes, clusters) = await BuildConfigAsync(ct);

    //    // Facoltativo: evita reload continui se uguale (qui facciamo solo un check semplice)
    //    if (ReferenceEquals(routes, _current.Routes) && ReferenceEquals(clusters, _current.Clusters))
    //    {
    //        return;
    //    }

    //    ApplyNewConfig(routes, clusters);
    //}

    /// <summary>
    /// Richiamato dal polling service. Carica config e, se diversa, segnala change.
    /// </summary>
    public async Task RefreshAsync(CancellationToken ct)
    {
        try
        {
            await UpdateConfigInternalAsync(ct);

            LastRefreshUtc = DateTimeOffset.UtcNow;
            LastRefreshError = null;
        }
        catch (Exception ex)
        {
            // Suppress transient errors in polling loop, but log them
            LastRefreshError = ex.Message;
            _logger.LogError(ex, "Error during automatic configuration refresh.");
            // Do NOT throw, or the poller might crash
        }
    }

    private void ApplyNewConfig(IReadOnlyList<RouteConfig> routes, IReadOnlyList<ClusterConfig> clusters)
    {
        // Crea un nuovo token per la nuova snapshot
        var newCts = new CancellationTokenSource();
        var newSnapshot = new ProxyConfigSnapshot(routes, clusters, new CancellationChangeToken(newCts.Token));

        // Swap atomico: pubblica nuova snapshot e sostituisce CTS
        var oldCts = Interlocked.Exchange(ref _changeCts, newCts);
        _current = newSnapshot;

        // Notifica YARP: cancella il vecchio token (trigger reload)
        try
        {
            oldCts.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // in pratica non dovrebbe succedere con questo schema, ma non facciamo crashare
        }
        finally
        {
            oldCts.Dispose();
        }

        _logger.LogInformation("YARP config updated. Routes={RouteCount}, Clusters={ClusterCount}",
            routes.Count, clusters.Count);
    }

    // 2) Costruzione config: qui dentro fai discovery + properties
    private async Task<(IReadOnlyList<RouteConfig> routes, IReadOnlyList<ClusterConfig> clusters, 
        List<string> detectedSslHosts)> BuildConfigAsync(CancellationToken ct)
    {
        var routes = new List<RouteConfig>();
        var clusters = new List<ClusterConfig>();
        var detectedSslHosts = new List<string>(); // Allowed hosts for SSL

        // --- TEST ROUTE da properties del gateway (scritte dall'admin endpoint) ---
        var testDestination = await TryGetPropertyAsync(_sfContext.ServiceName, "Yarp.TestDestination", ct);
        var testHost = await TryGetPropertyAsync(_sfContext.ServiceName, "Yarp.TestHost", ct);

        // Elenca le applicazioni
        var apps = await _fabricClient.QueryManager.GetApplicationListAsync();
        // keep a list of SSL-enabled hosts
        var allSSLAllowedHosts = new List<string>();
        foreach (var app in apps)
        {
            ct.ThrowIfCancellationRequested();

            // Elenca i servizi per app
            var services = await _fabricClient.QueryManager.GetServiceListAsync(app.ApplicationName);
            foreach (var svc in services)
            {
                ct.ThrowIfCancellationRequested();

                var settings = await TryGetYarpSettingsFromPropertiesAsync(svc.ServiceName, ct);
                if (settings is null || !settings.Enabled)
                {
                    continue;
                }

                var clusterId = svc.ServiceName.ToString();

                var destinations = await ResolveDestinationsAsync(svc.ServiceName, ct);

                // Se non trovi destinazioni, puoi scegliere:
                // - skip (più sicuro in avvio) oppure
                // - creare cluster vuoto (di solito porta a 503/502)
                if (destinations.Count == 0)
                {
                    _logger.LogWarning("Skipping service {ServiceName}: no destinations resolved.", svc.ServiceName);
                    continue;
                }
                // add hosts to the SSL inventory if needed
                if (settings.SslEnabled && settings.Hosts != null)
                {
                    allSSLAllowedHosts.AddRange(settings.Hosts);
                    foreach (var h in settings.Hosts)
                    {
                        if (!string.IsNullOrWhiteSpace(h))
                            detectedSslHosts.Add(h);
                    }
                }
                // --- CLUSTER CONFIG ---
                var clusterConfig = new ClusterConfig
                {
                    ClusterId = clusterId,
                    Destinations = destinations,
                    // Load Balancing (default RoundRobin se null)
                    LoadBalancingPolicy = settings.LoadBalancingPolicy ?? "RoundRobin",

                    // Session Affinity
                    SessionAffinity = settings.SessionAffinityEnabled
                        ? new SessionAffinityConfig { Enabled = true, Policy = "Cookie", FailurePolicy = "Redistribute" }
                        : null,

                    // Health Checks (Active)
                    HealthCheck = settings.HealthCheckEnabled
                        ? new HealthCheckConfig
                        {
                            Active = new ActiveHealthCheckConfig
                            {
                                Enabled = true,
                                Path = settings.HealthCheckPath ?? "/health",
                                Interval = TimeSpan.FromSeconds(10),
                                Timeout = TimeSpan.FromSeconds(5),
                                Policy = "ConsecutiveFailures"
                            }
                        }
                        : null,
                    // Support forcing HTTP/2 on port 80 to support gRPC without SSL
                    HttpRequest = new ForwarderRequestConfig
                    {
                        ActivityTimeout = TimeSpan.FromSeconds(100),
                        Version = settings.HttpVersion != null ? Version.Parse(settings.HttpVersion) : null,
                        // Se forzi HTTP/2 verso backend in chiaro, serve anche:
                        VersionPolicy = settings.HttpVersion == "2" ? HttpVersionPolicy.RequestVersionExact : HttpVersionPolicy.RequestVersionOrLower
                    }
                };
                clusters.Add(clusterConfig);

                var rateLimitProp = await TryGetPropertyAsync(svc.ServiceName, "Yarp.RateLimit", ct);
                settings.RateLimiterPolicy = rateLimitProp ?? "DefaultPolicy"; // Fallback a Default

                routes.Add(new RouteConfig
                {
                    RouteId = $"{svc.ServiceName.AbsolutePath.Trim('/')}-route",
                    ClusterId = clusterId,
                    Match = new RouteMatch
                    {
                        Hosts = settings.Hosts,               // es. ["api.contoso.com"]
                        Path = settings.Path ?? "/{**catch-all}"
                    },
                    RateLimiterPolicy = settings.RateLimiterPolicy,
                    Order = settings.Order
                });

                //clusters.Add(new ClusterConfig
                //{
                //    ClusterId = clusterId,
                //    Destinations = destinations,
                //    LoadBalancingPolicy = "RoundRobin",
                //    HttpRequest = new ForwarderRequestConfig
                //    {
                //        // niente ActivityContextHeaders (non esiste in 2.3.0)
                //        ActivityTimeout = TimeSpan.FromSeconds(100)
                //    }
                //});
            }
        }



        if (!string.IsNullOrWhiteSpace(testDestination) && !string.IsNullOrWhiteSpace(testHost))
        {
            const string testClusterId = "external-test-cluster";
            routes.Add(new RouteConfig
            {
                RouteId = "external-test-route",
                ClusterId = testClusterId,
                Match = new RouteMatch
                {
                    Hosts = new[] { testHost },        // es. "test.local"
                    Path = "/{**catch-all}"
                },
                Order = -1000 // prima di tutto (se vuoi)
            });

            clusters.Add(new ClusterConfig
            {
                ClusterId = testClusterId,
                Destinations = new Dictionary<string, DestinationConfig>
                {
                    ["d1"] = new DestinationConfig { Address = testDestination }
                }
            });
        }

        // set SSL-allowed hosts list
        _allowedSslHosts.Update(allSSLAllowedHosts);

        //return (routes, clusters);
        return (routes, clusters, detectedSslHosts);
    }

    private async Task<YarpSettings?> TryGetYarpSettingsFromPropertiesAsync(Uri serviceName, CancellationToken ct)
    {
        // Se Yarp.Enable non è true, ignoriamo tutto
        var enabledStr = await TryGetPropertyAsync(serviceName, "Yarp.Enable", ct);
        if (!string.Equals(enabledStr, "true", StringComparison.OrdinalIgnoreCase)) return null;

        var s = new YarpSettings { Enabled = true };

        // Parsing Hosts (CSV)
        var hosts = await TryGetPropertyAsync(serviceName, "Yarp.Hosts", ct);
        s.Hosts = hosts?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? Array.Empty<string>();

        // Altri settings base
        s.Path = await TryGetPropertyAsync(serviceName, "Yarp.Path", ct);
        var orderStr = await TryGetPropertyAsync(serviceName, "Yarp.Order", ct);
        if (int.TryParse(orderStr, out int o)) s.Order = o;

        // Load Balancing
        s.LoadBalancingPolicy = await TryGetPropertyAsync(serviceName, "Yarp.LoadBalancingPolicy", ct);

        // Session Affinity (Yarp.SessionAffinity = true)
        var aff = await TryGetPropertyAsync(serviceName, "Yarp.SessionAffinity", ct);
        s.SessionAffinityEnabled = string.Equals(aff, "true", StringComparison.OrdinalIgnoreCase);

        // Rate Limiting (nome della policy)
        s.RateLimiterPolicy = await TryGetPropertyAsync(serviceName, "Yarp.RateLimitingPolicy", ct);

        // Health Check (Active)
        var hc = await TryGetPropertyAsync(serviceName, "Yarp.HealthCheck.Enabled", ct);
        s.HealthCheckEnabled = string.Equals(hc, "true", StringComparison.OrdinalIgnoreCase);
        s.HealthCheckPath = await TryGetPropertyAsync(serviceName, "Yarp.HealthCheck.Path", ct);

        // http version
        s.HttpVersion = await TryGetPropertyAsync(serviceName, "Yarp.HttpVersion", ct);
        // is SSL requested / enabled?
        var sslVal = await TryGetPropertyAsync(serviceName, "Yarp.Ssl.Enabled", ct);
        s.SslEnabled = string.Equals(sslVal, "true", StringComparison.OrdinalIgnoreCase);

        return s;
    }

    private async Task<string?> TryGetPropertyAsync(Uri serviceName, string propertyName, CancellationToken ct)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            var prop = await _fabricClient.PropertyManager.GetPropertyAsync(serviceName, propertyName);
            return prop?.GetValue<string>();
        }
        catch (FabricElementNotFoundException)
        {
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed reading property {Property} for {ServiceName}", propertyName, serviceName);
            return null;
        }
    }

    private async Task<IReadOnlyDictionary<string, DestinationConfig>> ResolveDestinationsAsync(Uri serviceName, CancellationToken ct)
    {
        var dests = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase);

        try
        {
            // Usa il resolver SF (stateless/singleton: prima partizione; per altri casi si estende)
            var resolver = ServicePartitionResolver.GetDefault();
            var partition = await resolver.ResolveAsync(serviceName, new ServicePartitionKey(), ct);

            foreach (var ep in partition.Endpoints)
            {
                var address = TryExtractHttpAddress(ep.Address);
                if (!string.IsNullOrWhiteSpace(address))
                {
                    // Destination id deve essere stabile? Per ora un guid va bene.
                    dests[Guid.NewGuid().ToString("N")] = new DestinationConfig { Address = address };
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed resolving endpoints for {ServiceName}", serviceName);
        }

        return dests;
    }

    // ep.Address è JSON (string) con endpoints. Qui facciamo un parsing robusto con System.Text.Json.
    private static string? TryExtractHttpAddress(string endpointAddressJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(endpointAddressJson);

            // Formato tipico SF Kestrel listener:
            // { "Endpoints": { "ServiceEndpoint": "http://ip:port/" } }
            if (doc.RootElement.TryGetProperty("Endpoints", out var endpoints) &&
                endpoints.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in endpoints.EnumerateObject())
                {
                    var val = prop.Value.GetString();
                    if (val != null &&
                        (val.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                         val.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                    {
                        return val.EndsWith("/") ? val : (val + "/");
                    }
                }
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    /// <summary>
    /// Rebuild config
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    //public async Task ReloadAsync(CancellationToken ct)
    //{
    //    try
    //    {
    //        ct.ThrowIfCancellationRequested();
    //        var (routes, clusters) = await BuildConfigAsync(ct);
    //        ApplyNewConfig(routes, clusters);
    //        LastRefreshUtc = DateTimeOffset.UtcNow;
    //        LastRefreshError = null;
    //    }
    //    catch (Exception ex)
    //    {
    //        LastRefreshUtc = DateTimeOffset.UtcNow;
    //        LastRefreshError = ex.ToString();
    //        throw;
    //    }
    //}

    /// <summary>
    /// Rebuild config
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    public async Task ReloadAsync(CancellationToken ct)
    {
        try
        {
            await UpdateConfigInternalAsync(ct);

            LastRefreshUtc = DateTimeOffset.UtcNow;
            LastRefreshError = null;
        }
        catch (Exception ex)
        {
            LastRefreshUtc = DateTimeOffset.UtcNow;
            LastRefreshError = ex.ToString();
            _logger.LogError(ex, "Error during manual configuration reload.");
            throw; // Throw here so the Admin API receives the 500 Error
        }
    }

    /// <summary>
    /// Used by RefreshAsync and ReloadAsync to update configuration and handle new SSL domains.
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    private async Task UpdateConfigInternalAsync(CancellationToken ct)
    {
        // 1. Build new config and get detected SSL hosts
        var (routes, clusters, detectedSslHosts) = await BuildConfigAsync(ct);

        // 2. CHECK FOR NEW SSL DOMAINS (The Restart Logic)
        // Compare detected hosts vs what we loaded at Startup
        // var startupSslHosts = _allowedSslHosts.GetAll();
        var detectedSet = new HashSet<string>(detectedSslHosts, StringComparer.OrdinalIgnoreCase);

        // If we found a domain that is NOT in the startup set, we must restart
        if (!detectedSet.IsSubsetOf(_startupSslHosts))
        {
            var newDomains = detectedSet.Except(_startupSslHosts);
            _logger.LogWarning("New SSL Domains detected: {Domains}. Triggering graceful restart...", string.Join(",", newDomains));

            // Trigger Restart in background (Fire-and-forget)
            _ = Task.Run(async () =>
            {
                try
                {
                    // Wait for YARP update to propagate
                    await Task.Delay(TimeSpan.FromSeconds(2));

                    // Stop accepting new connections
                    _appLifetime.StopApplication();

                    // Drain period
                    await Task.Delay(TimeSpan.FromSeconds(5));

                    // Die
                    Environment.Exit(42);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Graceful restart failed. Forcing exit.");
                    Environment.Exit(-1);
                }
            });
        }

        // update the Singleton (so runtime checks pass immediately for the new domain before restart)
        _allowedSslHosts.Update(detectedSslHosts);

        // optimization: Check if YARP config actually changed before swapping
        // (Optional: You can use deep comparison or hash, currently we rely on reference or simply always update)
        // For simplicity/safety with dynamic tokens, we always apply if we got this far.
        ApplyNewConfig(routes, clusters);
    }

    private sealed class YarpSettings
    {
        public bool Enabled { get; set; }
        public IReadOnlyList<string> Hosts { get; set; } = Array.Empty<string>();
        public string? Path { get; set; }
        public int Order { get; set; }

        // Nuovi campi
        public string? LoadBalancingPolicy { get; set; } // es. "LeastRequests"
        public bool SessionAffinityEnabled { get; set; }
        public string? RateLimiterPolicy { get; set; }   // es. "MyFixedWindow"
        public bool HealthCheckEnabled { get; set; }
        public string? HealthCheckPath { get; set; }     // es. "/api/health"
        public string? HttpVersion { get; set; } // "1.1", "2", "3"
        public bool SslEnabled { get; set; }
    }

    // Snapshot immutabile richiesta da YARP: Routes/Clusters + ChangeToken NON nullo
    private sealed class ProxyConfigSnapshot : IProxyConfig
    {
        public ProxyConfigSnapshot(
            IReadOnlyList<RouteConfig> routes,
            IReadOnlyList<ClusterConfig> clusters,
            IChangeToken changeToken)
        {
            Routes = routes ?? Array.Empty<RouteConfig>();
            Clusters = clusters ?? Array.Empty<ClusterConfig>();
            ChangeToken = changeToken ?? throw new ArgumentNullException(nameof(changeToken));
        }

        public IReadOnlyList<RouteConfig> Routes { get; }
        public IReadOnlyList<ClusterConfig> Clusters { get; }
        public IChangeToken ChangeToken { get; }
    }
}