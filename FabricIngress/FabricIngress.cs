using FabricIngress.Logging;
using FabricIngress.SSL;
using LettuceEncrypt;
using LettuceEncrypt.Acme;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Microsoft.ServiceFabric.Services.Communication.AspNetCore;
using Microsoft.ServiceFabric.Services.Communication.Runtime;
using Microsoft.ServiceFabric.Services.Runtime;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;
using System.Diagnostics;
using System.Fabric;
using System.Fabric.Query;
using System.Net;
using System.Reflection;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace ServiceFabricIngress
{
    /// <summary>
    /// The FabricRuntime creates an instance of this class for each service type instance.
    /// </summary>
    internal sealed class FabricIngress : Microsoft.ServiceFabric.Services.Runtime.StatelessService
    {

        public FabricIngress(StatelessServiceContext context)
            : base(context)
        { }

        protected override IEnumerable<ServiceInstanceListener> CreateServiceInstanceListeners()
        {
            return new ServiceInstanceListener[]
            {
                new ServiceInstanceListener(serviceContext =>
                {
                    // 1. PRE-LOAD SSL HOSTS (Blocking Call)
                    // We verify all services in the cluster to build the initial whitelist for ACME Initial Domains.
                    var sslHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var fabricClient = new FabricClient();

                    try
                    {
                        // 1. Get ALL Applications in the cluster
                        // Passing null returns all applications
                        var applications = fabricClient.QueryManager.GetApplicationListAsync().GetAwaiter().GetResult();

                        foreach (var app in applications)
                        {
                            // 2. Query services for THIS application
                            var services = fabricClient.QueryManager.GetServiceListAsync(app.ApplicationName).GetAwaiter().GetResult();

                            foreach (var svc in services)
                            {
                                // 3. Read properties for each service
                                // Using the 3-arg overload (Uri, Bool, Token) for compatibility
                                var props = fabricClient.PropertyManager.EnumeratePropertiesAsync(svc.ServiceName, true, null).GetAwaiter().GetResult();

                                if (props == null) continue;

                                bool sslEnabled = false;
                                string hostsRaw = null;

                                foreach (var p in props)
                                {
                                    var key = p.Metadata.PropertyName;

                                    // Helper to read value safely (Generic Method Reflection)
                                    string val = null;
                                    try
                                    {
                                        var m = p.GetType().GetMethods().FirstOrDefault(x => x.Name == "GetValue" && x.IsGenericMethod);
                                        val = m?.MakeGenericMethod(typeof(string)).Invoke(p, null) as string;
                                    }
                                    catch { /* ignore */ }

                                    if (key == "Yarp.Ssl.Enabled" && string.Equals(val, "true", StringComparison.OrdinalIgnoreCase))
                                        sslEnabled = true;

                                    if (key == "Yarp.Hosts")
                                        hostsRaw = val;
                                }

                                // Add to our startup whitelist if enabled
                                if (sslEnabled && !string.IsNullOrEmpty(hostsRaw))
                                {
                                    var splitHosts = hostsRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                                    foreach (var h in splitHosts) sslHosts.Add(h);
                                }
                            }
                        }
                        ServiceEventSource.Current.ServiceMessage(serviceContext, $"LettuceEncrypt Initial Domains: {string.Join(", ", sslHosts)}");
                    }
                    catch (Exception ex)
                    {
                        ServiceEventSource.Current.ServiceMessage(serviceContext, $"Warning: Failed to pre-load SSL hosts: {ex.Message}");
                    }

                    return new KestrelCommunicationListener(serviceContext, "HttpEndpoint", (url, listener) =>
                    {
                        ServiceEventSource.Current.ServiceMessage(serviceContext, $"Starting Kestrel on {url}");
                        try
                        {
                            return new WebHostBuilder()
                            .UseKestrel(kestrelOptions =>
                                {
                                    var allowedHosts = kestrelOptions.ApplicationServices.GetRequiredService<AllowedSSLHosts>();
                                    // === A. HARDENING & PERFORMANCE ===
                                    kestrelOptions.AddServerHeader = false; // Security: Nasconde "Server: Kestrel"

                                    // Anti-DDoS Limits
                                    kestrelOptions.Limits.MaxRequestBodySize = 10 * 1024 * 1024; // 10MB
                                    kestrelOptions.Limits.MaxRequestLineSize = 8 * 1024; // 8KB
                                    kestrelOptions.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15); // Timeout lento = Drop connection
                                    kestrelOptions.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2); // Tuning Performance

                                    // HTTP/2 Limits (Performance)
                                    kestrelOptions.Limits.Http2.MaxStreamsPerConnection = 1000;
                                    kestrelOptions.Limits.Http2.HeaderTableSize = 4096;

                                    var serviceContext = kestrelOptions.ApplicationServices.GetRequiredService<StatelessServiceContext>();
                                    var endpoints = serviceContext.CodePackageActivationContext.GetEndpoints();
                                    var appServices = kestrelOptions.ApplicationServices;

                                    // A) Configura Porta HTTP (es. 80)
                                    if (endpoints.Contains("HttpEndpoint"))
                                    {
                                        int port = endpoints["HttpEndpoint"].Port;
                                        kestrelOptions.Listen(IPAddress.Any, port, listenOptions =>
                                        {
                                            // Solo HTTP in chiaro (ACME Challenge + Traffico non-SSL)
                                            listenOptions.Protocols = HttpProtocols.Http1; // O Http1AndHttp2 se non usi gRPC in chiaro
                                        });
                                    }

                                    // B) Configura Porta SSL (es. 443)
                                    if (endpoints.Contains("SslEndpoint"))
                                    {
                                        int port = endpoints["SslEndpoint"].Port;
                                        kestrelOptions.Listen(IPAddress.Any, port, listenOptions =>
                                        {
                                            // Enables HTTP/1.1 (Web), HTTP/2 (gRPC/Web)
                                            // Lettuce Encrypt has issues with HTTP/3
                                            listenOptions.Protocols = HttpProtocols.Http1AndHttp2;

                                            listenOptions.UseHttps(https =>
                                            {
                                                // Let's run LettuceEncrypt to let it set its selector
                                                // https.UseLettuceEncrypt(appServices);
                                                // now we intercept the selector and extend it to perform our check
                                                var originalSelector = https.ServerCertificateSelector;
                                                var allowedHosts = appServices.GetRequiredService<AllowedSSLHosts>();
                                                ////// let's replace the selector
                                                https.ServerCertificateSelector = (connectionContext, domain) =>
                                                {
                                                    // here we will check if this host is SSL-enabled
                                                    if (!string.IsNullOrEmpty(domain) && !allowedHosts.Contains(domain))
                                                    {
                                                        // if SSL is not enabled we have two options
                                                        // option 1 : throw an exception (brutal)
                                                        // throw new AuthenticationException($"SSL disabled for {domain}");

                                                        // option 2 : returns null (Kestrel will attempt to use the default cert
                                                        // if no default cert is available, it will fail

                                                        // what we want is to avoid anyone to send a request using a
                                                        // fake domain: that would fail to create the certificate
                                                        // but it will exhaust our LE monthly limits so we need to close
                                                        // the connection

                                                        return null;
                                                    }

                                                    // if this domain/host is SSL-enabled, we follow the chain and
                                                    // call the original selector
                                                    //if (originalSelector != null)
                                                    //    return originalSelector(connectionContext, domain);

                                                    //return null;
                                                    return AcmeCertificateManager.GetCertificate(domain);
                                                };
                                            });
                                        });
                                    }

                                })
                            .ConfigureAppConfiguration((hostingContext, config) =>
                                {
                                    config.AddEnvironmentVariables(); // OTEL_EXPORTER_OTLP_ENDPOINT arriva qui
                                })
                            .ConfigureServices(services =>
                                {
                                    // enable logging
                                    //services.AddLogging(logging =>
                                    //{
                                    //    logging.ClearProviders();
                                    //    logging.AddConsole(); // Allows you to see logs in the console window (if running local/container)
                                    //    logging.AddDebug();   // Allows you to see logs in Visual Studio Output window
                                    //    logging.AddSerilog(dispose: true);

                                    //    // KEY PART: Enable Debug logs for LettuceEncrypt
                                    //    logging.AddFilter("LettuceEncrypt", LogLevel.Debug);

                                    //    // Also useful to see Kestrel's handshake decisions
                                    //    logging.AddFilter("Microsoft.AspNetCore.Server.Kestrel", LogLevel.Debug);
                                    //});
                                    // === LOGGING CHANGE: Setup ===
                                    services.AddLogging(loggingBuilder =>
                                    {
                                        loggingBuilder.ClearProviders();
                                    
                                        // 1. Get Config
                                        var configPkg = serviceContext.CodePackageActivationContext.GetConfigurationPackageObject("Config");
                                        var section = configPkg.Settings.Sections["LettuceEncryptConfig"]; // Assuming settings are here
                                    
                                        // CHANGED: Read string instead of bool. Default to "Fatal" (Off).
                                        string initialLogLevel = "Fatal";
                                        if (section.Parameters.Contains("FileLoggingLevel"))
                                        {
                                            initialLogLevel = section.Parameters["FileLoggingLevel"].Value;
                                        }
                                        else if (section.Parameters.Contains("EnableFileLogging"))
                                        {
                                            // Backwards compatibility: if old boolean param exists
                                            bool.TryParse(section.Parameters["EnableFileLogging"].Value, out bool enabled);
                                            initialLogLevel = enabled ? "Information" : "Fatal";
                                        }
                                        // 2. Determine Paths and Names
                                        // Use the same path as Certs (or a specific LogPath parameter)
                                        var certPath = Environment.GetEnvironmentVariable("FabricIngress_CertPath") ?? @"C:\SFCertificates";
                                        Directory.CreateDirectory(certPath);

                                        // Get Node Name (Sanitize it just in case, though SF node names are usually safe)
                                        var nodeName = serviceContext.NodeContext.NodeName.Replace(":", "_").Replace("/", "_");
                                    
                                        // Filename pattern: C:\SFCertificates\ingress_Node1_20260106.log
                                        var logFileName = Path.Combine(certPath, $"ingress_{nodeName}_.log");

                                        // 3. Initialize Control Switch
                                        var loggingControl = new LoggingControl(initialLogLevel);
                                        services.AddSingleton(loggingControl);

                                        // 4. Configure Serilog
                                        var loggerConfig = new LoggerConfiguration()
                                            .MinimumLevel.Debug() // Global minimum (allows Debug to flow to sinks if they want it)
                                            .Enrich.FromLogContext()
                                            .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}");

                                        loggerConfig.WriteTo.File(
                                            path: logFileName,
                                            rollingInterval: RollingInterval.Day,
                                            retainedFileCountLimit: 7,
                                            levelSwitch: loggingControl.FileSwitch, // <--- Controls Debug/Info/Fatal dynamically
                                            outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}"
                                        );

                                        var logger = loggerConfig.CreateLogger();
                                        loggingBuilder.AddSerilog(logger, dispose: true);

                                        // Filters
                                        // loggingBuilder.AddFilter("LettuceEncrypt", LogLevel.Debug);
                                        services.AddHostedService<AcmeCertificateManager>();
                                        loggingBuilder.AddFilter("Microsoft.AspNetCore.Server.Kestrel", LogLevel.Debug);
                                    });


                                    services.AddSingleton<StatelessServiceContext>(serviceContext);
                                    // Get Service Fabric context and config
                                    var config = serviceContext.CodePackageActivationContext.GetConfigurationPackageObject("Config");

                                    // Extrapolate settings from relevant section of Settings.xml
                                    var section = config.Settings.Sections["LettuceEncryptConfig"];
                                    string email = section.Parameters["EmailAddress"].Value;
                                    bool acceptTerms = bool.Parse(section.Parameters["AcceptTermsOfService"].Value);
                                    // this should not be here for maximum security. We will keep it here
                                    // to make deployments easier but it should be improved by using Service Fabric secrets
                                    string password = section.Parameters["PfxPassword"].Value;
                                    // === C. RATE LIMITING SERVICES ===
                                    // Definisci le "Policy" che i servizi SF potranno scegliere tramite property
                                    services.AddRateLimiter(options =>
                                    {
                                        // Policy Default (se nessuna specificata)
                                        options.AddFixedWindowLimiter("DefaultPolicy", opt =>
                                        {
                                            opt.PermitLimit = 1000;
                                            opt.Window = TimeSpan.FromMinutes(1);
                                            opt.QueueLimit = 20;
                                        });

                                        options.AddFixedWindowLimiter("FixedWindowPolicy", opt =>
                                        {
                                            opt.PermitLimit = 100;
                                            opt.Window = TimeSpan.FromMinutes(1);
                                        });

                                        // Policy "Strict" (es. per API pesanti)
                                        options.AddFixedWindowLimiter("StrictPolicy", opt =>
                                        {
                                            opt.PermitLimit = 50;
                                            opt.Window = TimeSpan.FromMinutes(1);
                                            opt.QueueLimit = 0;
                                        });

                                        // Gestione Rejection (429 Too Many Requests)
                                        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                                    });

                                    services.AddSingleton<StatelessServiceContext>(serviceContext);
                                    services.AddSingleton<IProxyConfigProvider, ServiceFabricPropertyConfigProvider>();
                                    services.AddSingleton<StatelessServiceContext>(serviceContext);

                                    services.AddSingleton<ServiceFabricPropertyConfigProvider>();
                                    services.AddSingleton<IProxyConfigProvider>(sp => sp.GetRequiredService<ServiceFabricPropertyConfigProvider>());
                                    services.AddHostedService<ServiceFabricDiscoveryHostedService>();
                                    services.AddSingleton<AllowedSSLHosts>(new AllowedSSLHosts());

                                    // Health checks
                                    services.AddHealthChecks();

                                    // Registra il nostro provider dinamico basato su Properties
                                    // services.AddSingleton<IProxyConfigProvider, ServiceFabricPropertyConfigProvider>();

                                    // LettuceEncrypt (Automatic SSL)
                                    var certPath = Environment.GetEnvironmentVariable("FabricIngress_CertPath") ?? @"C:\SFCertificates";
                                    Directory.CreateDirectory(certPath);

                                    services.AddReverseProxy()
                                            .ConfigureHttpClient((context, handler) =>
                                            {
                                                // “Preserve tracing”: YARP reinietta gli header di tracing per l’hop successivo
                                                handler.ActivityHeadersPropagator =
                                                    new ReverseProxyPropagator(DistributedContextPropagator.Current);
                                            });

                                    // config
                                    const string serviceName = "yarp-gateway";
                                    var otlpEndpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");

                                    //services.AddLettuceEncrypt(options =>
                                    //{
                                    //    options.EmailAddress = email;
                                    //    options.AcceptTermsOfService = acceptTerms;
                                    //    options.AllowedChallengeTypes = ChallengeType.Http01; // accept HTTP connections only
                                    //})
                                    //services.AddLettuceEncrypt(options =>
                                    //{
                                    //   options.DomainNames = sslHosts.ToArray();
                                    //   options.AcceptTermsOfService = true;
                                    //   options.EmailAddress = email;
                                    //   options.AllowedChallengeTypes = ChallengeType.Http01; // accept HTTP connections only
                                    //})
                                    //.PersistDataToDirectory(new DirectoryInfo(certPath), password);

                                    // register the Singleton for the Runtime Watcher to compare against
                                    services.AddSingleton(new AllowedSSLHosts(sslHosts));

                                    services.AddOpenTelemetry()
                                    .ConfigureResource(r => r.AddService(serviceName))
                                    .WithTracing(tracing =>
                                    {
                                        tracing
                                            .AddAspNetCoreInstrumentation()
                                            .AddHttpClientInstrumentation()
                                            .AddSource("Yarp.ReverseProxy"); // activity source di YARP

                                        // Feature flag: esporta solo se configurato
                                        if (!string.IsNullOrWhiteSpace(otlpEndpoint))
                                        {
                                            tracing.AddOtlpExporter(); // usa OTEL_EXPORTER_OTLP_* env vars/standard config [web:797][web:801]
                                        }
                                    });
                                    //// rate limiting policy(ies)
                                    //services.AddRateLimiter(options => {
                                    //    options.AddFixedWindowLimiter("FixedWindowPolicy", opt => {
                                    //        opt.PermitLimit = 100;
                                    //        opt.Window = TimeSpan.FromMinutes(1);
                                    //    });
                                    //});
                                })
                            .Configure(app =>
                                {
                                    // enable rate limiting
                                    app.UseRateLimiter();
                                    app.UseRouting();
                                    app.Use(async (context, next) =>
                                    {
                                        await next(); // Lascia provare YARP

                                        // Se YARP non ha trovato nulla (404) E non abbiamo servito contenuto
                                        if (context.Response.StatusCode == 404 && !context.Response.HasStarted)
                                        {
                                            // Opzione A: Ritorna 404 pulito (Consigliato)
                                            context.Response.ContentType = "text/plain";
                                            await context.Response.WriteAsync("Not Found");

                                            // Opzione B: Abort Connection (Stealth Mode)
                                            // context.Abort(); 
                                        }
                                    });
                                    app.UseEndpoints(endpoints =>
                                    {
                                        // check if request is local
                                        static bool IsLocal(HttpContext ctx)
                                        {
                                            var ip = ctx.Connection.RemoteIpAddress;
                                            return ip != null && IPAddress.IsLoopback(ip);
                                        }
                                        // Endpoint admin SOLO DEV/LOCAL
                                        endpoints.MapPost("/_admin/set-test-route", async context =>
                                        {
                                            // Consenti solo da localhost (IPv4/IPv6)
                                            var remoteIp = context.Connection.RemoteIpAddress;
                                            var isLocal = remoteIp != null && IPAddress.IsLoopback(remoteIp);

                                            // Se non sei in locale, blocca
                                            if (!isLocal)
                                            {
                                                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                                                await context.Response.WriteAsync("Forbidden");
                                                return;
                                            }

                                            // Leggi payload JSON: { "destination": "http://localhost:5055/", "host": "test.local" }
                                            var body = await context.Request.ReadFromJsonAsync<SetTestRouteRequest>();
                                            if (body is null || string.IsNullOrWhiteSpace(body.destination) || string.IsNullOrWhiteSpace(body.host))
                                            {
                                                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                                                await context.Response.WriteAsync("Invalid payload");
                                                return;
                                            }

                                            // Nome del servizio *gateway* (quello dove vuoi salvare le properties)
                                            // Idealmente passalo da DI; qui lo ricaviamo dalla variabile chiusa serviceContext.
                                            var gatewayServiceName = serviceContext.ServiceName;

                                            var fc = new FabricClient();

                                            await fc.PropertyManager.PutPropertyAsync(gatewayServiceName, "Yarp.TestDestination", body.destination);
                                            await fc.PropertyManager.PutPropertyAsync(gatewayServiceName, "Yarp.TestHost", body.host);

                                            await context.Response.WriteAsJsonAsync(new
                                            {
                                                ok = true,
                                                service = gatewayServiceName.ToString(),
                                                destination = body.destination,
                                                host = body.host
                                            });
                                        });
                                        endpoints.MapPost("/_admin/clear-test-route", async context =>
                                        {
                                            var remoteIp = context.Connection.RemoteIpAddress;
                                            if (remoteIp is null || !System.Net.IPAddress.IsLoopback(remoteIp))
                                            {
                                                context.Response.StatusCode = 403;
                                                await context.Response.WriteAsync("Forbidden");
                                                return;
                                            }

                                            var fc = new FabricClient();
                                            var name = serviceContext.ServiceName;

                                            // Cancella le properties (se non esistono, puoi ignorare l’eccezione)
                                            try { await fc.PropertyManager.DeletePropertyAsync(name, "Yarp.TestDestination"); } catch { }
                                            try { await fc.PropertyManager.DeletePropertyAsync(name, "Yarp.TestHost"); } catch { }

                                            await context.Response.WriteAsJsonAsync(new { ok = true });
                                        });
                                        // health checks
                                        endpoints.MapHealthChecks("/_admin/health");
                                        // _admin/config (GET)
                                        endpoints.MapGet("/_admin/config", async ctx =>
                                        {
                                            if (!IsLocal(ctx)) { ctx.Response.StatusCode = 403; return; }

                                            var provider = ctx.RequestServices.GetRequiredService<ServiceFabricPropertyConfigProvider>();
                                            var cfg = provider.GetConfig(); // IProxyConfig

                                            var payload = new
                                            {
                                                routes = cfg.Routes.Select(r => new
                                                {
                                                    r.RouteId,
                                                    r.ClusterId,
                                                    hosts = r.Match?.Hosts,
                                                    path = r.Match?.Path,
                                                    r.Order
                                                }),
                                                clusters = cfg.Clusters.Select(c => new
                                                {
                                                    c.ClusterId,
                                                    destinations = c.Destinations?.Select(d => new { id = d.Key, address = d.Value.Address })
                                                }),
                                                providerStatus = new
                                                {
                                                    provider.LastRefreshUtc,
                                                    provider.LastRefreshError
                                                }
                                            };

                                            await ctx.Response.WriteAsJsonAsync(payload);
                                        });
                                        // _admin/version (GET)
                                        endpoints.MapGet("/_admin/version", async ctx =>
                                        {
                                            if (!IsLocal(ctx)) { ctx.Response.StatusCode = 403; return; }

                                            var asm = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
                                            var ver = asm.GetName().Version?.ToString();

                                            await ctx.Response.WriteAsJsonAsync(new
                                            {
                                                service = "FabricIngress",
                                                version = ver,
                                                framework = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
                                                process = Environment.ProcessId
                                            });
                                        });
                                        // /_admin/reload (POST) - force immediate refresh of config
                                        endpoints.MapPost("/_admin/reload", async ctx =>
                                        {
                                            if (!IsLocal(ctx)) { ctx.Response.StatusCode = 403; return; }

                                            var provider = ctx.RequestServices.GetRequiredService<ServiceFabricPropertyConfigProvider>();

                                            try
                                            {
                                                await provider.ReloadAsync(ctx.RequestAborted);
                                                ctx.Response.StatusCode = 200;
                                                await ctx.Response.WriteAsJsonAsync(new { ok = true, provider.LastRefreshUtc });
                                            }
                                            catch (Exception ex)
                                            {
                                                ctx.Response.StatusCode = 500;
                                                await ctx.Response.WriteAsJsonAsync(new { ok = false, error = ex.Message });
                                            }
                                        });
                                        // /_admin/trace (GET) - shows if OpenTelemetry is configured/active (no secrets)
                                        endpoints.MapGet("/_admin/trace", async ctx =>
                                        {
                                            if (!IsLocal(ctx)) { ctx.Response.StatusCode = 403; return; }

                                            // Legge config/env var: qui assumiamo che tu abbia AddEnvironmentVariables nella config host,
                                            // altrimenti usa Environment.GetEnvironmentVariable direttamente.
                                            var config = ctx.RequestServices.GetRequiredService<IConfiguration>();

                                            var endpoint = config["OTEL_EXPORTER_OTLP_ENDPOINT"]
                                                           ?? Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");

                                            // Maschera endpoint (evita di esporre host interni completi in chiaro)
                                            string? masked = null;
                                            if (!string.IsNullOrWhiteSpace(endpoint))
                                            {
                                                masked = endpoint.Length <= 12 ? "***" : endpoint.Substring(0, 12) + "...";
                                            }

                                            await ctx.Response.WriteAsJsonAsync(new
                                            {
                                                openTelemetry = new
                                                {
                                                    otlpEndpointConfigured = !string.IsNullOrWhiteSpace(endpoint),
                                                    otlpEndpointMasked = masked,
                                                    note = "If configured, gateway exports spans via OTLP exporter"
                                                }
                                            });
                                        });
                                        // === LOGGING CHANGE: Admin Route ===
                                        // POST /_admin/logging?level=debug
                                        endpoints.MapPost("/_admin/logging", async ctx =>
                                        {
                                            if (!IsLocal(ctx)) { ctx.Response.StatusCode = 403; return; }

                                            var control = ctx.RequestServices.GetRequiredService<LoggingControl>();

                                            // Check "level" query param
                                            if (ctx.Request.Query.TryGetValue("level", out var levelStr))
                                            {
                                                control.SetLevel(levelStr);

                                                await ctx.Response.WriteAsJsonAsync(new
                                                {
                                                    ok = true,
                                                    currentLevel = control.GetCurrentLevel(),
                                                    message = $"File logging level set to {control.GetCurrentLevel()}"
                                                });
                                            }
                                            else
                                            {
                                                // Just return current status
                                                await ctx.Response.WriteAsJsonAsync(new
                                                {
                                                    ok = true,
                                                    currentLevel = control.GetCurrentLevel(),
                                                    supportedLevels = new[] { "Debug", "Information", "Fatal" }
                                                });
                                            }
                                        });
                                        // SSL ACME challenge
                                        endpoints.MapGet("/.well-known/acme-challenge/{token}", async context =>
                                        {
                                            var token = context.GetRouteValue("token") as string;
                                        
                                            // Must match AcmeCertificateManager path
                                            var certPath = Environment.GetEnvironmentVariable("FabricIngress_CertPath") ?? @"C:\SFCertificates";
                                            var filePath = Path.Combine(certPath, token);

                                            // Security: Alphanumeric only
                                            if (string.IsNullOrWhiteSpace(token) || token.Any(c => !char.IsLetterOrDigit(c) && c != '-' && c != '_'))
                                            {
                                                context.Response.StatusCode = 404; return;
                                            }

                                            if (File.Exists(filePath))
                                            {
                                                var content = await File.ReadAllTextAsync(filePath);
                                                context.Response.ContentType = "application/octet-stream";
                                                await context.Response.WriteAsync(content);
                                            }
                                            else
                                            {
                                                context.Response.StatusCode = 404;
                                            }
                                        });
                                        // app.UseRateLimiter();
                                        endpoints.MapReverseProxy();
                                    });
                                })
                                .UseServiceFabricIntegration(listener, ServiceFabricIntegrationOptions.None)
                                .UseUrls(url)
                                .Build();
                        }
                        catch (Exception ex)
                        {
                            ServiceEventSource.Current.ServiceMessage(serviceContext, $"Error starting Kestrel: {ex.ToString()}");
                            throw;
                        }
                    }); //)
                })
            };
        }
    }
}

internal sealed record SetTestRouteRequest(string destination, string host);


