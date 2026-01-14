using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Fabric;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FabricIngress.SSL;

public class AcmeCertificateManager : BackgroundService
{
    private readonly ILogger<AcmeCertificateManager> _logger;
    private readonly AllowedSSLHosts _allowedHosts;
    private readonly string _certPath;
    private readonly string _email;
    private readonly string _pfxPassword;
    private FileSystemWatcher? _fileWatcher;

    // Thread-safe cache: Key = Domain (SNI), Value = Certificate
    private static readonly ConcurrentDictionary<string, X509Certificate2> _certCache = new(StringComparer.OrdinalIgnoreCase);

    public AcmeCertificateManager(
        ILogger<AcmeCertificateManager> logger,
        AllowedSSLHosts allowedHosts,
        StatelessServiceContext context)
    {
        _logger = logger;
        _allowedHosts = allowedHosts;

        // Read Config
        var configPkg = context.CodePackageActivationContext.GetConfigurationPackageObject("Config");
        var section = configPkg.Settings.Sections["LettuceEncryptConfig"];

        _email = section.Parameters["EmailAddress"].Value;
        _pfxPassword = section.Parameters["PfxPassword"].Value;

        // Shared Storage Path (Crucial for Multi-Server!)
        _certPath = Environment.GetEnvironmentVariable("FabricIngress_CertPath") ?? @"C:\SFCertificates";
        System.IO.Directory.CreateDirectory(_certPath);

        // Start Monitoring
        SetupFileSystemWatcher();
    }

    private void SetupFileSystemWatcher()
    {
        try
        {
            _fileWatcher = new FileSystemWatcher(_certPath, "*.pfx");
            _fileWatcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime;
            _fileWatcher.Changed += OnCertificateFileUpdated;
            _fileWatcher.Created += OnCertificateFileUpdated;
            _fileWatcher.Renamed += OnCertificateFileUpdated;
            _fileWatcher.Deleted += OnCertificateFileDeleted;
            _fileWatcher.EnableRaisingEvents = true;
            _logger.LogInformation("Monitoring certificate changes in {Path}", _certPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to initialize FileSystemWatcher. Auto-reload will not work.");
        }
    }

    private void OnCertificateFileDeleted(object sender, FileSystemEventArgs e)
    {
        var domain = Path.GetFileNameWithoutExtension(e.Name);
        if (_certCache.TryRemove(domain, out _))
        {
            _logger.LogInformation("Certificate file deleted. Removed {Domain} from cache. Renewal will occur on next loop.", domain);
        }
    }

    private void OnCertificateFileUpdated(object sender, FileSystemEventArgs e)
    {
        _logger.LogInformation("Detected certificate change on disk: {File}", e.Name);
        // Delay slightly to allow writer to release lock
        Task.Run(async () =>
        {
            await Task.Delay(500);
            LoadCertificateFromFile(e.FullPath);
        });
    }

    // Kestrel calls this via the Selector
    public static X509Certificate2? GetCertificate(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return null;
        _certCache.TryGetValue(domain, out var cert);
        return cert;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ACME Manager Started.");

        LoadAllCertificates();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAndRenewCertificates(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in ACME renewal loop.");
            }
            // Check every 6 hours
            await Task.Delay(TimeSpan.FromHours(6), stoppingToken);
        }
    }

    public override void Dispose()
    {
        _fileWatcher?.Dispose();
        base.Dispose();
    }

    private void LoadAllCertificates()
    {
        try
        {
            var files = System.IO.Directory.GetFiles(_certPath, "*.pfx");
            foreach (var file in files) LoadCertificateFromFile(file);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading certificates from disk.");
        }
    }

    //private void LoadCertificateFromFile(string filePath)
    //{
    //    int retries = 3;
    //    while (retries > 0)
    //    {
    //        try
    //        {
    //            var domain = Path.GetFileNameWithoutExtension(filePath);
    //            var cert = new X509Certificate2(filePath, _pfxPassword,
    //                X509KeyStorageFlags.MachineKeySet |
    //                X509KeyStorageFlags.PersistKeySet |
    //                X509KeyStorageFlags.Exportable);
    //            // var cert = new X509Certificate2(filePath, _pfxPassword, X509KeyStorageFlags.EphemeralKeySet);

    //            if (cert.NotAfter > DateTime.UtcNow)
    //            {
    //                _certCache[domain] = cert;
    //                _logger.LogInformation("Loaded certificate for {Domain} [Expires: {Date}]", domain, cert.NotAfter);
    //            }
    //            else
    //            {
    //                _logger.LogWarning("Certificate for {Domain} is expired. Ignoring.", domain);
    //            }
    //            return;
    //        }
    //        catch (IOException)
    //        {
    //            retries--;
    //            Thread.Sleep(500);
    //        }
    //        catch (Exception ex)
    //        {
    //            _logger.LogWarning("Failed to load {File}: {Message}", filePath, ex.Message);
    //            return;
    //        }
    //    }
    //}

    //private void LoadCertificateFromFile(string filePath)
    //{
    //    int retries = 3;
    //    while (retries > 0)
    //    {
    //        try
    //        {
    //            var domain = Path.GetFileNameWithoutExtension(filePath);

    //            // CRITICAL: All three flags are mandatory
    //            var cert = new X509Certificate2(
    //                filePath,
    //                _pfxPassword,
    //                X509KeyStorageFlags.MachineKeySet |
    //                X509KeyStorageFlags.PersistKeySet |
    //                X509KeyStorageFlags.Exportable
    //            );

    //            // DIAGNOSTIC: Check if private key is present
    //            if (!cert.HasPrivateKey)
    //            {
    //                _logger.LogError("Certificate for {Domain} loaded, but has no private key!", domain);
    //                return;
    //            }

    //            if (cert.NotAfter > DateTime.UtcNow)
    //            {
    //                _certCache[domain] = cert;
    //                _logger.LogInformation("Loaded certificate for {Domain} [Expires: {Date}] [HasPrivateKey: {HasKey}]",
    //                    domain, cert.NotAfter, cert.HasPrivateKey);
    //            }
    //            else
    //            {
    //                _logger.LogWarning("Certificate for {Domain} is expired. Ignoring.", domain);
    //            }
    //            return;
    //        }
    //        catch (System.Security.Cryptography.CryptographicException ex)
    //        {
    //            _logger.LogError(ex, "Cryptographic error loading {File}. Is the password correct?", filePath);
    //            return;
    //        }
    //        catch (IOException)
    //        {
    //            retries--;
    //            Thread.Sleep(500);
    //        }
    //        catch (Exception ex)
    //        {
    //            _logger.LogWarning(ex, "Failed to load {File}", filePath);
    //            return;
    //        }
    //    }
    //}

    private void LoadCertificateFromFile(string filePath)
    {
        int retries = 5;
        while (retries-- > 0)
        {
            try
            {
                var domain = Path.GetFileNameWithoutExtension(filePath);

                // 1) Leggi il PFX da SMB in memoria
                var pfxBytes = File.ReadAllBytes(filePath);

                // 2) Import “machine + persist” (necessario per SChannel in questo contesto)
                //var flags =
                //    X509KeyStorageFlags.MachineKeySet |
                //    X509KeyStorageFlags.PersistKeySet |
                //    X509KeyStorageFlags.Exportable;

                var flags =
                    X509KeyStorageFlags.UserKeySet |
                    X509KeyStorageFlags.PersistKeySet |
                    X509KeyStorageFlags.Exportable;

                var cert = new X509Certificate2(pfxBytes, _pfxPassword, flags);

                // Diagnostica utile
                var rsa = cert.GetRSAPrivateKey();
                _logger.LogInformation(
                    "Loaded certificate for {Domain} [Expires: {NotAfter}] [HasPrivateKey: {HasKey}] [KeyType: {KeyType}]",
                    domain, cert.NotAfter, cert.HasPrivateKey, rsa?.GetType().FullName);

                if (!cert.HasPrivateKey)
                {
                    _logger.LogError("Certificate for {Domain} has NO private key after import.", domain);
                    return;
                }

                if (cert.NotAfter <= DateTime.UtcNow)
                {
                    _logger.LogWarning("Certificate for {Domain} is expired. Ignoring.", domain);
                    return;
                }

                _certCache[domain] = cert;
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(500);
            }
            catch (CryptographicException ex)
            {
                _logger.LogError(ex, "Cryptographic error loading PFX {File}. Password/format/keystore issue.", filePath);
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error loading PFX {File}.", filePath);
                return;
            }
        }
    }


    private async Task CheckAndRenewCertificates(CancellationToken ct)
    {
        var domains = _allowedHosts.GetAll().Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (!domains.Any()) return;

        var acme = new AcmeContext(WellKnownServers.LetsEncryptV2); // Use LetsEncryptStagingV2 for testing!
        try
        {
            // 1. MUST Register the Account successfully.
            // If this fails, we cannot proceed with Orders.
            _logger.LogInformation("Registering ACME account for {Email}...", _email);
            await acme.NewAccount(_email, true);
        }
        catch (Exception ex)
        {
            // If registration fails, STOP. Do not try to Order certs.
            _logger.LogError(ex, "Failed to register ACME account. Cannot renew certificates.");
            return; // <--- Critical: Exit here.
        }

        foreach (var domain in domains)
        {
            if (ct.IsCancellationRequested) break;

            if (_certCache.TryGetValue(domain, out var existingCert))
            {
                // Renew only if < 30 days remaining
                if (existingCert.NotAfter > DateTime.UtcNow.AddDays(30)) continue;
            }

            try
            {
                _logger.LogInformation("Renewing certificate for {Domain}...", domain);
                await RenewSingleDomainAsync(acme, domain, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to renew certificate for {Domain}", domain);
            }
        }
    }

    private async Task RenewSingleDomainAsync(AcmeContext acme, string domain, CancellationToken ct)
    {
        var order = await acme.NewOrder(new[] { domain });
        var authzList = await order.Authorizations();

        foreach (var authz in authzList)
        {
            var httpChallenge = await authz.Http();
            var keyAuth = httpChallenge.KeyAuthz;
            var token = httpChallenge.Token;

            // 1. Write Challenge to SHARED Disk
            var challengeFile = Path.Combine(_certPath, token);
            await File.WriteAllTextAsync(challengeFile, keyAuth, ct);

            try
            {
                // 2. Trigger Validation (Let's Encrypt will hit the Load Balancer -> Any Node)
                await httpChallenge.Validate();

                // 3. Poll Status
                while (true)
                {
                    var status = await authz.Resource();
                    if (status.Status == AuthorizationStatus.Valid) break;
                    if (status.Status == AuthorizationStatus.Invalid) throw new Exception($"Validation failed: {status.Challenges.FirstOrDefault()?.Error?.Detail}");
                    await Task.Delay(1000, ct);
                }
            }
            finally
            {
                if (File.Exists(challengeFile)) File.Delete(challengeFile);
            }
        }

        // 4. Generate & Save PFX
        //var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
        var privateKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
        var certChain = await order.Generate(new CsrInfo(), privateKey);
        var pfxBuilder = certChain.ToPfx(privateKey);
        var pfxBytes = pfxBuilder.Build("FabricIngress", _pfxPassword);

        var pfxPath = Path.Combine(_certPath, $"{domain}.pfx");

        // Writing this file triggers FileSystemWatcher on ALL nodes!
        await File.WriteAllBytesAsync(pfxPath, pfxBytes, ct);

        // Load locally immediately
        LoadCertificateFromFile(pfxPath);
    }
}