//using LettuceEncrypt;
//using Microsoft.Extensions.Logging;
//using System.Diagnostics.CodeAnalysis;

//namespace FabricIngress.SSL;

//public class FileSystemChallengeStore : IHttpChallengeResponseStore
//{
//    private readonly string _basePath;
//    private readonly ILogger _logger;

//    public FileSystemChallengeStore(string basePath, ILogger<FileSystemChallengeStore> logger)
//    {
//        _basePath = basePath;
//        _logger = logger;
//        // Ensure directory exists
//        Directory.CreateDirectory(_basePath);
//    }

//    public Task AddChallengeResponseAsync(string token, string response, CancellationToken cancellationToken)
//    {
//        try
//        {
//            var filePath = Path.Combine(_basePath, token);
//            // Write the challenge response (key authorization) to disk
//            File.WriteAllText(filePath, response);
//            _logger.LogInformation($"Persisted ACME challenge to {filePath}");
//        }
//        catch (Exception ex)
//        {
//            _logger.LogError(ex, "Failed to persist ACME challenge to disk.");
//            throw;
//        }
//        return Task.CompletedTask;
//    }

//    public Task<string?> GetChallengeResponseAsync(string token, CancellationToken cancellationToken)
//    {
//        var filePath = Path.Combine(_basePath, token);
//        if (File.Exists(filePath))
//        {
//            try
//            {
//                return Task.FromResult<string?>(File.ReadAllText(filePath));
//            }
//            catch (Exception ex)
//            {
//                _logger.LogError(ex, $"Failed to read ACME challenge from {filePath}");
//            }
//        }
//        return Task.FromResult<string?>(null);
//    }
//}
