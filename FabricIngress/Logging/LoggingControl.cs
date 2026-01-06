using Serilog.Core;
using Serilog.Events;

namespace FabricIngress.Logging;

public class LoggingControl
{
    public LoggingLevelSwitch FileSwitch { get; }

    public LoggingControl(string initialLevel)
    {
        FileSwitch = new LoggingLevelSwitch(ParseLevel(initialLevel));
    }

    public void SetLevel(string levelName)
    {
        FileSwitch.MinimumLevel = ParseLevel(levelName);
    }

    public string GetCurrentLevel()
    {
        return FileSwitch.MinimumLevel.ToString();
    }

    private LogEventLevel ParseLevel(string levelName)
    {
        // Default to Fatal (Off) if invalid
        if (string.IsNullOrWhiteSpace(levelName)) return LogEventLevel.Fatal;

        return levelName.ToLowerInvariant() switch
        {
            "debug" => LogEventLevel.Debug,
            "info" => LogEventLevel.Information,
            "information" => LogEventLevel.Information,
            "fatal" => LogEventLevel.Fatal,
            "off" => LogEventLevel.Fatal, // Alias for clear intent
            _ => LogEventLevel.Fatal
        };
    }
}
