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

    public void SetLevel(string levelName) => FileSwitch.MinimumLevel = ParseLevel(levelName);

    public string GetCurrentLevel() => FileSwitch.MinimumLevel.ToString();

    private LogEventLevel ParseLevel(string levelName)
    {
        if (string.IsNullOrWhiteSpace(levelName)) return LogEventLevel.Fatal;
        return levelName.ToLowerInvariant() switch
        {
            "debug" => LogEventLevel.Debug,
            "info" or "information" => LogEventLevel.Information,
            "fatal" or "off" => LogEventLevel.Fatal,
            _ => LogEventLevel.Fatal
        };
    }
}
