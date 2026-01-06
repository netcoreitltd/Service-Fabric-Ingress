namespace FabricIngress.SSL;

public class AllowedSSLHosts
{
    // volatile/lock non strettamente necessari per letture atomiche di reference, 
    // ma un lock è più sicuro per gli aggiornamenti massivi.
    private HashSet<string> _hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new object();

    public void Update(IEnumerable<string> hosts)
    {
        lock (_lock)
        {
            _hosts = new HashSet<string>(hosts, StringComparer.OrdinalIgnoreCase);
        }
    }

    public bool Contains(string host)
    {
        if (host == null) return false;
        lock (_lock) return _hosts.Contains(host);
    }
}
