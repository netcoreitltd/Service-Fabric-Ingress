namespace FabricIngress.SSL;

public class AllowedSSLHosts
{
    // volatile/lock non strettamente necessari per letture atomiche di reference, 
    // ma un lock è più sicuro per gli aggiornamenti massivi.
    private HashSet<string> _hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new object();

    // constructor for Startup Initialization
    public AllowedSSLHosts(IEnumerable<string> initialHosts)
    {
        // Initialize the HashSet with the startup list
        _hosts = new HashSet<string>(initialHosts ?? Enumerable.Empty<string>(), StringComparer.OrdinalIgnoreCase);
    }

    // default Constructor (if used by DI without args somewhere else, though unlikely now)
    public AllowedSSLHosts()
    {
        _hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    //public void Update(IEnumerable<string> hosts)
    //{
    //    lock (_lock)
    //    {
    //        _hosts = new HashSet<string>(hosts, StringComparer.OrdinalIgnoreCase);
    //    }
    //}

    public void Update(IEnumerable<string> hosts)
    {
        lock (_lock)
        {
            _hosts.Clear();
            if (hosts != null)
            {
                foreach (var h in hosts) _hosts.Add(h);
            }
        }
    }

    public IEnumerable<string> GetAll()
    {
        lock (_lock)
        {
            return _hosts.ToArray();
        }
    }

    public bool Contains(string host)
    {
        if (host == null) return false;
        lock (_lock) return _hosts.Contains(host);
    }

}
