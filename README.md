# Service Fabric Ingress (YARP Gateway)

A production-ready, Service Fabric–native reverse proxy and API gateway for on-premises Windows clusters. It provides Kubernetes-style HTTP/HTTPS ingress—exposing your microservices over a single public endpoint (ports 80/443) with dynamic host/path routing, automated Let's Encrypt SSL, and optional rate limiting.

This project is designed for **standalone / bare-metal Windows Service Fabric clusters** where cloud-native ingress controllers (like Azure App Gateway) are unavailable. It replaces the built-in Service Fabric Reverse Proxy at the edge, offering a secure, tunable, and standards-based entry point for your applications. [web:1480][web:1137]

## Why this exists

Service Fabric's [built-in reverse proxy](https://learn.microsoft.com/en-us/azure/service-fabric/service-fabric-reverseproxy) is an internal routing mechanism, not an edge gateway. It lacks critical perimeter features like automatic SSL termination, host-based routing, and traffic throttling.

**Service Fabric Ingress** fills this gap by wrapping Microsoft's high-performance [YARP](https://microsoft.github.io/reverse-proxy/) library in a stateless service that:
1.  **Shields your cluster:** Closes all ports except 80/443 to the internet.
2.  **Automates Ops:** Discovers routes dynamically from Service Fabric service properties.
3.  **Modernizes Connectivity:** Supports WebSockets, gRPC (over HTTP/2), and SSE out of the box.

## Features

### Core Capabilities
- **Single Entry Point:** Expose multiple services (API, Web, Mobile) via a single public IP on ports 80/443.
- **Dynamic Routing:** Routes are generated automatically by reading `Yarp.*` properties from your backend services. No config files to manage.
- **Automated SSL:** Integrated **Let's Encrypt (ACME)** support via [LettuceEncrypt](https://github.com/natemcmaster/LettuceEncrypt). Certificates are auto-renewed and stored securely.
- **Multi-Protocol:** Full support for HTTP/1.1, HTTP/2, WebSockets (Blazor Server), and Server-Sent Events (SSE).
- **Rate Limiting:** Apply per-service throttling policies (e.g., "Strict" vs "Default") directly from Service Fabric properties. [web:1445]

### Enterprise Hardening
- **Security Defaults:** TLS 1.2/1.3 enforcement, server header removal, aggressive timeouts for slowloris protection. [web:1032]
- **Stealth Mode:** Unknown hosts/routes return a generic 404, minimizing information leakage.
- **Stateless Scale:** Deploy as `InstanceCount = -1` on frontend nodes for linear scalability.

## Architecture

Internet
│
├─ HTTPS (443) ───> [ Service Fabric Ingress ] ───> [ Internal Backend Service ]
│ (Stateless Gateway) (Dynamic Port / No Public Access)
└─ HTTP (80) ─────> [ ACME Challenge Handler ]

The gateway runs on your edge nodes. It continuously monitors the Service Fabric Naming Service. When it detects a service with properties like `Yarp.Hosts` or `Yarp.Path`, it instantly reconfigures its internal routing table to forward traffic to that service's internal endpoints. [web:533]

## Getting Started

### Prerequisites
- Windows Service Fabric Cluster (Standalone or Azure)
- .NET 8+ installed on nodes
- DNS pointed to your cluster IP (for SSL generation)

### Installation

1.  **Clone & Build:**
    ```bash
    git clone https://github.com/yourusername/service-fabric-ingress.git
    # Build and package via Visual Studio or MSBuild
    ```

2.  **Deploy:**
    Deploy the application to your cluster. It will start listening on ports 80 and 443.

3.  **Configure a Backend Service:**
    Add the following properties to any Service Fabric service you want to expose:

    ```powershell
    # Example PowerShell command to expose a service
    Update-ServiceFabricService -ServiceName fabric:/MyApp/MyApi -Stateless -Property @{
        "Yarp.Hosts" = "api.example.com"
        "Yarp.Path" = "/v1/{**catch-all}"
        "Yarp.RateLimit" = "DefaultPolicy"
    }
    ```

    The gateway will pick up these changes immediately and start routing traffic from `https://api.example.com/v1/*` to your service.

## Configuration Reference

The gateway behavior is driven by **Service Properties** on your backend services:

| Property | Description | Example |
| :--- | :--- | :--- |
| `Yarp.Hosts` | Comma-separated list of hostnames to match | `api.app.com,admin.app.com` |
| `Yarp.Path` | URL Path pattern to match | `/api/{**catch-all}` |
| `Yarp.Order` | Route priority (lower number = higher priority) | `1` |
| `Yarp.RateLimit` | Name of the rate limiting policy to apply | `StrictPolicy` |

## Limitations

- **HTTP/3:** Disabled when using Let's Encrypt due to Kestrel technical limitations with ACME TLS callbacks. HTTP/2 is fully supported. [web:1368][web:1366]
- **Stateful Services:** Currently supports Stateless services out-of-the-box. Stateful service routing requires custom partition resolution logic (planned).
- **TCP/UDP:** This is a Layer 7 (HTTP) gateway. For raw TCP/UDP ingress, a separate solution is required.

## Azure Service Fabric Managed Clusters
**Note:** If you are running **Azure Service Fabric Managed Clusters**, you should prefer using Azure-native solutions like [Azure Application Gateway](https://learn.microsoft.com/en-us/azure/service-fabric/how-to-managed-cluster-networking) or Azure Front Door. This project is optimized for scenarios where those managed services are not available (e.g., On-Premises). [web:1327]

## License

Released under **CC0 1.0 Universal** (Public Domain). You are free to use, modify, and distribute this software for any purpose, commercial or private, without attribution.

## Disclaimer

This project is a community-driven open-source initiative and is **not affiliated with or supported by Microsoft**. Use at your own risk.

