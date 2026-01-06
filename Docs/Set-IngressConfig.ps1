<#
.SYNOPSIS
    Configure YARP Ingress properties for a Service Fabric service.
.EXAMPLE
    .\Set-IngressConfig.ps1 -ServiceName fabric:/MyApp/MySvc -Hosts "api.test.com" -Methods "GET,POST" -AddHeaders @{"X-Server"="SF-Node1"}
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$ServiceName,

    [string]$Hosts,           # Es: "api.domain.com"
    [string]$Path = "/{**catch-all}",
    [string]$Methods,         # Es: "GET,POST"
    [string]$RateLimit,       # Es: "DefaultPolicy"
    [switch]$Enable = $true,  # Default true
    
    [hashtable]$AddHeaders,   # Es: @{ "X-Custom" = "123"; "X-Env" = "Prod" }

    [string]$HealthCheckPath, # Es: "/health"
    [switch]$EnableHealthCheck
)

$ErrorActionPreference = "Stop"

# Connessione al cluster (se non già connesso)
try { Get-ServiceFabricClusterConnection | Out-Null } catch { Connect-ServiceFabricCluster }

Write-Host "Configuring properties for: $ServiceName" -ForegroundColor Cyan

# Costruiamo la hashtable delle proprietà da inviare
$properties = @{}

# Proprietà Base
$properties["Yarp.Enable"] = $Enable.ToString().ToLower()
$properties["Yarp.Path"]   = $Path

if (-not [string]::IsNullOrWhiteSpace($Hosts)) { $properties["Yarp.Hosts"] = $Hosts }
if (-not [string]::IsNullOrWhiteSpace($Methods)) { $properties["Yarp.Methods"] = $Methods }
if (-not [string]::IsNullOrWhiteSpace($RateLimit)) { $properties["Yarp.RateLimitingPolicy"] = $RateLimit }

# Health Check
if ($EnableHealthCheck -or -not [string]::IsNullOrWhiteSpace($HealthCheckPath)) {
    $properties["Yarp.HealthCheck.Enabled"] = "true"
    if ($HealthCheckPath) { $properties["Yarp.HealthCheck.Path"] = $HealthCheckPath }
}

# Headers Custom (Itera sulla hashtable passata come parametro)
if ($AddHeaders) {
    foreach ($key in $AddHeaders.Keys) {
        $propKey = "Yarp.Header.$key"
        $properties[$propKey] = $AddHeaders[$key]
        Write-Host "  -> Header aggiunto: $key" -ForegroundColor Gray
    }
}

# ESECUZIONE UPDATE
# Nota: Update-ServiceFabricService richiede le property una per una se usiamo la hashtable integrata, 
# ma purtroppo il comando nativo non supporta facilmente la rimozione o l'aggiornamento massivo dinamico.
# Facciamo un loop.

foreach ($key in $properties.Keys) {
    $val = $properties[$key]
    Write-Host "Setting $key = $val"
    
    # Riprova in caso di conflitti di scrittura
    $retry = 0
    while ($retry -lt 3) {
        try {
            # Usiamo Set-ServiceFabricService (alias improprio) -> Usiamo Update-ServiceFabricService
            # Il comando Update accetta -Property @{ key = val }
            $singleProp = @{}
            $singleProp[$key] = $val
            Update-ServiceFabricService -ServiceName $ServiceName -Stateless -Property $singleProp | Out-Null
            break
        }
        catch {
            $retry++
            Start-Sleep -Milliseconds 500
            if ($retry -eq 3) { Write-Error "Impossibile impostare $key: $_" }
        }
    }
}

Write-Host "Configurazione completata! Il proxy aggiornerà la rotta a breve." -ForegroundColor Green
