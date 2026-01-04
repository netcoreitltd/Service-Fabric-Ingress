# How to test on a Single-node ASF Dev Machine

A special configuration allows you to test **FabricIngress** on a local dev/test machine to ensure that the software is functioning correctly.

`{assignedport}` represents the HTTP port you assigned to __FabricIngress__.

### Create a Test Backend Project

Execute the following commands in PowerShell to set up a local backend service:

```powershell
mkdir C:\Test
cd C:\Test
dotnet new web -n TestBackend
dotnet run --project .\TestBackend --urls http://localhost:5055
```

### Set Up FabricIngress to Route Local Connections

While keeping the backend project running, enable the **FabricIngress** special test mode by running the following PowerShell commands. This configuration routes traffic from a custom host name to your local backend.

```powershell
$body = @{ destination = "http://localhost:5055/"; host = "test.local" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://localhost:{assignedport}/_admin/set-test-route" -Body $body -ContentType "application/json"
```

This enables test mode for the `test.local` host and forwards connections to the `http://localhost:5055/` URL. 

**Note:** This special mode is only enabled for _localhost_ connections. Your request must be sent from the same machine where **FabricIngress** is running.

### Invoke the Service Using the Host Header

Test the routing using `curl` to simulate a request to the `test.local` host:

```powershell
curl.exe -i -H "Host: test.local" "http://localhost:{assignedport}/"
```

After verifying that the response is **"Hello World!"**, you can proceed to disable and clear the test route.

### Clearing the Test Route

To disable the special test mode and clear the routing entry, issue the following PowerShell command:

```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:{assignedport}/_admin/clear-test-route"
```

If you receive an **OK** response, the special test mode has been disabled. 

**Important:** Synchronization occurs approximately every 30 seconds; you might still receive the previous response for a short period after clearing the route.
