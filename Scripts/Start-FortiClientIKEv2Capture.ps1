<#
.SYNOPSIS
    Detached background capture of local network stack state during a FortiClient
    IKEv2 connection attempt. Designed to survive loss of the remote session
    (e.g. ScreenConnect) the moment the tunnel starts negotiating.

.DESCRIPTION
    Run this BEFORE the user clicks Connect. It launches a separate, detached
    PowerShell process (not a job tied to this console/session) that polls
    every second and appends to a CSV on disk:
        - UDP 500 / 4500 binding + owning process
        - Fortinet Virtual Ethernet Adapter (IKEv2) status
        - Presence/PID of fortivpn.exe, ipsecproxy.exe, ipsec.exe (FortiAuth)
        - Default route + interface (catches route hijack/flap that could
          explain the remote session drop)

    Because it's launched via Start-Process (not Start-Job/Invoke-Command),
    it keeps running independently even if the ScreenConnect session hangs
    up mid-negotiation. Just reconnect afterward and read the CSV.

    Self-terminates after -DurationMinutes, or immediately if a stop-flag
    file appears (see -StopFlagPath), so nobody has to babysit it.

    Part of the FortiClient Connection Troubleshooting Toolkit (see FCT-Toolkit.ps1 in this same
    folder for the menu-driven entry point) - also fully usable standalone.

.PARAMETER DurationMinutes
    How long to capture. Default 10. Give it enough headroom to cover the user
    clicking Connect, waiting, and the eventual cancel/disconnect.

.PARAMETER OutputDir
    Folder for the CSV output. Defaults to C:\Admin\FCTToolkit\Output\Captures.

.EXAMPLE
    # Start it, then have the user attempt the connection, then walk away
    . C:\Admin\FCTToolkit\Start-FortiClientIKEv2Capture.ps1 -DurationMinutes 10

.EXAMPLE
    # Stop it early once you're back in, without waiting for the timer
    New-Item -ItemType File -Path C:\Admin\FCTToolkit\Output\Captures\STOP -Force
#>

[CmdletBinding()]
param(
    [int]$DurationMinutes = 10,
    [string]$OutputDir = "C:\Admin\FCTToolkit\Output\Captures",
    [switch]$RunCapture   # internal - used when the script relaunches itself detached
)

$stopFlagPath = Join-Path $OutputDir "STOP"

# ---------------------------------------------------------------------------
# LAUNCHER MODE: spawn the detached worker and return control immediately
# ---------------------------------------------------------------------------
if (-not $RunCapture) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Remove-Item $stopFlagPath -ErrorAction SilentlyContinue

    $scriptPath = $MyInvocation.MyCommand.Path
    $csvPath = Join-Path $OutputDir "IKEv2_Capture_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    $argList = @(
        "-NoProfile","-ExecutionPolicy","Bypass",
        "-File", "`"$scriptPath`"",
        "-RunCapture",
        "-DurationMinutes", $DurationMinutes,
        "-OutputDir", "`"$OutputDir`""
    )

    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList $argList `
        -WindowStyle Hidden -PassThru

    Write-Host "Capture started in detached process (PID $($proc.Id))." -ForegroundColor Green
    Write-Host "It will run for $DurationMinutes minutes even if this session drops."
    Write-Host "Output folder: $OutputDir"
    Write-Host "`nTo stop it early once you're reconnected, run:"
    Write-Host "  New-Item -ItemType File -Path '$stopFlagPath' -Force"
    Write-Host "`nHave the user attempt the IKEv2 connection now."
    return
}

# ---------------------------------------------------------------------------
# WORKER MODE: this is the detached process. Runs independent of the caller.
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$csvPath = Join-Path $OutputDir "IKEv2_Capture_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$endTime = (Get-Date).AddMinutes($DurationMinutes)

$rows = New-Object System.Collections.Generic.List[object]

while ((Get-Date) -lt $endTime) {

    if (Test-Path $stopFlagPath) { break }

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'

    # UDP 500 / 4500
    $u500 = Get-NetUDPEndpoint -LocalPort 500 -ErrorAction SilentlyContinue | Select-Object -First 1
    $u4500 = Get-NetUDPEndpoint -LocalPort 4500 -ErrorAction SilentlyContinue | Select-Object -First 1
    $u500Proc  = if ($u500)  { (Get-Process -Id $u500.OwningProcess -ErrorAction SilentlyContinue).ProcessName } else { $null }
    $u4500Proc = if ($u4500) { (Get-Process -Id $u4500.OwningProcess -ErrorAction SilentlyContinue).ProcessName } else { $null }

    # IKEv2 virtual adapter status
    $ikeAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -match 'Fortinet Virtual Ethernet' } |
        Select-Object -First 1

    # Relevant Forti processes
    $fortivpn    = Get-Process -Name fortivpn    -ErrorAction SilentlyContinue | Select-Object -First 1
    $ipsecproxy  = Get-Process -Name ipsecproxy  -ErrorAction SilentlyContinue | Select-Object -First 1
    $ipsecAuth   = Get-Process -Name ipsec       -ErrorAction SilentlyContinue | Select-Object -First 1

    # Default route (catches a route flap that could explain losing the remote session)
    $defRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object -Property RouteMetric | Select-Object -First 1

    $row = [PSCustomObject]@{
        Timestamp        = $ts
        UDP500_Bound     = [bool]$u500
        UDP500_PID       = $u500.OwningProcess
        UDP500_Process   = $u500Proc
        UDP4500_Bound    = [bool]$u4500
        UDP4500_PID      = $u4500.OwningProcess
        UDP4500_Process  = $u4500Proc
        IKEv2Adapter     = $ikeAdapter.Status
        FortiVPN_PID     = $fortivpn.Id
        IpsecProxy_PID   = $ipsecproxy.Id
        IpsecAuth_PID    = $ipsecAuth.Id
        DefaultRoute_If  = $defRoute.InterfaceAlias
        DefaultRoute_NH  = $defRoute.NextHop
    }
    $rows.Add($row)

    # Write incrementally so partial data survives even if the process is killed
    $row | Export-Csv -Path $csvPath -NoTypeInformation -Append

    Start-Sleep -Seconds 1
}

# Final summary appended as a plain text sidecar for quick reading
$summaryPath = $csvPath -replace '\.csv$', '_summary.txt'
$sawIpsecProxy = $rows | Where-Object { $_.IpsecProxy_PID } | Select-Object -First 1
$sawAdapterUp  = $rows | Where-Object { $_.IKEv2Adapter -eq 'Up' } | Select-Object -First 1
$sawPort500    = $rows | Where-Object { $_.UDP500_Bound } | Select-Object -First 1

@"
Capture window: $($rows[0].Timestamp) to $($rows[-1].Timestamp)
Total samples:  $($rows.Count)

ipsecproxy.exe ever seen running: $([bool]$sawIpsecProxy)
IKEv2 virtual adapter ever went Up: $([bool]$sawAdapterUp)
UDP 500 ever bound: $([bool]$sawPort500)

If ipsecproxy.exe never appeared and UDP 500 was never bound, FortiClient
never actually attempted the network-level handshake - the failure is
happening inside fortivpn.exe / the GUI layer before it hands off to the
IPsec engine. Point next troubleshooting at FortiClient itself (profile,
cert store, emulation) rather than the network path or FortiGate.

If ipsecproxy.exe appeared and UDP 500 bound, but the adapter never went
Up, the handshake started but didn't complete - correlate the timestamps
here against the FortiGate-side IKE debug for the actual rejection reason.
"@ | Out-File -FilePath $summaryPath -Encoding UTF8
