<#
.SYNOPSIS
    Detached packet capture (using Windows' built-in pktmon) filtered to
    UDP 500/4500, to settle definitively whether IKEv2 traffic leaves the
    NIC at all during a connection attempt - independent of whatever
    firewall/EDR/VPN software might or might not be involved.

.DESCRIPTION
    pktmon is a kernel-level ETW trace, not a user-session process - it
    keeps running even if the ScreenConnect session drops, same reasoning
    as the earlier detached capture script.

    Run this BEFORE the user attempts the connection. It self-stops after
    -DurationMinutes and converts the trace to a .pcapng you can open in
    Wireshark.

    What the result tells you:
      - No UDP 500/4500 packets in the capture at all -> something on THIS
        machine is blocking it before it reaches the network stack's outer
        edge (local firewall, EDR network filter, or FortiClient itself
        never actually attempting the handshake).
      - Outbound packets present, no inbound response -> traffic is leaving
        the machine fine; look at the router/ISP path or the FortiGate side
        (correlate with FortiGate-side IKE debug).
      - Outbound + inbound both present -> the handshake is happening at
        the network level; the failure is happening above that, in
        FortiClient's own processing of the response (worth revisiting the
        FortiClient debug logs for this exact window).

    Part of the FortiClient Connection Troubleshooting Toolkit (see FCT-Toolkit.ps1 in this same
    folder for the menu-driven entry point) - also fully usable standalone.

.PARAMETER DurationMinutes
    How long to capture. Default 10.

.PARAMETER OutputDir
    Default C:\Admin\FCTToolkit\Output\Captures (same folder as the other capture script).

.EXAMPLE
    . C:\Admin\FCTToolkit\Start-FortiClientPacketCapture.ps1 -DurationMinutes 10
#>

[CmdletBinding()]
param(
    [int]$DurationMinutes = 10,
    [string]$OutputDir = "C:\Admin\FCTToolkit\Output\Captures",
    [switch]$RunCapture   # internal - used by the detached stop-timer process
)

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# ---------------------------------------------------------------------------
if (-not $RunCapture) {

    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $etlPath    = Join-Path $OutputDir "IKEv2_Packets_$ts.etl"
    $pcapngPath = Join-Path $OutputDir "IKEv2_Packets_$ts.pcapng"

    Write-Host "Resetting any existing pktmon filters/capture..." -ForegroundColor Cyan
    pktmon stop 2>$null | Out-Null
    pktmon filter remove 2>$null | Out-Null

    Write-Host "Adding filters for UDP 500 and 4500..." -ForegroundColor Cyan
    pktmon filter add -p 500  -t UDP | Out-Null
    pktmon filter add -p 4500 -t UDP | Out-Null

    Write-Host "Starting capture -> $etlPath" -ForegroundColor Cyan
    pktmon start --etw -f "$etlPath" -m multi | Out-Null

    # Launch a detached stop-timer so this survives the session dropping
    $scriptPath = $MyInvocation.MyCommand.Path
    $argList = @(
        "-NoProfile","-ExecutionPolicy","Bypass",
        "-File", "`"$scriptPath`"",
        "-RunCapture",
        "-DurationMinutes", $DurationMinutes,
        "-OutputDir", "`"$OutputDir`""
    )
    Start-Process -FilePath "powershell.exe" -ArgumentList $argList -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $OutputDir "capture_timer_$ts.log") | Out-Null

    Write-Host "`nCapture running for $DurationMinutes minutes, independent of this session." -ForegroundColor Green
    Write-Host "Have the user attempt the IKEv2 connection now." -ForegroundColor Green
    Write-Host "`nWhen done, the .pcapng will be at:`n  $pcapngPath" -ForegroundColor Green
    Write-Host "`nTo stop early once reconnected:  pktmon stop" -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------------------------
# WORKER: waits out the duration, then stops capture and converts to pcapng
# ---------------------------------------------------------------------------
Start-Sleep -Seconds ($DurationMinutes * 60)

pktmon stop | Out-Null

$latestEtl = Get-ChildItem -Path $OutputDir -Filter "IKEv2_Packets_*.etl" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($latestEtl) {
    $pcapngPath = $latestEtl.FullName -replace '\.etl$', '.pcapng'
    pktmon pcapng $latestEtl.FullName -o $pcapngPath | Out-Null

    # Quick pass/fail summary without needing Wireshark open
    $summaryPath = $latestEtl.FullName -replace '\.etl$', '_summary.txt'
    $rawText = Join-Path $OutputDir "raw_dump_temp.txt"
    pktmon format $latestEtl.FullName -o $rawText 2>$null | Out-Null

    $outboundCount = 0
    $inboundCount  = 0
    if (Test-Path $rawText) {
        $content = Get-Content $rawText -ErrorAction SilentlyContinue
        $outboundCount = ($content | Select-String -Pattern 'UDP.*:500\b|UDP.*:4500\b' | Measure-Object).Count
        Remove-Item $rawText -ErrorAction SilentlyContinue
    }

    @"
Capture file: $($latestEtl.Name)
Converted to: $(Split-Path $pcapngPath -Leaf)
Packet lines matching UDP 500/4500 (rough count, verify in Wireshark): $outboundCount

If this is 0: no IKEv2 traffic left this NIC during the capture window -
the block (or the failure) is happening locally, before anything hits
the wire. Point troubleshooting at FortiClient itself, local firewall,
or an EDR network filter rather than the FortiGate/network path.

If this is > 0: open the .pcapng in Wireshark and check whether there
are BOTH outbound (src=this host, dport 500/4500) and inbound
(dst=this host, sport 500/4500) packets. Outbound-only means it left
fine but nothing came back - correlate with FortiGate-side IKE debug
for the same timestamps.
"@ | Out-File -FilePath $summaryPath -Encoding UTF8
}
