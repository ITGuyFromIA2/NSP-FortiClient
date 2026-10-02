<#
.SYNOPSIS
    Checks whether Windows Firewall or third-party security software could be
    blocking FortiClient's IKEv2 traffic (UDP 500/4500) or its processes.

.DESCRIPTION
    Three modes:

    1) Static check (default) - firewall profile state, any rules touching
       Fortinet's binaries or ports 500/4500, and what security products are
       actually registered with Windows (catches HP Wolf Security / other
       OEM-bundled firewalls that aren't the Windows Defender Firewall you'd
       normally check).

    2) -EnableBlockAuditing - turns on Windows Filtering Platform "connection
       blocked" auditing (Security event ID 5157). This is the one that
       actually catches a SILENT drop live - run this before the connection
       attempt, alongside the capture scripts. A block that never shows up
       anywhere else will show up here, with the exact rule/filter that did it.

    3) -ShowBlockedEvents - reads back 5157 events from the Security log,
       filtered to ports 500/4500 or Fortinet process paths, since the time
       you specify. Run this after the attempt.

    4) -DisableBlockAuditing - turns auditing back off afterward (it does add
       Security log volume, so don't leave it on indefinitely).

    Part of the FortiClient Connection Troubleshooting Toolkit (see FCT-Toolkit.ps1 in this same
    folder for the menu-driven entry point) - also fully usable standalone.

.EXAMPLE
    # Before the attempt
    .\Test-FortiClientFirewallBlocking.ps1 -EnableBlockAuditing

.EXAMPLE
    # After the attempt
    .\Test-FortiClientFirewallBlocking.ps1 -ShowBlockedEvents -SinceMinutes 15

.EXAMPLE
    # Cleanup
    .\Test-FortiClientFirewallBlocking.ps1 -DisableBlockAuditing
#>

[CmdletBinding()]
param(
    [switch]$EnableBlockAuditing,
    [switch]$DisableBlockAuditing,
    [switch]$ShowBlockedEvents,
    [int]$SinceMinutes = 30
)

function Write-Section {
    param([string]$Title)
    Write-Host "`n===== $Title =====" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
if ($EnableBlockAuditing) {
    Write-Section "Enabling WFP Block Auditing"
    auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable | Out-Null
    auditpol /get /subcategory:"Filtering Platform Connection"
    Write-Host "`nAuditing enabled. Have the user attempt the connection now." -ForegroundColor Green
    Write-Host "Then run this script again with -ShowBlockedEvents." -ForegroundColor Green
    return
}

if ($DisableBlockAuditing) {
    Write-Section "Disabling WFP Block Auditing"
    auditpol /set /subcategory:"Filtering Platform Connection" /failure:disable | Out-Null
    auditpol /get /subcategory:"Filtering Platform Connection"
    Write-Host "`nAuditing disabled." -ForegroundColor Green
    return
}

if ($ShowBlockedEvents) {
    Write-Section "Blocked Connections - Security Log 5157 (last $SinceMinutes min)"
    $since = (Get-Date).AddMinutes(-$SinceMinutes)
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 5157
        StartTime = $since
    } -ErrorAction SilentlyContinue

    if (-not $events) {
        Write-Host "No 5157 events found. Either nothing was blocked, or auditing wasn't enabled for this window."
        return
    }

    $events | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

        $isRelevant = $data.DestPort -in '500','4500' -or
                      $data.SourcePort -in '500','4500' -or
                      $data.Application -match 'forti|ipsec'

        if ($isRelevant) {
            Write-Host "`n[$($_.TimeCreated)]"
            Write-Host "  Application:  $($data.Application)"
            Write-Host "  Direction:    $($data.Direction)"
            Write-Host "  Src:          $($data.SourceAddress):$($data.SourcePort)"
            Write-Host "  Dst:          $($data.DestAddress):$($data.DestPort)"
            Write-Host "  Protocol:     $($data.Protocol)"
            Write-Host "  Filter ID:    $($data.FilterRTID)"
            Write-Host "  Layer:        $($data.LayerName)"
        }
    }
    return
}

# ---------------------------------------------------------------------------
# DEFAULT: static check
# ---------------------------------------------------------------------------

Write-Section "Windows Firewall Profile State"
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogAllowed, LogFileName |
    Format-Table -AutoSize

Write-Section "Registered Security Products (Security Center)"
try {
    Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName FirewallProduct -ErrorAction Stop |
        Select-Object displayName, productState | Format-Table -AutoSize
    Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
        Select-Object displayName, productState | Format-Table -AutoSize
} catch {
    Write-Host "Could not query SecurityCenter2 (may require elevation or isn't populated on this SKU)."
}
Write-Host "(If anything other than 'Windows Defender Firewall' / 'Microsoft Defender Antivirus' shows up here - e.g. HP Wolf Security, McAfee, etc. - that product's OWN firewall/network filter is a real candidate and Windows Firewall rules below won't reflect it.)"

Write-Section "Firewall Rules Referencing Fortinet Binaries"
$fortiPaths = @(
    'fortivpn.exe','ipsecproxy.exe','ipsec.exe','FortiClient.exe','fcappdb.exe','FortiSSLVPNdaemon.exe'
)
Get-NetFirewallApplicationFilter | Where-Object {
    $ap = $_.Program
    $fortiPaths | Where-Object { $ap -match [regex]::Escape($_) }
} | ForEach-Object {
    $rule = $_ | Get-NetFirewallRule
    [PSCustomObject]@{
        RuleName  = $rule.DisplayName
        Enabled   = $rule.Enabled
        Direction = $rule.Direction
        Action    = $rule.Action
        Program   = $_.Program
    }
} | Format-Table -AutoSize

Write-Section "Firewall Rules Referencing UDP 500 / 4500"
Get-NetFirewallPortFilter | Where-Object {
    $_.Protocol -eq 'UDP' -and ($_.LocalPort -match '500|4500' -or $_.RemotePort -match '500|4500')
} | ForEach-Object {
    $rule = $_ | Get-NetFirewallRule
    [PSCustomObject]@{
        RuleName  = $rule.DisplayName
        Enabled   = $rule.Enabled
        Direction = $rule.Direction
        Action    = $rule.Action
        LocalPort = $_.LocalPort
        RemotePort= $_.RemotePort
    }
} | Format-Table -AutoSize

Write-Section "Built-in 'Core Networking - IPsec' Rule Group State"
Get-NetFirewallRule -Group '*IPsec*' -ErrorAction SilentlyContinue |
    Select-Object DisplayName, Enabled, Direction, Action | Format-Table -AutoSize

Write-Section "Non-Microsoft WFP Filter Providers (catches EDR/VPN agents that skip Security Center registration)"
try {
    $wfpFile = Join-Path $env:TEMP "wfpstate_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    netsh wfp show state file="$wfpFile" | Out-Null
    if (Test-Path $wfpFile) {
        [xml]$wfp = Get-Content $wfpFile
        $providers = $wfp.wfpdiag.providers.item |
            Where-Object { $_.providerKey.data -notmatch '^\{4b153735|^\{f3183a' } |  # common MS provider GUID prefixes, best-effort
            Select-Object -ExpandProperty name -Unique
        $providers | Where-Object { $_ -and $_ -notmatch 'Microsoft|Windows' } | ForEach-Object {
            Write-Host "  Non-Microsoft filter provider: $_"
        }
        if (-not ($providers | Where-Object { $_ -notmatch 'Microsoft|Windows' })) {
            Write-Host "  No non-Microsoft WFP providers found."
        }
        Remove-Item $wfpFile -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "Could not enumerate WFP state (needs elevation)."
}

Write-Section "Known EDR / VPN / SASE Agent Sweep (process + service names)"
$vendorPatterns = @(
    'CSFalcon','SentinelAgent','SentinelOne','CylanceSvc','Cb Defense','CarbonBlack',
    'TmCCSF','TrendMicro','McAfee','mfe','Symantec','sepMasterService','Sophos',
    'Trellix','Forcepoint','Netskope','nsdiag','ZSATunnel','Zscaler',
    'GlobalProtect','PanGP','CiscoAnyConnect','vpnagent','Umbrella','csc_',
    'CheckPoint','FortiEDR','wolf' # HP Wolf Security
)
$hits = Get-Process | Where-Object { $n = $_.ProcessName; $vendorPatterns | Where-Object { $n -match $_ } }
$hits += Get-Service | Where-Object { $_.Status -eq 'Running' } | Where-Object { $n = $_.DisplayName; $vendorPatterns | Where-Object { $n -match $_ } }
if ($hits) {
    $hits | Select-Object -Unique | Format-Table -AutoSize
    Write-Host "Any of these represent a network filter that Windows Firewall rules above won't show." -ForegroundColor Yellow
} else {
    Write-Host "  No known EDR/VPN/SASE agents found running under checked name patterns."
    Write-Host "  (This list isn't exhaustive - if the user's org is known to use a specific EDR product, check its process name directly.)"
}

Write-Host "`nNext step: run with -EnableBlockAuditing before the next attempt," -ForegroundColor Yellow
Write-Host "then -ShowBlockedEvents afterward to see any live silent drop." -ForegroundColor Yellow
Write-Host "For the most conclusive answer - does the packet even leave the NIC - use the" -ForegroundColor Yellow
Write-Host "companion packet capture script (Start-FortiClientPacketCapture.ps1)." -ForegroundColor Yellow
