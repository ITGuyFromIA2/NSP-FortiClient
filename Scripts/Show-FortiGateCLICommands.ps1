<#
.SYNOPSIS
    Generates the FortiGate-side CLI diagnostic commands for a live FortiClient IKEv2/IPsec
    connection issue, pre-filled with the CURRENT machine's own public IP address (looked up live,
    via a public web service) - no more hand-typing or copy/paste-editing the client's IP into each
    command mid-session.

.DESCRIPTION
    Companion to the FortiGate-side commands originally scratched into a plain notes file (see
    Examples_Sources\FCT_SourceItems\UsageNotes_And_FortiGateCommands.txt, repo root - moved there
    from this folder's own SourceItems\ subfolder, 2026-08-21) - same three command
    groups, generated fresh each run with the real IP substituted in:

      1. Gateway list check - find/clear a hung Dialup-Vendor gateway for this user (no IP needed).
      2. Packet sniffer (run in a SEPARATE FortiGate CLI session) - confirms IKEv2 packets are even
         reaching the FortiGate from this specific client IP.
      3. IKE debug (run in ANOTHER separate CLI session, alongside #2) - live IKE/FSSO negotiation
         log, filtered to just this client IP so it's not drowned out by every other tunnel's traffic.

    Run this ON the machine actually having the connection problem (e.g. during a remote session) -
    the public IP it looks up is whatever this machine's own outbound traffic is currently sourced
    from, which is what the FortiGate will actually see FortiClient's IKEv2 packets arrive from.

    CAUTION: if this machine is already connected to a DIFFERENT VPN/tunnel at the time this runs,
    the looked-up IP reflects THAT tunnel's exit address, not the user's real ISP-assigned address -
    disconnect other VPNs first if possible, or pass the known-correct address via -IPAddress instead
    of relying on the live lookup.

    Part of the FortiClient Connection Troubleshooting Toolkit (see FCT-Toolkit.ps1 in this same
    folder for the menu-driven entry point) - also fully usable standalone.

.PARAMETER IPAddress
    Skip the live public-IP lookup and use this address instead (e.g. if the tech already knows it,
    or the machine is behind another VPN at the moment and the live lookup would be wrong).

.PARAMETER CopyToClipboard
    Which command block to copy to the clipboard after displaying all of them. Interactive prompt if
    not specified. 'None' skips the clipboard entirely - useful for non-interactive/test invocation.

.EXAMPLE
    .\Show-FortiGateCLICommands.ps1

.EXAMPLE
    .\Show-FortiGateCLICommands.ps1 -IPAddress 203.0.113.10 -CopyToClipboard All
#>

[CmdletBinding()]
param(
    [string]$IPAddress,
    [ValidateSet('GatewayCheck','GatewayGet','GatewayClear','Sniffer','IKEDebugIKE','IKEDebugFNBAMD','IKEDebugBoth','All','None')]
    [string]$CopyToClipboard
)

function Get-FCTPublicIPAddress {
    <#
    .SYNOPSIS
        Looks up this machine's current public IP address, trying several independent plain-text
        lookup services in order so any single one being down/blocked/rate-limited doesn't block
        this tool. Returns $null (never throws) if all of them fail - the caller decides what to do.
    #>
    param([int]$TimeoutSeconds = 8)
    $services = @('https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com')
    foreach ($svc in $services) {
        try {
            $raw = Invoke-RestMethod -Uri $svc -TimeoutSec $TimeoutSeconds -UseBasicParsing
            $candidate = "$raw".Trim()
            if ($candidate -match '^\d{1,3}(\.\d{1,3}){3}$') {
                return [pscustomobject]@{ IP = $candidate; Source = $svc }
            }
        } catch {
            continue
        }
    }
    return $null
}

function New-FCTIKEDebugCommand {
    <#
    .SYNOPSIS
        Builds the "IKE debug" command block for a given client IP and debug scope. Pure
        string-building, same reasoning as New-FCTFortiGateCommandSet below.

    .DESCRIPTION
        The two `diagnose debug application` lines are independently useful - IKE alone for a pure
        negotiation/tunnel-establishment problem, FNBAMD alone for a RADIUS/LDAP/FSSO authentication
        problem - but share the same log-filter setup and the same trailing `diagnose debug enable`
        trigger, so they're "paired together" as one command-builder with a -Scope switch rather than
        being two fully independent blocks.
    #>
    param(
        [Parameter(Mandatory)][string]$ClientIP,
        [ValidateSet('IKE','FNBAMD','Both')][string]$Scope = 'Both'
    )
    $appLines = switch ($Scope) {
        'IKE'    { @('diagnose debug application ike -1') }
        'FNBAMD' { @('diagnose debug application fnbamd -1') }
        'Both'   { @('diagnose debug application ike -1', 'diagnose debug application fnbamd -1') }
    }
    $lines = @(
        'diagnose vpn ike log-filter clear',
        "diagnose vpn ike log-filter dst-addr4 $ClientIP"
    ) + $appLines + @('diagnose debug enable')
    return ($lines -join "`n")
}

function New-FCTGatewayGetCommand {
    <#
    .SYNOPSIS
        "Get" counterpart to New-FCTGatewayClearCommand - shows full detail for ONE named IKE
        gateway (remote/local IP, phase2 selectors, IKE version, DPD status, etc.) instead of the
        list-everything-and-grep of the Gateway List Check. Same `name <p1-interface-name>` argument
        convention as the clear command, so a tech can get/clear/get-again against the same gateway
        without retyping or reformatting anything.
    #>
    param([Parameter(Mandatory)][string]$P1Name)
    return "diagnose vpn ike gateway list name $P1Name"
}

function New-FCTGatewayClearCommand {
    <#
    .SYNOPSIS
        Real, copyable "clear phase 1" command for one named gateway - promoted out of being just a
        commented-out placeholder inside the Gateway List Check block (previously
        `#   diagnose vpn ike gateway clear name <p1-interface-name>`, requiring hand-editing before
        it was usable) into its own generated, pre-filled command.
    #>
    param([Parameter(Mandatory)][string]$P1Name)
    return "diagnose vpn ike gateway clear name $P1Name"
}

function New-FCTFortiGateCommandSet {
    <#
    .SYNOPSIS
        Builds the FortiGate CLI command blocks that only depend on the client IP (not a specific
        gateway name). Pure string-building, no I/O - kept separate from the console/clipboard
        interaction below so it can be tested directly without mocking
        Invoke-RestMethod/Read-Host/Set-Clipboard.
    #>
    param([Parameter(Mandatory)][string]$ClientIP)

    $gatewayCheckCmd = "diagnose vpn ike gateway list | grep Dialup-Vendor"

    $snifferCmd = "diagnose sniffer packet any 'host $ClientIP and (port 500 or port 4500)' 4 0 l"

    return [pscustomobject]@{
        GatewayCheckCmd = $gatewayCheckCmd
        SnifferCmd      = $snifferCmd
        IKEDebugCmd     = New-FCTIKEDebugCommand -ClientIP $ClientIP -Scope 'Both'
    }
}

# ---------------------------------------------------------------------------
# Only run the interactive flow when actually executed (not dot-sourced for the functions above -
# e.g. by a test harness that wants New-FCTFortiGateCommandSet/Get-FCTPublicIPAddress in isolation).
# ---------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {

    function Write-FCTSection { param([string]$Title) Write-Host "`n===== $Title =====" -ForegroundColor Cyan }

    # Best-effort console maximize via UI Automation's WindowPattern.SetWindowVisualState(Maximized) -
    # see FCT-Toolkit.ps1's own copy of this same helper for the full explanation of why this replaced
    # the original GetForegroundWindow()+ShowWindowAsync(SW_MAXIMIZE) P/Invoke implementation
    # (2026-08-21, after that Add-Type/DllImport block was confirmed, via a real Defender for Endpoint
    # alert against IPSec-MasterOrchestrator.ps1, to be the sole cause of 2 of 7 flagged ATT&CK
    # capabilities - see Examples_Sources\DefenderAlert.txt and the project_console_fullscreen_menus
    # memory for the full history). UIAutomationClient/UIAutomationTypes loaded via
    # Add-Type -AssemblyName - standard, signed .NET Framework assemblies, zero unmanaged interop.
    # Duplicated here rather than shared since this script runs standalone just as often as launched
    # via `&` from FCT-Toolkit.ps1's menu, and `&` doesn't inherit the caller's function definitions.
    try {
        Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
        Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop

        $focused = [System.Windows.Automation.AutomationElement]::FocusedElement
        if ($focused) {
            $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
            $current = $focused
            $windowElement = $null
            $hops = 0
            while ($current -and $hops -lt 15) {
                if ($current.Current.ControlType -eq [System.Windows.Automation.ControlType]::Window) {
                    $windowElement = $current
                    break
                }
                $current = $walker.GetParent($current)
                $hops++
            }
            if ($windowElement) {
                $patternObj = $null
                if ($windowElement.TryGetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern, [ref]$patternObj)) {
                    ([System.Windows.Automation.WindowPattern]$patternObj).SetWindowVisualState([System.Windows.Automation.WindowVisualState]::Maximized)
                }
            }
        }
    } catch {
        # Best-effort only.
    }

    if ($IPAddress) {
        if ($IPAddress -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
            Throw "-IPAddress '$IPAddress' doesn't look like a valid IPv4 address."
        }
        Write-Host "Using manually-supplied IP address: $IPAddress" -ForegroundColor Yellow
        $resolvedIP = $IPAddress
    } else {
        Write-Host "Looking up this machine's current public IP address..." -ForegroundColor Cyan
        $lookup = Get-FCTPublicIPAddress
        if (-not $lookup) {
            Throw "Could not determine a public IP address from any lookup service (api.ipify.org, ifconfig.me, icanhazip.com all failed/unreachable). Pass -IPAddress manually instead."
        }
        Write-Host "Found: $($lookup.IP)  (via $($lookup.Source))" -ForegroundColor Green
        $resolvedIP = $lookup.IP
    }

    Write-Host "`nCAUTION: if this machine is on a DIFFERENT VPN/tunnel right now, the address above is" -ForegroundColor Yellow
    Write-Host "that tunnel's exit IP, not the user's real ISP address - verify or use -IPAddress instead." -ForegroundColor Yellow

    $cmdSet = New-FCTFortiGateCommandSet -ClientIP $resolvedIP

    # -----------------------------------------------------------------------
    # NON-INTERACTIVE FAST PATH - unchanged from before: an explicit -CopyToClipboard skips the loop
    # entirely and does exactly one copy, for scripted/test invocation (see the .EXAMPLE in the
    # comment-based help above).
    # -----------------------------------------------------------------------
    if ($CopyToClipboard) {
        $clipText = switch ($CopyToClipboard) {
            "GatewayCheck"     { $cmdSet.GatewayCheckCmd }
            "Sniffer"          { $cmdSet.SnifferCmd }
            "IKEDebugBoth"     { $cmdSet.IKEDebugCmd }
            "IKEDebugIKE"      { New-FCTIKEDebugCommand -ClientIP $resolvedIP -Scope 'IKE' }
            "IKEDebugFNBAMD"   { New-FCTIKEDebugCommand -ClientIP $resolvedIP -Scope 'FNBAMD' }
            "All"              { "$($cmdSet.GatewayCheckCmd)`n`n$($cmdSet.SnifferCmd)`n`n$($cmdSet.IKEDebugCmd)" }
            default            { $null }   # GatewayGet/GatewayClear need a P1 name - not reachable non-interactively
        }
        if ($clipText) {
            try { Set-Clipboard -Value $clipText; Write-Host "`nCopied to clipboard: $CopyToClipboard" -ForegroundColor Green }
            catch { Write-Host "`nWARNING: Could not copy to clipboard - $($_.Exception.Message)" -ForegroundColor Yellow }
        }
        return [pscustomobject]@{
            IPAddress       = $resolvedIP
            GatewayCheckCmd = $cmdSet.GatewayCheckCmd
            SnifferCmd      = $cmdSet.SnifferCmd
            IKEDebugCmd     = $cmdSet.IKEDebugCmd
        }
    }

    # -----------------------------------------------------------------------
    # INTERACTIVE LOOP - stays in this section, letting a tech copy several different blocks in
    # sequence (list, then get, then clear, then get again to confirm, then the sniffer/debug
    # commands for a fresh attempt) without bouncing back out to FCT-Toolkit.ps1's own top-level menu
    # and back in each time - that round trip previously re-ran the whole public-IP lookup and
    # reprinted everything just to copy a second block.
    # -----------------------------------------------------------------------
    $P1Name = $null

    do {
        Write-FCTSection "1. Gateway List Check (run first, single CLI session, no IP needed)"
        Write-Host $cmdSet.GatewayCheckCmd

        Write-FCTSection "2. Get Gateway Detail (single named gateway)"
        if ($P1Name) {
            Write-Host (New-FCTGatewayGetCommand -P1Name $P1Name)
        } else {
            Write-Host "  (no P1 interface name set yet - pick option 2 or 3 below and you'll be asked for one)" -ForegroundColor DarkGray
        }

        Write-FCTSection "3. Clear Phase 1 (single named gateway - only if it's actually hung)"
        if ($P1Name) {
            Write-Host (New-FCTGatewayClearCommand -P1Name $P1Name)
        } else {
            Write-Host "  (no P1 interface name set yet - pick option 2 or 3 below and you'll be asked for one)" -ForegroundColor DarkGray
        }

        Write-FCTSection "4. Packet Sniffer (run in ONE separate FortiGate CLI session)"
        Write-Host $cmdSet.SnifferCmd

        Write-FCTSection "5. IKE Debug (run in ANOTHER separate FortiGate CLI session, alongside #4)"
        Write-Host "  Same log-filter/enable trigger either way - pick IKE only, FNBAMD (auth) only, or both"
        Write-Host "  when you copy below, depending on whether this looks like a negotiation problem or an"
        Write-Host "  authentication (RADIUS/LDAP/FSSO) problem."

        Write-Host "`nHave the user attempt the connection once the sniffer/debug CLI sessions are running." -ForegroundColor Green

        Write-Host "`nCopy which block to clipboard?"
        Write-Host "  1. Gateway List Check"
        Write-Host "  2. Get Gateway Detail        - prompts for the P1 interface name"
        Write-Host "  3. Clear Phase 1             - prompts for the P1 interface name"
        Write-Host "  4. Packet Sniffer"
        Write-Host "  5. IKE Debug - IKE only"
        Write-Host "  6. IKE Debug - FNBAMD (auth) only"
        Write-Host "  7. IKE Debug - Both"
        Write-Host "  P. Set/change the P1 interface name (current: $(if ($P1Name) { $P1Name } else { 'not set' }))"
        Write-Host "  A. All (list + sniffer + IKE Debug Both, combined into one paste)"
        Write-Host "  Q. Done - back to the Toolkit menu"
        $sel = Read-Host "Select"
        $selUpper = $sel.Trim().ToUpper()

        if ($selUpper -in @('2','3') -and -not $P1Name) {
            $entered = Read-Host "P1 interface name (from the Gateway List Check output above)"
            if (-not [string]::IsNullOrWhiteSpace($entered)) { $P1Name = $entered.Trim() }
        }

        $copyChoice = switch ($selUpper) {
            "1" { "GatewayCheck" }
            "2" { if ($P1Name) { "GatewayGet" }   else { "None" } }
            "3" { if ($P1Name) { "GatewayClear" } else { "None" } }
            "4" { "Sniffer" }
            "5" { "IKEDebugIKE" }
            "6" { "IKEDebugFNBAMD" }
            "7" { "IKEDebugBoth" }
            "A" { "All" }
            default { "None" }
        }

        if ($selUpper -eq 'P') {
            $entered = Read-Host "New P1 interface name (current: $(if ($P1Name) { $P1Name } else { 'not set' }))"
            if (-not [string]::IsNullOrWhiteSpace($entered)) { $P1Name = $entered.Trim() }
        } else {
            $clipText = switch ($copyChoice) {
                "GatewayCheck"   { $cmdSet.GatewayCheckCmd }
                "GatewayGet"     { New-FCTGatewayGetCommand   -P1Name $P1Name }
                "GatewayClear"   { New-FCTGatewayClearCommand -P1Name $P1Name }
                "Sniffer"        { $cmdSet.SnifferCmd }
                "IKEDebugIKE"    { New-FCTIKEDebugCommand -ClientIP $resolvedIP -Scope 'IKE' }
                "IKEDebugFNBAMD" { New-FCTIKEDebugCommand -ClientIP $resolvedIP -Scope 'FNBAMD' }
                "IKEDebugBoth"   { New-FCTIKEDebugCommand -ClientIP $resolvedIP -Scope 'Both' }
                "All"            { "$($cmdSet.GatewayCheckCmd)`n`n$($cmdSet.SnifferCmd)`n`n$($cmdSet.IKEDebugCmd)" }
                default          { $null }
            }

            if ($clipText) {
                try {
                    Set-Clipboard -Value $clipText
                    Write-Host "`nCopied to clipboard: $copyChoice" -ForegroundColor Green
                } catch {
                    Write-Host "`nWARNING: Could not copy to clipboard - $($_.Exception.Message)" -ForegroundColor Yellow
                }
            } elseif ($selUpper -notin @('Q','QUIT')) {
                Write-Host "`nNothing copied to clipboard." -ForegroundColor Gray
            }
        }

        if ($selUpper -notin @('Q','QUIT')) {
            Write-Host ""
            Read-Host "Press Enter to show this section again" | Out-Null
            Clear-Host
        }
    } while ($selUpper -notin @('Q','QUIT'))

    [pscustomobject]@{
        IPAddress       = $resolvedIP
        GatewayCheckCmd = $cmdSet.GatewayCheckCmd
        SnifferCmd      = $cmdSet.SnifferCmd
        IKEDebugCmd     = $cmdSet.IKEDebugCmd
        P1Name          = $P1Name
    }
}
