function Start-NSPFortiClientToolkit {
    <#
    .SYNOPSIS
        The FortiClient Connection Troubleshooting Toolkit menu - run it ON the machine with the
        connection problem (typically over a remote session): readiness check, pre-attempt monitoring
        (detached captures and block auditing that survive a dropped session), firewall/EDR sweep,
        blocked-connection review, and the FortiGate-side CLI commands.

    .DESCRIPTION
        Moved from the zip-era FCT-Toolkit.ps1; the menu is unchanged. Typical flow for a live IKEv2
        failure: 1 (readiness) and 2 (monitoring) before the attempt, 7 (FortiGate CLI) on the
        FortiGate side, the user tries to connect, then 3 and 4. Relaunches elevated if needed.

    .PARAMETER OutputRoot
        Where reports and captures go (Reports\ and Captures\ under it).

    .PARAMETER SeedAnswersJson
        Accepted for the NSP launcher contract; this toolkit has no answers of its own yet.

    .PARAMETER SeedOnly
        Merge -SeedAnswersJson and return without opening the menu.

    .PARAMETER NoElevate
        Do not relaunch elevated.

    .EXAMPLE
        Start-NSPFortiClientToolkit
    #>
    [CmdletBinding()]
    param(
        [string]$OutputRoot = 'C:\Admin\FCTToolkit\Output',
        [string]$SeedAnswersJson,
        [switch]$SeedOnly,
        [switch]$NoElevate
    )

    Use-NSPFortiClientDependency

    if ($SeedOnly) {
        $null = Import-NSPToolSeedAnswers -Tool FortiClient -SeedAnswersJson $SeedAnswersJson
        return
    }

    if (-not $NoElevate) {
        $manifest = (Join-Path $script:ModuleRoot 'NSP.FortiClient.psd1').Replace("'", "''")
        $relaunch = "Import-Module '$manifest'; Start-NSPFortiClientToolkit"
        if ($PSBoundParameters.ContainsKey('OutputRoot')) { $relaunch += " -OutputRoot '$($OutputRoot.Replace("'", "''"))'" }
        if (Invoke-NSPElevated -Command $relaunch -NoExit) { return }
    }
    if ($SeedAnswersJson) { $null = Import-NSPToolSeedAnswers -Tool FortiClient -SeedAnswersJson $SeedAnswersJson }

    $captureDir = Join-Path $OutputRoot 'Captures'
    $reportDir = Join-Path $OutputRoot 'Reports'
    foreach ($dir in @($OutputRoot, $captureDir, $reportDir)) {
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    }

    Set-NSPConsoleMaximized -ErrorAction SilentlyContinue
    $version = [string]$ExecutionContext.SessionState.Module.Version
    $versionLabel = (Get-NSPToolVersionStatus -ToolKey 'NSP.FortiClient' -Version $version).Label

    # ----- zip-era FCT-Toolkit.ps1 menu (the scripts are called through their module functions) -----
    while ($true) {
        Write-Host ""
        Write-Host "================================================"
        Write-Host "  FortiClient Connection Troubleshooting Toolkit  $versionLabel"
        Write-Host "================================================"
        Write-Host "*** Before the Attempt ***"
        Write-Host "  1. Readiness Check             - pre-attempt snapshot (services, ports, adapters, events)"
        Write-Host "  2. Start Pre-Attempt Monitoring - Live Capture and/or Block Auditing (1/2/both)"
        Write-Host "  3. Firewall / EDR Check         - static sweep of firewall rules, security products, EDR/VPN agents"
        Write-Host ""
        Write-Host "*** After the Attempt ***"
        Write-Host "  4. Show Blocked Connections    - read back blocked-connection events"
        Write-Host "  5. Stop Live Capture Early     - drop the STOP flag for any running capture"
        Write-Host "  6. Disable Block Auditing      - turn logging back off (cleanup)"
        Write-Host ""
        Write-Host "*** FortiGate ***"
        Write-Host "  7. FortiGate CLI Commands      - generate + copy commands using this machine's public IP"
        Write-Host ""
        Write-Host "  Q. Quit"
        Write-Host "================================================"
        Write-Host "  Output folder: $OutputRoot"
        Write-Host ""
        $choice = Read-Host "Select an option"

        switch -Regex ("$choice".Trim()) {
            '^1$' {
                $mins = Read-Host "Look back how many minutes in the event logs? [30]"
                if ([string]::IsNullOrWhiteSpace($mins)) { $mins = 30 }
                Test-NSPFortiClientIKEv2Readiness -SinceMinutes ([int]$mins) `
                    -OutputPath (Join-Path $reportDir "FortiClient_IKEv2_Readiness_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt")
            }
            '^2$' {
                Write-Host "  1. Live Capture only (state + packet capture)"
                Write-Host "  2. Block Auditing only (WFP block logging)"
                Write-Host "  3. Both (recommended)"
                $monSel = Read-Host "Enable which? [3]"
                if ([string]::IsNullOrWhiteSpace($monSel)) { $monSel = "3" }

                if ($monSel -in @("1", "3")) {
                    $mins = Read-Host "Capture for how many minutes? [10]"
                    if ([string]::IsNullOrWhiteSpace($mins)) { $mins = 10 }
                    Start-NSPFortiClientIKEv2Capture -DurationMinutes ([int]$mins) -OutputDir $captureDir
                    Start-NSPFortiClientPacketCapture -DurationMinutes ([int]$mins) -OutputDir $captureDir
                }
                if ($monSel -in @("2", "3")) {
                    Test-NSPFortiClientFirewallBlocking -EnableBlockAuditing
                }
                if ($monSel -notin @("1", "2", "3")) {
                    Write-Host "Invalid selection - nothing enabled." -ForegroundColor Yellow
                }
            }
            '^3$' { Test-NSPFortiClientFirewallBlocking }
            '^4$' {
                $mins = Read-Host "Look back how many minutes? [30]"
                if ([string]::IsNullOrWhiteSpace($mins)) { $mins = 30 }
                Test-NSPFortiClientFirewallBlocking -ShowBlockedEvents -SinceMinutes ([int]$mins)
            }
            '^5$' { Stop-NSPFortiClientCapture -CaptureDir $captureDir }
            '^6$' { Test-NSPFortiClientFirewallBlocking -DisableBlockAuditing }
            '^7$' { Show-NSPFortiGateCLICommand }
            '^[Qq](uit)?$' {
                Write-Host "Goodbye." -ForegroundColor Gray
                return
            }
            default { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    }
}
