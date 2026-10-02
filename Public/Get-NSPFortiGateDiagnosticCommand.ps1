function Get-NSPFortiGateDiagnosticCommand {
    <#
    .SYNOPSIS
        The FortiGate CLI diagnostic commands for one FortiClient's IKEv2 connection, as text - no
        prompts, no clipboard, no lookup. For scripts and RMM; Show-NSPFortiGateCLICommand is the
        interactive version.

    .PARAMETER ClientIP
        The client's public IP, as the FortiGate sees it.

    .PARAMETER P1Name
        A phase 1 interface (gateway) name, to add its get and clear commands.

    .PARAMETER DebugScope
        IKE (negotiation), FNBAMD (RADIUS/LDAP authentication) or Both.

    .EXAMPLE
        (Get-NSPFortiGateDiagnosticCommand -ClientIP 203.0.113.10).IKEDebugCmd
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')][string]$ClientIP,
        [string]$P1Name,
        [ValidateSet('IKE', 'FNBAMD', 'Both')][string]$DebugScope = 'Both'
    )
    # The script's command builders are pure; dot-sourcing it defines them here without running its
    # interactive part (it checks for a dot-source).
    . (Join-Path $script:ModuleRoot 'Scripts\Show-FortiGateCLICommands.ps1')
    $set = New-FCTFortiGateCommandSet -ClientIP $ClientIP
    $out = [ordered]@{
        ClientIP        = $ClientIP
        GatewayCheckCmd = $set.GatewayCheckCmd
        SnifferCmd      = $set.SnifferCmd
        IKEDebugCmd     = New-FCTIKEDebugCommand -ClientIP $ClientIP -Scope $DebugScope
        GatewayGetCmd   = $null
        GatewayClearCmd = $null
    }
    if ($P1Name) {
        $out.GatewayGetCmd = New-FCTGatewayGetCommand -P1Name $P1Name
        $out.GatewayClearCmd = New-FCTGatewayClearCommand -P1Name $P1Name
    }
    [pscustomobject]$out
}
