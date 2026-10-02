function Show-NSPFortiGateCLICommand {
    <#
    .SYNOPSIS
        Interactive: shows the FortiGate-side CLI diagnostics for this machine's FortiClient IKEv2
        connection - gateway list check / get / clear, packet sniffer, IKE and FNBAMD debug - pre-filled
        with this machine's public IP (looked up live), and copies the chosen block to the clipboard.

    .PARAMETER IPAddress
        Use this address instead of the live public-IP lookup (e.g. when another VPN is connected).

    .PARAMETER CopyToClipboard
        Which block to copy without asking; 'None' copies nothing.

    .EXAMPLE
        Show-NSPFortiGateCLICommand

    .EXAMPLE
        Show-NSPFortiGateCLICommand -IPAddress 203.0.113.10 -CopyToClipboard All
    #>
    [CmdletBinding()]
    param(
        [string]$IPAddress,
        [ValidateSet('GatewayCheck', 'GatewayGet', 'GatewayClear', 'Sniffer', 'IKEDebugIKE', 'IKEDebugFNBAMD', 'IKEDebugBoth', 'All', 'None')]
        [string]$CopyToClipboard
    )
    Invoke-NSPFortiClientScript -Name 'Show-FortiGateCLICommands.ps1' -Parameters $PSBoundParameters
}
