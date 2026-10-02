function Test-NSPFortiClientFirewallBlocking {
    <#
    .SYNOPSIS
        Firewall / EDR sweep for a FortiClient connection problem - firewall profiles and rules that
        touch IKE, installed security products, other VPN/EDR agents - plus Windows Filtering Platform
        block auditing: turn it on before the attempt, read the blocked connections back after, turn
        it off again.

    .PARAMETER EnableBlockAuditing
        Turn on WFP block auditing (before the attempt).

    .PARAMETER DisableBlockAuditing
        Turn it back off (cleanup).

    .PARAMETER ShowBlockedEvents
        Show the blocked-connection events logged since -SinceMinutes.

    .PARAMETER SinceMinutes
        How far back -ShowBlockedEvents looks.

    .EXAMPLE
        Test-NSPFortiClientFirewallBlocking

    .EXAMPLE
        Test-NSPFortiClientFirewallBlocking -ShowBlockedEvents -SinceMinutes 15
    #>
    [CmdletBinding()]
    param(
        [switch]$EnableBlockAuditing,
        [switch]$DisableBlockAuditing,
        [switch]$ShowBlockedEvents,
        [int]$SinceMinutes
    )
    Invoke-NSPFortiClientScript -Name 'Test-FortiClientFirewallBlocking.ps1' -Parameters $PSBoundParameters
}
