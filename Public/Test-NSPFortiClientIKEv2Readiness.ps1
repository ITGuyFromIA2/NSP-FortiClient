function Test-NSPFortiClientIKEv2Readiness {
    <#
    .SYNOPSIS
        Pre-attempt snapshot for a FortiClient IKEv2 connection problem: FortiClient services, IKE
        ports (UDP 500/4500) in use, network adapters, and recent FortiClient / IKE event-log entries.
        Writes a text report. Run it before the user tries to connect.

    .PARAMETER SinceMinutes
        How far back to read the event logs.

    .PARAMETER OutputPath
        The report file. Defaults to C:\Admin\FCTToolkit\Output\Reports\FortiClient_IKEv2_Readiness_<time>.txt.

    .EXAMPLE
        Test-NSPFortiClientIKEv2Readiness -SinceMinutes 60
    #>
    [CmdletBinding()]
    param(
        [int]$SinceMinutes,
        [string]$OutputPath
    )
    Invoke-NSPFortiClientScript -Name 'Test-FortiClientIKEv2Readiness.ps1' -Parameters $PSBoundParameters
}
