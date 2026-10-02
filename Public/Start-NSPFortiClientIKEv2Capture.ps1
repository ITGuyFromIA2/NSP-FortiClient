function Start-NSPFortiClientIKEv2Capture {
    <#
    .SYNOPSIS
        Starts a detached, timed capture of FortiClient / IKEv2 state (services, sockets, adapters,
        routes, event logs) that keeps running if the remote session drops. Stop it early with
        Stop-NSPFortiClientCapture.

    .PARAMETER DurationMinutes
        How long to capture.

    .PARAMETER OutputDir
        Where the capture files go. Defaults to C:\Admin\FCTToolkit\Output\Captures.

    .EXAMPLE
        Start-NSPFortiClientIKEv2Capture -DurationMinutes 15
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$DurationMinutes,
        [string]$OutputDir
    )
    if ($PSCmdlet.ShouldProcess('this computer', 'Start a detached IKEv2 state capture')) {
        $forward = @{}
        foreach ($k in 'DurationMinutes', 'OutputDir') { if ($PSBoundParameters.ContainsKey($k)) { $forward[$k] = $PSBoundParameters[$k] } }
        Invoke-NSPFortiClientScript -Name 'Start-FortiClientIKEv2Capture.ps1' -Parameters $forward
    }
}
