function Start-NSPFortiClientPacketCapture {
    <#
    .SYNOPSIS
        Starts a timed pktmon packet capture of IKE traffic (UDP 500/4500), with a detached stop timer
        so it ends on schedule even if the remote session drops. Stop it early with
        Stop-NSPFortiClientCapture.

    .PARAMETER DurationMinutes
        How long to capture.

    .PARAMETER OutputDir
        Where the capture files go. Defaults to C:\Admin\FCTToolkit\Output\Captures.

    .EXAMPLE
        Start-NSPFortiClientPacketCapture -DurationMinutes 10
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$DurationMinutes,
        [string]$OutputDir
    )
    if ($PSCmdlet.ShouldProcess('this computer', 'Start a pktmon capture of IKE traffic')) {
        $forward = @{}
        foreach ($k in 'DurationMinutes', 'OutputDir') { if ($PSBoundParameters.ContainsKey($k)) { $forward[$k] = $PSBoundParameters[$k] } }
        Invoke-NSPFortiClientScript -Name 'Start-FortiClientPacketCapture.ps1' -Parameters $forward
    }
}
