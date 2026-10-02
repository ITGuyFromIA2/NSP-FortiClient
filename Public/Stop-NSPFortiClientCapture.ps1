function Stop-NSPFortiClientCapture {
    <#
    .SYNOPSIS
        Ends running FortiClient captures early: drops the STOP flag the detached state capture
        watches for, and stops pktmon.

    .PARAMETER CaptureDir
        The capture folder the running capture writes to.

    .EXAMPLE
        Stop-NSPFortiClientCapture
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$CaptureDir = 'C:\Admin\FCTToolkit\Output\Captures')
    if ($PSCmdlet.ShouldProcess($CaptureDir, 'Drop the STOP flag and stop pktmon')) {
        if (-not (Test-Path -LiteralPath $CaptureDir)) { New-Item -ItemType Directory -Path $CaptureDir -Force | Out-Null }
        New-Item -ItemType File -Path (Join-Path $CaptureDir 'STOP') -Force | Out-Null
        if (Get-Command pktmon -ErrorAction SilentlyContinue) { pktmon stop 2>$null | Out-Null }
        Write-Host "Stop flag dropped and pktmon stopped. Any running capture(s) will end shortly." -ForegroundColor Green
    }
}
