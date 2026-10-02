function Invoke-NSPFortiClientScript {
    # Runs one of the toolkit scripts shipped in Scripts\. They stay script files (not functions)
    # because the two capture scripts relaunch themselves detached by path (-File $PSCommandPath
    # -RunCapture) so a capture survives a dropped remote session.
    param(
        [Parameter(Mandatory)][string]$Name,
        [hashtable]$Parameters = @{}
    )
    $path = Join-Path $script:ModuleRoot "Scripts\$Name"
    if (-not (Test-Path -LiteralPath $path)) { throw "$Name is missing from the NSP.FortiClient module ($path) - reinstall the module." }
    & $path @Parameters
}
