function New-NSPFortiClientShim {
    <#
    .SYNOPSIS
        Writes a launcher script for the FortiClient Connection Troubleshooting Toolkit - to drop on
        the machine with the connection problem and run (right-click > Run with PowerShell).

    .DESCRIPTION
        The launcher installs NSP.FortiClient (this version or newer) and the NSP modules it uses from
        the PowerShell Gallery and opens the toolkit menu. See New-NSPToolShim (NSP.ClientScripts).

    .PARAMETER Path
        Where to write the launcher (.ps1).

    .PARAMETER Company
        Shown in the launcher header.

    .PARAMETER GeneratedBy
        Shown in the launcher header, e.g. 'SuperScript 1.2.0'.

    .PARAMETER Force
        Overwrite an existing file.

    .EXAMPLE
        New-NSPFortiClientShim -Path C:\Temp\FortiClient-Toolkit.ps1
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([IO.FileInfo])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Company,
        [string]$GeneratedBy,
        [switch]$Force
    )

    Import-NSPToolkitModule -Name NSP.ClientScripts -MinimumVersion 0.1.0
    $version = [string]$ExecutionContext.SessionState.Module.Version
    $shim = @{
        ToolName             = 'FortiClient Troubleshooting Toolkit'
        ModuleName           = 'NSP.FortiClient'
        ModuleMinimumVersion = $version
        EntryFunction        = 'Start-NSPFortiClientToolkit'
        Modules              = @(
            @{ Name = 'NSP.Console'; MinimumVersion = '0.1.2' }
            @{ Name = 'NSP.Toolkit'; MinimumVersion = '0.1.0' }
            @{ Name = 'NSP.FortiClient'; MinimumVersion = $version }
        )
        Path                 = $Path
        Force                = $Force
    }
    if ($Company) { $shim['Company'] = $Company }
    if ($GeneratedBy) { $shim['GeneratedBy'] = $GeneratedBy }

    if ($PSCmdlet.ShouldProcess($Path, 'Write FortiClient toolkit launcher')) {
        New-NSPToolShim @shim -Confirm:$false
    }
}
