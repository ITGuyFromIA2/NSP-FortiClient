<#
.SYNOPSIS
    Pre-connect / post-failure diagnostic for FortiClient IKEv2 on Windows ARM.

.DESCRIPTION
    Captures the local-stack state that isn't visible in FortiClient's own logs:
      - CPU architecture / OS build / FortiClient version
      - IKEEXT (Windows built-in IKE/AuthIP) service state - known port 500/4500 conflict source
      - UDP 500 / 4500 binding ownership
      - Fortinet / WAN Miniport virtual adapter presence and status
      - Recent System + Application event log entries tied to RRAS, IKEEXT, or FortiClient crashes
      - FortiClient VPN-related service states

    Run this AFTER a failed IKEv2 attempt (before rebooting/retrying) so the event log
    window still contains the relevant entries. Pass -SinceMinutes to widen/narrow the
    event log lookback relative to now.

    Part of the FortiClient Connection Troubleshooting Toolkit (see FCT-Toolkit.ps1 in this same
    folder for the menu-driven entry point) - also fully usable standalone.

.PARAMETER SinceMinutes
    How far back to search event logs, in minutes. Default 30.

.PARAMETER OutputPath
    Where to write the report. Defaults under the toolkit's shared output folder
    (C:\Admin\FCTToolkit\Output\Reports).

.EXAMPLE
    .\Test-FortiClientIKEv2Readiness.ps1 -SinceMinutes 60
#>

[CmdletBinding()]
param(
    [int]$SinceMinutes = 30,
    [string]$OutputPath = "C:\Admin\FCTToolkit\Output\Reports\FortiClient_IKEv2_Readiness_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

$ErrorActionPreference = 'SilentlyContinue'
$OutputDir = Split-Path -Path $OutputPath -Parent
if ($OutputDir -and -not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$sb = New-Object System.Text.StringBuilder
function Write-Section {
    param([string]$Title)
    $null = $sb.AppendLine("`n===== $Title =====")
    Write-Host "`n===== $Title =====" -ForegroundColor Cyan
}
function Write-Line {
    param([string]$Text)
    $null = $sb.AppendLine($Text)
    Write-Host $Text
}

$since = (Get-Date).AddMinutes(-$SinceMinutes)

# ---------------------------------------------------------------------------
Write-Section "System / Architecture"
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
Write-Line "Computer:        $($cs.Name)"
Write-Line "Manufacturer:    $($cs.Manufacturer) $($cs.Model)"
Write-Line "Processor Arch:  $($env:PROCESSOR_ARCHITECTURE)"
Write-Line "OS:              $($os.Caption) Build $($os.BuildNumber)"
Write-Line "OS Architecture: $($os.OSArchitecture)"

# ---------------------------------------------------------------------------
Write-Section "FortiClient Install / Version"
$fcReg = Get-ItemProperty "HKLM:\SOFTWARE\Fortinet\FortiClient*" -ErrorAction SilentlyContinue
$fcUninstall = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object { $_.DisplayName -like "*FortiClient*" }
if ($fcUninstall) {
    foreach ($f in $fcUninstall) {
        Write-Line "Product:         $($f.DisplayName)"
        Write-Line "Version:         $($f.DisplayVersion)"
        Write-Line "InstallLocation: $($f.InstallLocation)"
    }
} else {
    Write-Line "Could not find FortiClient in Uninstall registry keys."
}
$exePath = Get-ChildItem "C:\Program Files\Fortinet\FortiClient\fortivpn.exe" -ErrorAction SilentlyContinue
if ($exePath) {
    $ver = (Get-Item $exePath.FullName).VersionInfo
    Write-Line "fortivpn.exe:    $($ver.FileVersion)  (arch check below)"
    $peHeader = [System.Reflection.AssemblyName]::GetAssemblyName($exePath.FullName) 2>$null
}

# ---------------------------------------------------------------------------
Write-Section "IKEEXT / RasMan Service State (known port 500/4500 conflict source)"
foreach ($svc in @('IKEEXT','RemoteAccess','RasMan','PolicyAgent')) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        Write-Line ("{0,-14} Status={1,-8} StartType={2}" -f $s.Name, $s.Status, $s.StartType)
    } else {
        Write-Line "$svc`: service not found"
    }
}

# ---------------------------------------------------------------------------
Write-Section "FortiClient Service State"
Get-Service | Where-Object { $_.DisplayName -like "*Forti*" } | ForEach-Object {
    Write-Line ("{0,-30} Status={1,-8} StartType={2}" -f $_.Name, $_.Status, $_.StartType)
}

# ---------------------------------------------------------------------------
Write-Section "UDP 500 / 4500 Port Ownership"
foreach ($port in 500,4500) {
    $eps = Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue
    if ($eps) {
        foreach ($ep in $eps) {
            $procName = (Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            Write-Line "UDP $port -> PID $($ep.OwningProcess) ($procName) local=$($ep.LocalAddress)"
        }
    } else {
        Write-Line "UDP $port -> no listener bound"
    }
}

# ---------------------------------------------------------------------------
Write-Section "Virtual / VPN Adapters"
Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -match 'Fortinet|WAN Miniport|IKEv2|IPsec|Forti'
} | Select-Object Name, InterfaceDescription, Status, MacAddress | ForEach-Object {
    Write-Line ("{0,-20} {1,-40} Status={2}" -f $_.Name, $_.InterfaceDescription, $_.Status)
}
Write-Line "`n(If nothing listed above, the IPsec virtual adapter never came up for this attempt.)"

# ---------------------------------------------------------------------------
Write-Section "System Event Log - RRAS / IKEEXT / RasClient (last $SinceMinutes min)"
Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    StartTime = $since
} -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'RasClient|RemoteAccess|IKEEXT|Rasman' -or $_.Id -in 20227,13801,13868 } |
    Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
    ForEach-Object {
        Write-Line "`n[$($_.TimeCreated)] Id=$($_.Id) [$($_.ProviderName)] $($_.LevelDisplayName)"
        Write-Line "$($_.Message)"
    }

# ---------------------------------------------------------------------------
Write-Section "Application Event Log - FortiClient (last $SinceMinutes min)"
Get-WinEvent -FilterHashtable @{
    LogName   = 'Application'
    StartTime = $since
} -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Forti' -or $_.Message -match 'fortivpn|FortiClient' } |
    Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
    ForEach-Object {
        Write-Line "`n[$($_.TimeCreated)] Id=$($_.Id) [$($_.ProviderName)] $($_.LevelDisplayName)"
        Write-Line "$($_.Message)"
    }

# ---------------------------------------------------------------------------
Write-Section "Driver Signing / Faulting Module Check (Application log, last $SinceMinutes min)"
Get-WinEvent -FilterHashtable @{
    LogName   = 'Application'
    StartTime = $since
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 1000,1001 -and $_.Message -match 'forti' } |
    Select-Object TimeCreated, Id, Message |
    ForEach-Object {
        Write-Line "`n[$($_.TimeCreated)] Id=$($_.Id)"
        Write-Line "$($_.Message)"
    }

# ---------------------------------------------------------------------------
$sb.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`nReport saved to: $OutputPath" -ForegroundColor Green
