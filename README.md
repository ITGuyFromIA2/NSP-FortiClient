# NSP.FortiClient

FortiClient VPN endpoint troubleshooting for NSP deployments - the **FortiClient Connection
Troubleshooting Toolkit** (formerly the zip-delivered FCT toolkit in NSP-FGTIPSecTools). Windows
PowerShell **5.1** compatible (and 7+); imports on a bare host.

Run it **on the machine with the connection problem**, typically over a remote session - the captures
and block auditing keep running if that session drops.

## Start it

```powershell
Start-NSPFortiClientToolkit                 # the menu (relaunches elevated)
Start-NSPToolkit -Tool FortiClient          # same, via the NSP.Toolkit launcher
New-NSPFortiClientShim -Path C:\Temp\FortiClient-Toolkit.ps1   # a launcher to drop on the endpoint
```

Typical flow for a live IKEv2 failure: readiness check (1) and monitoring (2) **before** the attempt,
the FortiGate CLI commands (7) on the FortiGate side, the user tries to connect, then the firewall/EDR
check (3) and blocked connections (4).

## What's in it

| Function | Menu | Purpose |
|---|---|---|
| `Start-NSPFortiClientToolkit` | - | The menu. Output goes to `C:\Admin\FCTToolkit\Output` (`-OutputRoot`). |
| `Test-NSPFortiClientIKEv2Readiness` | 1 | Pre-attempt snapshot: services, IKE ports, adapters, recent events. |
| `Start-NSPFortiClientIKEv2Capture` | 2 | Detached, timed FortiClient/IKEv2 state capture. |
| `Start-NSPFortiClientPacketCapture` | 2 | pktmon capture of UDP 500/4500 with a detached stop timer. |
| `Test-NSPFortiClientFirewallBlocking` | 2, 3, 4, 6 | Firewall/EDR sweep; WFP block auditing on / read back / off. |
| `Stop-NSPFortiClientCapture` | 5 | End running captures early. |
| `Show-NSPFortiGateCLICommand` | 7 | FortiGate-side diagnostics pre-filled with this machine's public IP; copies to the clipboard. |
| `Get-NSPFortiGateDiagnosticCommand` | - | The same FortiGate commands as plain text for a given IP - no prompts (scripts, RMM). |
| `New-NSPFortiClientShim` | - | A launcher script (NSP.ClientScripts ToolShim recipe). |

## Source layout

The five diagnostic scripts ship verbatim in `Scripts\` and the public functions call them. They stay
scripts because the two captures relaunch themselves detached by path (`-File $PSCommandPath`) so a
capture survives a dropped remote session. They are not linted yet (`tools\AnalyzerBaseline.txt`).

## Tests

```powershell
.\tools\Test-Repo.ps1      # PSScriptAnalyzer + Pester 5 under Windows PowerShell 5.1 and pwsh
```

Nothing in the tests runs a capture, pktmon or auditpol for real.
