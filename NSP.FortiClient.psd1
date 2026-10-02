@{
    RootModule        = 'NSP.FortiClient.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'd1c5255e-efc5-4619-a4a5-b9b85f91f14b'
    Author            = 'Network Systems Plus'
    CompanyName       = 'Network Systems Plus'
    Copyright         = '(c) Network Systems Plus. All rights reserved.'
    Description       = 'FortiClient VPN endpoint troubleshooting for NSP deployments: the FortiClient Connection Troubleshooting Toolkit (readiness check, detached IKEv2/packet captures that survive a dropped remote session, firewall/EDR sweep and WFP block auditing, FortiGate-side CLI generator). Windows PowerShell 5.1 compatible.'

    # 5.1 is the floor for every NSP toolkit, and the module must import on a bare 5.1 host -
    # sibling NSP modules are loaded on first use (Private\Import-NSPToolkitModule.ps1), never
    # declared as RequiredModules.
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Get-NSPFortiGateDiagnosticCommand'
        'New-NSPFortiClientShim'
        'Show-NSPFortiGateCLICommand'
        'Start-NSPFortiClientIKEv2Capture'
        'Start-NSPFortiClientPacketCapture'
        'Start-NSPFortiClientToolkit'
        'Stop-NSPFortiClientCapture'
        'Test-NSPFortiClientFirewallBlocking'
        'Test-NSPFortiClientIKEv2Readiness'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('NSP', 'FortiClient', 'FortiGate', 'VPN', 'IKEv2', 'Troubleshooting', 'Windows')
            ProjectUri   = 'https://github.com/ITGuyFromIA2/NSP-FortiClient'
            LicenseUri   = 'https://github.com/ITGuyFromIA2/NSP-FortiClient/blob/main/LICENSE'
            ReleaseNotes = 'https://github.com/ITGuyFromIA2/NSP-FortiClient/blob/main/CHANGELOG.md'
        }
    }
}