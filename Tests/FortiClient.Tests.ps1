<#
    Pester 5. NSP.FortiClient: the wrappers around the toolkit scripts, the FortiGate command
    builder, the menu, and the launcher. Nothing here runs a capture, pktmon or auditpol for real.
#>

BeforeAll {
    $toolkits = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path (Split-Path -Parent $toolkits) 'NSP-Bootstrap\NSP.Bootstrap.psd1') -Force -Global -ErrorAction Stop
    foreach ($m in 'NSP-Console\NSP.Console.psd1', 'NSP-Toolkit\NSP.Toolkit.psd1', 'NSP-ClientScripts\NSP.ClientScripts.psd1') {
        Import-Module (Join-Path $toolkits $m) -Force -Global -ErrorAction Stop
    }
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.FortiClient.psd1') -Force -ErrorAction Stop
    $script:ScriptsDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Scripts'
}

AfterAll {
    Remove-Item Env:\NSP_TOOLKIT_ROOT -ErrorAction SilentlyContinue
    Remove-Module NSP.FortiClient -Force -ErrorAction SilentlyContinue
}

Describe 'NSP.FortiClient' {
    BeforeEach {
        $env:NSP_TOOLKIT_ROOT = Join-Path $TestDrive ('tk_' + [guid]::NewGuid().ToString('N'))
        Mock -ModuleName NSP.FortiClient Write-Host { }
    }

    Context 'Toolkit scripts' {
        It '<_> parses' -ForEach @('Show-FortiGateCLICommands.ps1', 'Start-FortiClientIKEv2Capture.ps1', 'Start-FortiClientPacketCapture.ps1', 'Test-FortiClientFirewallBlocking.ps1', 'Test-FortiClientIKEv2Readiness.ps1') {
            $parseErrors = $null
            [Management.Automation.Language.Parser]::ParseFile((Join-Path $ScriptsDir $_), [ref]$null, [ref]$parseErrors) | Out-Null
            $parseErrors | Should -BeNullOrEmpty
        }
    }

    Context 'Wrappers pass only what was given to the right script' {
        BeforeEach { Mock -ModuleName NSP.FortiClient Invoke-NSPFortiClientScript { } }

        It 'Test-NSPFortiClientIKEv2Readiness' {
            Test-NSPFortiClientIKEv2Readiness -SinceMinutes 45
            Should -Invoke -ModuleName NSP.FortiClient Invoke-NSPFortiClientScript -Times 1 -ParameterFilter {
                $Name -eq 'Test-FortiClientIKEv2Readiness.ps1' -and $Parameters.SinceMinutes -eq 45 -and -not $Parameters.ContainsKey('OutputPath')
            }
        }
        It 'Start-NSPFortiClientIKEv2Capture and -PacketCapture' {
            Start-NSPFortiClientIKEv2Capture -DurationMinutes 5 -OutputDir 'C:\x'
            Start-NSPFortiClientPacketCapture -DurationMinutes 7
            Should -Invoke -ModuleName NSP.FortiClient Invoke-NSPFortiClientScript -Times 1 -ParameterFilter {
                $Name -eq 'Start-FortiClientIKEv2Capture.ps1' -and $Parameters.DurationMinutes -eq 5 -and $Parameters.OutputDir -eq 'C:\x' -and $Parameters.Count -eq 2
            }
            Should -Invoke -ModuleName NSP.FortiClient Invoke-NSPFortiClientScript -Times 1 -ParameterFilter {
                $Name -eq 'Start-FortiClientPacketCapture.ps1' -and $Parameters.DurationMinutes -eq 7 -and $Parameters.Count -eq 1
            }
        }
        It 'the capture starters honour -WhatIf' {
            Start-NSPFortiClientIKEv2Capture -WhatIf
            Start-NSPFortiClientPacketCapture -WhatIf
            Should -Invoke -ModuleName NSP.FortiClient Invoke-NSPFortiClientScript -Times 0
        }
        It 'Test-NSPFortiClientFirewallBlocking' {
            Test-NSPFortiClientFirewallBlocking -ShowBlockedEvents -SinceMinutes 15
            Should -Invoke -ModuleName NSP.FortiClient Invoke-NSPFortiClientScript -Times 1 -ParameterFilter {
                $Name -eq 'Test-FortiClientFirewallBlocking.ps1' -and $Parameters.ShowBlockedEvents -and $Parameters.SinceMinutes -eq 15
            }
        }
        It 'Show-NSPFortiGateCLICommand' {
            Show-NSPFortiGateCLICommand -IPAddress 203.0.113.10 -CopyToClipboard None
            Should -Invoke -ModuleName NSP.FortiClient Invoke-NSPFortiClientScript -Times 1 -ParameterFilter {
                $Name -eq 'Show-FortiGateCLICommands.ps1' -and $Parameters.IPAddress -eq '203.0.113.10' -and $Parameters.CopyToClipboard -eq 'None'
            }
        }
    }

    Context 'Get-NSPFortiGateDiagnosticCommand' {
        It 'builds the IP-specific commands without prompting' {
            Mock -ModuleName NSP.FortiClient Read-Host { throw 'prompted' }
            $c = Get-NSPFortiGateDiagnosticCommand -ClientIP 203.0.113.10
            $c.SnifferCmd | Should -Be "diagnose sniffer packet any 'host 203.0.113.10 and (port 500 or port 4500)' 4 0 l"
            $c.IKEDebugCmd | Should -Match 'log-filter dst-addr4 203\.0\.113\.10'
            $c.IKEDebugCmd | Should -Match 'application ike -1'
            $c.IKEDebugCmd | Should -Match 'application fnbamd -1'
            $c.GatewayGetCmd | Should -BeNullOrEmpty
        }
        It 'adds the gateway get/clear commands and honours -DebugScope' {
            $c = Get-NSPFortiGateDiagnosticCommand -ClientIP 203.0.113.10 -P1Name 'Dialup-Vendor_0' -DebugScope IKE
            $c.GatewayGetCmd | Should -Be 'diagnose vpn ike gateway list name Dialup-Vendor_0'
            $c.GatewayClearCmd | Should -Be 'diagnose vpn ike gateway clear name Dialup-Vendor_0'
            $c.IKEDebugCmd | Should -Not -Match 'fnbamd'
        }
        It 'refuses something that is not an IPv4 address' {
            { Get-NSPFortiGateDiagnosticCommand -ClientIP 'host; rm' } | Should -Throw
        }
    }

    Context 'Menu' {
        BeforeEach {
            $script:Answers = [System.Collections.Generic.Queue[string]]::new()
            Mock -ModuleName NSP.FortiClient Read-Host { $script:Answers.Dequeue() }
            Mock -ModuleName NSP.FortiClient Set-NSPConsoleMaximized { }
            Mock -ModuleName NSP.FortiClient Get-NSPToolVersionStatus { [pscustomobject]@{ Label = 'v0.1.0' } }
            Mock -ModuleName NSP.FortiClient Test-NSPFortiClientIKEv2Readiness { }
            Mock -ModuleName NSP.FortiClient Start-NSPFortiClientIKEv2Capture { }
            Mock -ModuleName NSP.FortiClient Start-NSPFortiClientPacketCapture { }
            Mock -ModuleName NSP.FortiClient Test-NSPFortiClientFirewallBlocking { }
            Mock -ModuleName NSP.FortiClient Stop-NSPFortiClientCapture { }
            $script:Out = Join-Path $TestDrive ('out_' + [guid]::NewGuid().ToString('N'))
        }

        It 'runs the readiness check into Reports\ and returns on Q' {
            foreach ($a in '1', '', 'Q') { $Answers.Enqueue($a) }
            Start-NSPFortiClientToolkit -OutputRoot $Out -NoElevate
            Should -Invoke -ModuleName NSP.FortiClient Test-NSPFortiClientIKEv2Readiness -Times 1 -ParameterFilter {
                $SinceMinutes -eq 30 -and $OutputPath -like (Join-Path $Out 'Reports\FortiClient_IKEv2_Readiness_*.txt')
            }
            Test-Path -LiteralPath (Join-Path $Out 'Captures') | Should -BeTrue
        }
        It 'starts both captures and block auditing for monitoring option 3 (the default)' {
            foreach ($a in '2', '', '', 'Q') { $Answers.Enqueue($a) }
            Start-NSPFortiClientToolkit -OutputRoot $Out -NoElevate
            Should -Invoke -ModuleName NSP.FortiClient Start-NSPFortiClientIKEv2Capture -Times 1 -ParameterFilter { $DurationMinutes -eq 10 -and $OutputDir -eq (Join-Path $Out 'Captures') }
            Should -Invoke -ModuleName NSP.FortiClient Start-NSPFortiClientPacketCapture -Times 1
            Should -Invoke -ModuleName NSP.FortiClient Test-NSPFortiClientFirewallBlocking -Times 1 -ParameterFilter { $EnableBlockAuditing }
        }
        It 'stops captures in its own capture folder (5)' {
            foreach ($a in '5', 'q') { $Answers.Enqueue($a) }
            Start-NSPFortiClientToolkit -OutputRoot $Out -NoElevate
            Should -Invoke -ModuleName NSP.FortiClient Stop-NSPFortiClientCapture -Times 1 -ParameterFilter { $CaptureDir -eq (Join-Path $Out 'Captures') }
        }
    }

    Context 'Stop-NSPFortiClientCapture' {
        It 'drops the STOP flag and stops pktmon' {
            Mock -ModuleName NSP.FortiClient pktmon { }
            $dir = Join-Path $TestDrive 'cap'
            Stop-NSPFortiClientCapture -CaptureDir $dir
            Test-Path -LiteralPath (Join-Path $dir 'STOP') | Should -BeTrue
        }
        It 'changes nothing with -WhatIf' {
            Mock -ModuleName NSP.FortiClient pktmon { }
            $dir = Join-Path $TestDrive 'cap2'
            Stop-NSPFortiClientCapture -CaptureDir $dir -WhatIf
            Test-Path -LiteralPath $dir | Should -BeFalse
            Should -Invoke -ModuleName NSP.FortiClient pktmon -Times 0
        }
    }

    Context 'Launcher' {
        It 'writes a launcher with no answers that opens the toolkit' {
            $p = Join-Path $TestDrive 'FortiClient-Toolkit.ps1'
            New-NSPFortiClientShim -Path $p -GeneratedBy 'test' -Force | Should -BeOfType [IO.FileInfo]
            $text = Get-Content -LiteralPath $p -Raw
            $parseErrors = $null
            [Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$parseErrors) | Out-Null
            $parseErrors | Should -BeNullOrEmpty
            $text | Should -Match "EntryFunction\s+= 'Start-NSPFortiClientToolkit'"
            $text | Should -Match "ModuleName\s+= 'NSP\.FortiClient'"
        }
    }
}
