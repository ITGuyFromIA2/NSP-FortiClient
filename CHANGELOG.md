# Changelog

All notable changes to NSP.FortiClient are documented here. Versions follow
[SemVer](https://semver.org/). `0.x` until it has real use outside NSP.

## 0.1.1

- From the 2026-10-02 review: the sibling loader announces Gallery installs (module, version, scope)
  and is generated from NSP-Toolkit's canonical copy; the module loader dot-sources files in name
  order. Needs NSP.Toolkit 0.1.1.

## 0.1.0

First release: the zip-era FCT toolkit (NSP-FGTIPSecTools 1.0.0) as a module - the menu, the five
diagnostic scripts behind public functions, Get-NSPFortiGateDiagnosticCommand, a launcher.

The other NSP modules it needs are installed from the PowerShell Gallery the first time they're needed,
so `Install-Module` of this one module is enough. Set `NSP_NO_AUTOINSTALL=1` to turn that off.
