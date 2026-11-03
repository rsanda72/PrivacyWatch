# Builds a Windows release and packages it as dist\PrivacyWatch-<version>-<commit>[-dirty]\ plus a .zip.
# Usage: .\tools\package.ps1 [-Flutter H:\Programing\tools\flutter\bin] [-SkipTests]
param(
  [string]$Flutter = 'H:\Programing\tools\flutter\bin',
  [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$env:Path = "$Flutter;$env:Path"

$version = ((Select-String -Path pubspec.yaml -Pattern '^version:\s*(\S+)').Matches[0].Groups[1].Value) -replace '\+', '.'
$commit = (git rev-parse --short HEAD).Trim()
$dirty = if (git status --porcelain) { '-dirty' } else { '' }
$name = "PrivacyWatch-$version-$commit$dirty"

flutter analyze lib; if ($LASTEXITCODE) { throw 'analyze failed' }
if (-not $SkipTests) { flutter test; if ($LASTEXITCODE) { throw 'tests failed' } }
flutter build windows --release; if ($LASTEXITCODE) { throw 'build failed' }

$out = Join-Path $root "dist\$name"
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Path $out | Out-Null
Copy-Item "$root\build\windows\x64\runner\Release\*" $out -Recurse
"PrivacyWatch $version`ncommit $commit$dirty`nbuilt $(Get-Date -Format s)" | Set-Content "$out\BUILD-INFO.txt"
Compress-Archive -Path "$out\*" -DestinationPath "$out.zip" -Force
Write-Host "Packaged: $out`n          $out.zip"
