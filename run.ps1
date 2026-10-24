# Runs the game on a writable copy of the original DOS files.
#   .\run.ps1               play
#   .\run.ps1 --check       verify TD2EGA.EXE and exit
# Extra arguments are passed to td2port.exe. reference\dos is never used directly: the first run
# copies it to runs\game, and scores and SELECT.DAT go to runs\profile.
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$exe = Join-Path $root 'build\td2port.exe'
$source = Join-Path $root 'reference\dos'
$game = Join-Path $root 'runs\game'
$profileDir = Join-Path $root 'runs\profile'

if (-not (Test-Path $exe)) { throw "not built yet: run .\build.ps1 first" }
if (-not (Test-Path $game)) {
    New-Item -ItemType Directory -Force $game | Out-Null
    Copy-Item -Path (Join-Path $source '*') -Destination $game -Recurse
    # The originals are read-only; the copy must be writable.
    Get-ChildItem $game -Recurse -File | ForEach-Object { $_.IsReadOnly = $false }
}
New-Item -ItemType Directory -Force $profileDir | Out-Null

& $exe --game-dir $game --user-dir $profileDir @args
exit $LASTEXITCODE
