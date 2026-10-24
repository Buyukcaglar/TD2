# Runs the game on a writable copy of the original DOS files.
#   .\run.ps1               play
#   .\run.ps1 --check       verify TD2EGA.EXE and exit
#   .\run.ps1 -RecordStates play and save a race state every 10 s to runs\states (60 at most, 1 MiB
#                           each, overwriting earlier ones) for the harness's sim_tick cases
# Extra arguments are passed to td2port.exe. reference\dos is never used directly: the first run
# copies it to runs\game, and scores and SELECT.DAT go to runs\profile.
param([switch]$RecordStates, [Parameter(ValueFromRemainingArguments)]$Rest)
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
if ($RecordStates) {
    $states = Join-Path $root 'runs\states'
    New-Item -ItemType Directory -Force $states | Out-Null
    $env:TD2_STATE_DIR = $states
    $env:TD2_STATE_EVERY = '1001'
    $env:TD2_STATE_MAX = '60'
}

# td2port.exe is a windowed app; piping its output makes PowerShell wait for it and set its exit code.
& $exe --game-dir $game --user-dir $profileDir @Rest | Out-Host
exit $LASTEXITCODE
