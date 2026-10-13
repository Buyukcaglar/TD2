param(
    [ValidateSet('Import', 'Verify')][string]$Mode = 'Import',
    [ValidatePattern('^[a-zA-Z0-9-]+$')][string]$Revision = 'v2'
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $taskRoot
$ghidraRoot = 'C:\Projects\Civ1RE\tools\ghidra_12.1.3_PUBLIC'
$env:JAVA_HOME = 'C:\Projects\Civ1RE\tools\jdk-21.0.12.1+1'
$privateRoot = Join-Path $taskRoot 'analysis'
$env:JAVA_TOOL_OPTIONS = "-Duser.home=$privateRoot\ghidra-user -Dapplication.settingsdir=$privateRoot\ghidra-settings -Dapplication.cachedir=$privateRoot\ghidra-cache -Dapplication.tempdir=$privateRoot\ghidra-temp -Djava.io.tmpdir=$privateRoot\ghidra-temp"
$env:GHIDRA_HEADLESS_MAXMEM = '2G'
foreach ($directory in @('ghidra-user','ghidra-settings','ghidra-cache','ghidra-temp','ghidra-projects','logs')) {
    New-Item -ItemType Directory -Path (Join-Path $privateRoot $directory) -Force | Out-Null
}
$image = Join-Path $privateRoot 'derived\td2ega-v1\TD2EGA.image.bin'
$mz = Join-Path $privateRoot 'derived\td2ega-v1\TD2EGA.unpacked.exe'
if ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant() -ne '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4') {
    throw 'Unadmitted EGA image'
}
if ((Get-FileHash -LiteralPath $mz -Algorithm SHA256).Hash.ToLowerInvariant() -ne '71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2') {
    throw 'Unadmitted normalized MZ'
}
$projects = Join-Path $privateRoot 'ghidra-projects'
if ($Mode -eq 'Import') {
    $project = "TD2EGA-$Revision"
    $export = Join-Path $privateRoot "exports\td2ega-$Revision"
    if ((Test-Path -LiteralPath (Join-Path $projects "$project.gpr")) -or (Test-Path -LiteralPath $export)) {
        throw 'Choose a fresh project/export revision; existing analysis is preserved'
    }
    $headlessArguments = @($projects, $project, '-import', $mz, '-loader', 'MzLoader',
        '-processor', 'x86:LE:16:Real Mode', '-cspec', 'default',
        '-analysisTimeoutPerFile', '180', '-max-cpu', '2',
        '-scriptPath', (Join-Path $taskRoot 'tools\ghidra'),
        '-postScript', 'ExportRecovery.java', $export)
    $expectedOutput = Join-Path $export 'program-analysis.json'
} else {
    $expectedOutput = Join-Path $taskRoot "docs\recovery\evidence\td2ega-ghidra-$Revision.json"
    if (Test-Path -LiteralPath $expectedOutput) { throw 'Verification record already exists' }
    $headlessArguments = @($projects, 'TD2EGA', '-process', 'TD2EGA.unpacked.exe',
        '-noanalysis', '-readOnly', '-scriptPath', (Join-Path $taskRoot 'tools\ghidra'),
        '-postScript', 'VerifyMzImport.java', $image, $mz, $expectedOutput)
}
$headlessArguments += @('-log', (Join-Path $privateRoot "logs\ega-$Mode-$Revision.log"),
    '-scriptlog', (Join-Path $privateRoot "logs\ega-$Mode-$Revision-script.log"))
& (Join-Path $ghidraRoot 'support\analyzeHeadless.bat') @headlessArguments
if ($LASTEXITCODE -ne 0) { throw "Ghidra exited $LASTEXITCODE" }
if (!(Test-Path -LiteralPath $expectedOutput)) { throw 'Expected analysis/verification output missing' }
$result = Get-Content -LiteralPath $expectedOutput -Raw | ConvertFrom-Json
if ($Mode -eq 'Verify' -and $result.result -ne 'pass') { throw 'Imported image verification failed' }
Write-Output "Persisted $expectedOutput"
