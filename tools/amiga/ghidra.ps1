param([string]$File = 'runs\amiga\duel', [string]$A4 = '2957e', [string]$CodeStart = '10000', [string]$CodeEnd = '2155c')
# Decompiles an Amiga load file with Ghidra: lays it out with hunk.py, imports the image as 68000 code,
# sets A4, analyses, and writes every function to runs\amiga-ghidra\<name>.c. Overwrites earlier output.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location -LiteralPath $root
$ghidraRoot = 'C:\Projects\Civ1RE\tools\ghidra_12.1.3_PUBLIC'
$env:JAVA_HOME = 'C:\Projects\Civ1RE\tools\jdk-21.0.12.1+1'
$work = Join-Path $root 'runs\amiga-ghidra'
$env:JAVA_TOOL_OPTIONS = "-Duser.home=$work\user -Dapplication.settingsdir=$work\settings -Dapplication.cachedir=$work\cache -Dapplication.tempdir=$work\temp -Djava.io.tmpdir=$work\temp"
$env:GHIDRA_HEADLESS_MAXMEM = '2G'
foreach ($d in 'user', 'settings', 'cache', 'temp', 'project') { New-Item -ItemType Directory -Force (Join-Path $work $d) | Out-Null }
$name = Split-Path -Leaf $File
$image = Join-Path $work "$name.bin"
python tools\amiga\hunk.py $File $image | Out-Null
$out = Join-Path $work "$name.c"
$ErrorActionPreference = 'Continue'   # Java writes its notices to stderr
&(Join-Path $ghidraRoot 'support\analyzeHeadless.bat') (Join-Path $work 'project') $name -overwrite `
    -import $image -loader BinaryLoader -loader-baseAddr 0 -processor '68000:BE:32:default' `
    -scriptPath (Join-Path $root 'tools\ghidra') -preScript AmigaSetup.java $A4 $CodeStart $CodeEnd `
    -postScript AmigaDecompile.java $out -analysisTimeoutPerFile 600 -log (Join-Path $work "$name.log")
if ($LASTEXITCODE -ne 0) { throw "Ghidra exited $LASTEXITCODE" }
"wrote $out"
