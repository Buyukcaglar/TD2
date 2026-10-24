# Builds the game (Release) into build\ with MSVC 14.44 (VS 2022 BuildTools), the CMake and Ninja
# that ship with Visual Studio, and SDL3 3.4.18 from analysis\external.
#   .\build.ps1            configure if needed, then build
#   .\build.ps1 -Clean     delete build\ first
param([switch]$Clean)
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$build = Join-Path $root 'build'
$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$cmakeBin = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake'
$cmake = Join-Path $cmakeBin 'CMake\bin\cmake.exe'
$ninja = Join-Path $cmakeBin 'Ninja\ninja.exe'
$sdl = Join-Path $root 'analysis\external\sdl3-3.4.18\sdk\SDL3-3.4.18\cmake'

foreach ($p in $vcvars, $cmake, $ninja, (Join-Path $sdl 'SDL3Config.cmake')) {
    if (-not (Test-Path $p)) { throw "missing: $p" }
}
if ($Clean -and (Test-Path $build)) { Remove-Item -Recurse -Force $build }

# Run vcvars64 and import the environment it sets into this process.
$envDump = & cmd.exe /c "`"$vcvars`" 10.0.26100.0 -vcvars_ver=14.44 >nul 2>&1 && set"
if ($LASTEXITCODE -ne 0) { throw 'vcvars64.bat failed' }
foreach ($line in $envDump) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2]) }
}

if (-not (Test-Path (Join-Path $build 'build.ninja'))) {
    & $cmake -S $root -B $build -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" -DCMAKE_BUILD_TYPE=Release `
        -DCMAKE_C_COMPILER=cl "-DSDL3_DIR=$sdl"
    if ($LASTEXITCODE -ne 0) { throw 'cmake configure failed' }
}
& $cmake --build $build
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
Write-Host "built $(Join-Path $build 'td2port.exe')"
