# Builds the game (Release) into build\ with MSVC 14.44 (VS 2022 BuildTools), the CMake and Ninja
# that ship with Visual Studio, SDL3 3.4.18 and the archive libraries (libarchive 3.8.1, zlib 1.3.1,
# xz 5.8.1), all built from their sources in analysis\external and linked statically, so
# build\TD2.exe is a single portable exe.
#   .\build.ps1            configure if needed, then build
#   .\build.ps1 -Clean     delete build\ first (the archive libraries stay built)
param([switch]$Clean)
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$build = Join-Path $root 'build'
$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$cmakeBin = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake'
$cmake = Join-Path $cmakeBin 'CMake\bin\cmake.exe'
$ninja = Join-Path $cmakeBin 'Ninja\ninja.exe'
$sdl = Join-Path $root 'analysis\external\sdl3-3.4.18\source'
$arc = Join-Path $root 'analysis\external\archive-libs'
$arcPrefix = (Join-Path $arc 'install') -replace '\\', '/'   # forward slashes: libarchive's CMake macros take them as strings

foreach ($p in $vcvars, $cmake, $ninja, (Join-Path $sdl 'CMakeLists.txt'), (Join-Path $arc 'libarchive-3.8.1')) {
    if (-not (Test-Path $p)) { throw "missing: $p" }
}
if ($Clean -and (Test-Path $build)) { Remove-Item -Recurse -Force $build }

# From here on, failures are detected by exit code: CMake prints notes on stderr, which
# PowerShell 5.1 would otherwise turn into errors when output is redirected.
$ErrorActionPreference = 'Continue'

# Run vcvars64 and import the environment it sets into this process.
$envDump = & cmd.exe /c "`"$vcvars`" 10.0.26100.0 -vcvars_ver=14.44 >nul 2>&1 && set"
if ($LASTEXITCODE -ne 0) { throw 'vcvars64.bat failed' }
foreach ($line in $envDump) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2]) }
}

# The archive libraries, built once into analysis\external\archive-libs\install: static, Release,
# static C runtime, only what reading zip, 7z, rar and lha needs.
function Build-Library([string]$name, [string[]]$options) {
    $src = Join-Path $arc $name
    $bld = Join-Path $arc "build-$name"
    & $cmake -S $src -B $bld -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" -DCMAKE_BUILD_TYPE=Release `
        -DCMAKE_C_COMPILER=cl -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -DCMAKE_POLICY_DEFAULT_CMP0091=NEW `
        "-DCMAKE_INSTALL_PREFIX=$arcPrefix" "-DCMAKE_PREFIX_PATH=$arcPrefix" -DBUILD_SHARED_LIBS=OFF @options
    if ($LASTEXITCODE -ne 0) { throw "configure $name failed" }
    & $cmake --build $bld --target install
    if ($LASTEXITCODE -ne 0) { throw "build $name failed" }
}
# Local patch: libarchive takes a level 1-3 LHA header only with the MS-DOS attribute 20h in it, but
# Amiga LhA writes its protection bits there (00h, 02h), so Amiga .lha archives were "Unrecognized
# archive format". libarchive reads the attributes it uses from the extended headers, not that byte.
$lhaSrc = Join-Path $arc 'libarchive-3.8.1\libarchive\archive_read_support_format_lha.c'
$lhaText = [IO.File]::ReadAllText($lhaSrc)
$lhaOld = 'if (p[H_LEVEL_OFFSET] <= 3 && p[H_ATTR_OFFSET] == 0x20)'
if ($lhaText.Contains($lhaOld)) {
    [IO.File]::WriteAllText($lhaSrc, $lhaText.Replace($lhaOld, 'if (p[H_LEVEL_OFFSET] <= 3)	/* TD2 port: any attribute (Amiga LhA) */'))
    Remove-Item -Force "$arcPrefix/lib/archive.lib" -ErrorAction SilentlyContinue
}
if (-not (Test-Path "$arcPrefix/lib/archive.lib")) {
    Build-Library 'zlib-1.3.1' @()
    Build-Library 'xz-5.8.1' @('-DXZ_NLS=OFF', '-DXZ_DOC=OFF', '-DXZ_TOOL_XZ=OFF', '-DXZ_TOOL_XZDEC=OFF',
        '-DXZ_TOOL_LZMADEC=OFF', '-DXZ_TOOL_LZMAINFO=OFF', '-DXZ_TOOL_SCRIPTS=OFF')
    $lib = "$arcPrefix/lib"
    $inc = "$arcPrefix/include"
    Build-Library 'libarchive-3.8.1' @("-DZLIB_LIBRARY=$lib/zlibstatic.lib", "-DZLIB_INCLUDE_DIR=$inc",
        "-DLIBLZMA_LIBRARY=$lib/lzma.lib", "-DLIBLZMA_INCLUDE_DIR=$inc", '-DLZMA_API_STATIC=ON',
        '-DENABLE_OPENSSL=OFF', '-DENABLE_LIBB2=OFF', '-DENABLE_LZ4=OFF', '-DENABLE_ZSTD=OFF', '-DENABLE_BZip2=OFF',
        '-DENABLE_LIBXML2=OFF', '-DENABLE_EXPAT=OFF', '-DENABLE_WIN32_XMLLITE=OFF', '-DENABLE_PCREPOSIX=OFF',
        '-DENABLE_PCRE2POSIX=OFF', '-DENABLE_LIBGCC=OFF', '-DENABLE_TAR=OFF', '-DENABLE_CPIO=OFF',
        '-DENABLE_CAT=OFF', '-DENABLE_UNZIP=OFF', '-DENABLE_TEST=OFF', '-DENABLE_ACL=OFF', '-DENABLE_XATTR=OFF',
        '-DENABLE_ICONV=OFF', '-DPOSIX_REGEX_LIB=NONE')
}

if (-not (Test-Path (Join-Path $build 'build.ninja'))) {
    & $cmake -S $root -B $build -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" -DCMAKE_BUILD_TYPE=Release `
        -DCMAKE_C_COMPILER=cl "-DTD2_SDL_SOURCE=$sdl" "-DTD2_ARCHIVE_PREFIX=$arcPrefix"
    if ($LASTEXITCODE -ne 0) { throw 'cmake configure failed' }
}
& $cmake --build $build
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
Write-Host "built $(Join-Path $build 'TD2.exe')"
