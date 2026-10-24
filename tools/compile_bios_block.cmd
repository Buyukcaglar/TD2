@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\bios-block-repro\td2ega_bios_block.dll exit /b 2
if not exist analysis\build\bios-block-repro mkdir analysis\build\bios-block-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_bios_block.c /Foanalysis\build\bios-block-repro\ /Feanalysis\build\bios-block-repro\td2ega_bios_block.dll /link /EXPORT:td2ega_bios_block /IMPLIB:analysis\build\bios-block-repro\td2ega_bios_block.lib
