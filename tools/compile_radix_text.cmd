@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\radix-text-repro\td2ega_radix_text.dll exit /b 2
if not exist analysis\build\radix-text-repro mkdir analysis\build\radix-text-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_radix_text.c /Foanalysis\build\radix-text-repro\ /Feanalysis\build\radix-text-repro\td2ega_radix_text.dll /link /EXPORT:td2ega_radix_text /IMPLIB:analysis\build\radix-text-repro\td2ega_radix_text.lib
