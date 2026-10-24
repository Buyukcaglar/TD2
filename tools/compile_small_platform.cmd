@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\small-platform-repro\td2ega_small_platform.dll exit /b 2
if not exist analysis\build\small-platform-repro mkdir analysis\build\small-platform-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_small_platform.c /Foanalysis\build\small-platform-repro\ /Feanalysis\build\small-platform-repro\td2ega_small_platform.dll /link /EXPORT:td2ega_small_platform /IMPLIB:analysis\build\small-platform-repro\td2ega_small_platform.lib
