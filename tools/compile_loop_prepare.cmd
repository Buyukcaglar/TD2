@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\loop-prepare-repro\td2ega_loop_prepare.dll exit /b 2
if not exist analysis\build\loop-prepare-repro mkdir analysis\build\loop-prepare-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_loop_prepare.c /Foanalysis\build\loop-prepare-repro\ /Feanalysis\build\loop-prepare-repro\td2ega_loop_prepare.dll /link /EXPORT:td2ega_loop_prepare /IMPLIB:analysis\build\loop-prepare-repro\td2ega_loop_prepare.lib
