@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\timer-control-repro\td2ega_timer_control.dll exit /b 2
if not exist analysis\build\timer-control-repro mkdir analysis\build\timer-control-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_timer_control.c /Foanalysis\build\timer-control-repro\ /Feanalysis\build\timer-control-repro\td2ega_timer_control.dll /link /EXPORT:td2ega_timer_install_divisor /EXPORT:td2ega_timer_install_fixed /EXPORT:td2ega_timer_cleanup /IMPLIB:analysis\build\timer-control-repro\td2ega_timer_control.lib
