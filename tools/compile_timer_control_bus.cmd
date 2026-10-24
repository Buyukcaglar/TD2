@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\timer-control-bus-repro\td2ega_timer_control_bus.dll exit /b 2
if not exist analysis\build\timer-control-bus-repro mkdir analysis\build\timer-control-bus-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_timer_control_bus.c /Foanalysis\build\timer-control-bus-repro\ /Feanalysis\build\timer-control-bus-repro\td2ega_timer_control_bus.dll /link /EXPORT:td2ega_timer_control_bus /IMPLIB:analysis\build\timer-control-bus-repro\td2ega_timer_control_bus.lib
