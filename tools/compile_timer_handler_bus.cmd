@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\timer-handler-bus-repro-v3\td2ega_timer_handler_bus.dll exit /b 2
if not exist analysis\build\timer-handler-bus-repro-v3 mkdir analysis\build\timer-handler-bus-repro-v3
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_timer_handler_bus.c /Foanalysis\build\timer-handler-bus-repro-v3\ /Feanalysis\build\timer-handler-bus-repro-v3\td2ega_timer_handler_bus.dll /link /EXPORT:td2ega_timer_handler_bus /IMPLIB:analysis\build\timer-handler-bus-repro-v3\td2ega_timer_handler_bus.lib
