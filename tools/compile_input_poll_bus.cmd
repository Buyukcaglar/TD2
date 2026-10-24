@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\input-poll-bus-repro\td2ega_input_poll_bus.dll exit /b 2
if not exist analysis\build\input-poll-bus-repro mkdir analysis\build\input-poll-bus-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_input_poll_bus.c src\recovered\td2ega_keyboard_bios_bus.c src\recovered\td2ega_key_dispatch_bus.c src\recovered\td2ega_gameport_bus.c /Foanalysis\build\input-poll-bus-repro\ /Feanalysis\build\input-poll-bus-repro\td2ega_input_poll_bus.dll /link /EXPORT:td2ega_input_poll_bus /IMPLIB:analysis\build\input-poll-bus-repro\td2ega_input_poll_bus.lib
