@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\keyboard-bios-bus-repro\td2ega_keyboard_bios_bus.dll exit /b 2
if not exist analysis\build\keyboard-bios-bus-repro mkdir analysis\build\keyboard-bios-bus-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_keyboard_bios_bus.c /Foanalysis\build\keyboard-bios-bus-repro\ /Feanalysis\build\keyboard-bios-bus-repro\td2ega_keyboard_bios_bus.dll /link /EXPORT:td2ega_keyboard_bios_bus /IMPLIB:analysis\build\keyboard-bios-bus-repro\td2ega_keyboard_bios_bus.lib
