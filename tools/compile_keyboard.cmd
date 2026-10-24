@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\keyboard-repro\td2ega_keyboard.dll exit /b 2
if not exist analysis\build\keyboard-repro mkdir analysis\build\keyboard-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_keyboard.c /Foanalysis\build\keyboard-repro\ /Feanalysis\build\keyboard-repro\td2ega_keyboard.dll /link /EXPORT:td2ega_keyboard_install /EXPORT:td2ega_keyboard_restore /EXPORT:td2ega_keyboard_irq /EXPORT:td2ega_keyboard_bios /IMPLIB:analysis\build\keyboard-repro\td2ega_keyboard.lib
