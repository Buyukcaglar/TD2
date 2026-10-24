@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\motion-flags-bus-repro\td2ega_motion_flags_bus.dll exit /b 2
if not exist analysis\build\motion-flags-bus-repro mkdir analysis\build\motion-flags-bus-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_motion_flags_bus.c src\recovered\td2ega_signed_motion.c /Foanalysis\build\motion-flags-bus-repro\ /Feanalysis\build\motion-flags-bus-repro\td2ega_motion_flags_bus.dll /link /EXPORT:td2ega_motion_flags_bus /IMPLIB:analysis\build\motion-flags-bus-repro\td2ega_motion_flags_bus.lib
