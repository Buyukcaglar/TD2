@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\window-controllers-repro\td2ega_window_controllers.dll exit /b 2
if not exist analysis\build\window-controllers-repro mkdir analysis\build\window-controllers-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_window_controllers.c src\recovered\td2ega_sample_adjust.c src\recovered\td2ega_control_bus.c src\recovered\td2ega_byte_ring.c src\recovered\td2ega_sim_primitives.c /Foanalysis\build\window-controllers-repro\ /Feanalysis\build\window-controllers-repro\td2ega_window_controllers.dll /link /EXPORT:td2ega_window_controllers /IMPLIB:analysis\build\window-controllers-repro\td2ega_window_controllers.lib
