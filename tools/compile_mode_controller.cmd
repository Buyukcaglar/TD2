@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\mode-controller-repro\td2ega_mode_controller.dll exit /b 2
if not exist analysis\build\mode-controller-repro mkdir analysis\build\mode-controller-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_mode_controller.c src\recovered\td2ega_record_dispatch.c src\recovered\td2ega_record_math.c src\recovered\td2ega_small_algorithms.c src\recovered\td2ega_table_scalar.c src\recovered\td2ega_control_bus.c /Foanalysis\build\mode-controller-repro\ /Feanalysis\build\mode-controller-repro\td2ega_mode_controller.dll /link /EXPORT:td2ega_mode_controller /IMPLIB:analysis\build\mode-controller-repro\td2ega_mode_controller.lib
