@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\sim-controller-repro\td2ega_sim_controller.dll exit /b 2
if not exist analysis\build\sim-controller-repro mkdir analysis\build\sim-controller-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_sim_controller.c src\recovered\td2ega_window_controllers.c src\recovered\td2ega_threshold_transition.c src\recovered\td2ega_indexed_sample.c src\recovered\td2ega_sample_guards.c src\recovered\td2ega_table_scalar.c src\recovered\td2ega_sim_dispatch_bus.c src\recovered\td2ega_sample_adjust.c src\recovered\td2ega_control_bus.c src\recovered\td2ega_byte_ring.c src\recovered\td2ega_sim_primitives.c /Foanalysis\build\sim-controller-repro\ /Feanalysis\build\sim-controller-repro\td2ega_sim_controller.dll /link /EXPORT:td2ega_sim_controller /IMPLIB:analysis\build\sim-controller-repro\td2ega_sim_controller.lib
