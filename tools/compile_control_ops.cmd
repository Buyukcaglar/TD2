@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\control-ops-repro\td2ega_control_ops.dll exit /b 2
if not exist analysis\build\control-ops-repro mkdir analysis\build\control-ops-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_control_ops.c src\recovered\td2ega_sim_primitives.c /Foanalysis\build\control-ops-repro\ /Feanalysis\build\control-ops-repro\td2ega_control_ops.dll /link /EXPORT:td2ega_small_control_dispatch /EXPORT:td2ega_decelerate_target /EXPORT:td2ega_decelerate_fixed /EXPORT:td2ega_adjust_scaled_target /EXPORT:td2ega_update_limit_counter /EXPORT:td2ega_update_interval_state /IMPLIB:analysis\build\control-ops-repro\td2ega_control_ops.lib
