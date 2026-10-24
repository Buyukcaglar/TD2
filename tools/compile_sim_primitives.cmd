@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\sim-primitives-repro-v2\td2ega_sim_primitives.dll exit /b 2
if not exist analysis\build\sim-primitives-repro-v2 mkdir analysis\build\sim-primitives-repro-v2
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_sim_primitives.c /Foanalysis\build\sim-primitives-repro-v2\ /Feanalysis\build\sim-primitives-repro-v2\td2ega_sim_primitives.dll /link /EXPORT:td2ega_sum_eight_samples /EXPORT:td2ega_clamp_product_target /EXPORT:td2ega_signed_interval_overlap /EXPORT:td2ega_snapshot_stage_one /EXPORT:td2ega_snapshot_stage_two /EXPORT:td2ega_arm_transition_50 /EXPORT:td2ega_arm_transition_3c /EXPORT:td2ega_update_curve_record /EXPORT:td2ega_toggle_control_bit /EXPORT:td2ega_raise_byte_threshold /EXPORT:td2ega_lower_byte_threshold /EXPORT:td2ega_clear_transition /IMPLIB:analysis\build\sim-primitives-repro-v2\td2ega_sim_primitives.lib
