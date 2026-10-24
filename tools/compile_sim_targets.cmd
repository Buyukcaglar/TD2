@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\sim-targets-repro\td2ega_sim_targets.dll exit /b 2
if not exist analysis\build\sim-targets-repro mkdir analysis\build\sim-targets-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_sim_targets.c /Foanalysis\build\sim-targets-repro\ /Feanalysis\build\sim-targets-repro\td2ega_sim_targets.dll /link /EXPORT:td2ega_update_sample_targets /EXPORT:td2ega_compare_target_delta /EXPORT:td2ega_adjust_target /IMPLIB:analysis\build\sim-targets-repro\td2ega_sim_targets.lib
