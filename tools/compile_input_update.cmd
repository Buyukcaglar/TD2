@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\input-update-repro-v3\td2ega_input_update.dll exit /b 2
if not exist analysis\build\input-update-repro-v3 mkdir analysis\build\input-update-repro-v3
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_input_update.c src\recovered\td2ega_input_poll.c src\recovered\td2ega_key_dispatch.c src\recovered\td2ega_gameport.c src\recovered\td2ega_input_control.c src\recovered\td2ega_sim_targets.c src\recovered\td2ega_sim_primitives.c src\recovered\td2ega_signed_motion.c src\recovered\td2ega_control_ops.c /Foanalysis\build\input-update-repro-v3\ /Feanalysis\build\input-update-repro-v3\td2ega_input_update.dll /link /EXPORT:td2ega_input_update /IMPLIB:analysis\build\input-update-repro-v3\td2ega_input_update.lib
