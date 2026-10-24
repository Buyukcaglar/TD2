@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\session-init-repro\td2ega_session_init.dll exit /b 2
if not exist analysis\build\session-init-repro mkdir analysis\build\session-init-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_session_init.c src\recovered\td2ega_sim_primitives.c src\recovered\td2ega_timer_control.c src\recovered\td2ega_timer_callbacks.c /Foanalysis\build\session-init-repro\ /Feanalysis\build\session-init-repro\td2ega_session_init.dll /link /EXPORT:td2ega_zero_simulation_state /EXPORT:td2ega_reset_view_state /EXPORT:td2ega_reset_session_state /EXPORT:td2ega_install_simulation_state /IMPLIB:analysis\build\session-init-repro\td2ega_session_init.lib
