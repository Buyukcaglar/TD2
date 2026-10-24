@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\wait-roots-repro\td2ega_wait_roots.dll exit /b 2
if not exist analysis\build\wait-roots-repro mkdir analysis\build\wait-roots-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_wait_roots.c src\recovered\td2ega_input_bridge.c src\recovered\td2ega_wait_control.c src\recovered\td2ega_small_state.c /Foanalysis\build\wait-roots-repro\ /Feanalysis\build\wait-roots-repro\td2ega_wait_roots.dll /link /EXPORT:td2ega_wait_roots /IMPLIB:analysis\build\wait-roots-repro\td2ega_wait_roots.lib
