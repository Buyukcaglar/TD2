@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\small-state-repro\td2ega_small_state.dll exit /b 2
if not exist analysis\build\small-state-repro mkdir analysis\build\small-state-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_small_state.c /Foanalysis\build\small-state-repro\ /Feanalysis\build\small-state-repro\td2ega_small_state.dll /link /EXPORT:td2ega_small_state /IMPLIB:analysis\build\small-state-repro\td2ega_small_state.lib
