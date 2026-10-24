@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\state-loop-repro\td2ega_state_loop.dll exit /b 2
if not exist analysis\build\state-loop-repro mkdir analysis\build\state-loop-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_state_loop.c /Foanalysis\build\state-loop-repro\ /Feanalysis\build\state-loop-repro\td2ega_state_loop.dll /link /EXPORT:td2ega_state_loop /IMPLIB:analysis\build\state-loop-repro\td2ega_state_loop.lib
