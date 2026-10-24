@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\loop-controls-repro\td2ega_loop_controls.dll exit /b 2
if not exist analysis\build\loop-controls-repro mkdir analysis\build\loop-controls-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_loop_controls.c /Foanalysis\build\loop-controls-repro\ /Feanalysis\build\loop-controls-repro\td2ega_loop_controls.dll /link /EXPORT:td2ega_loop_control /IMPLIB:analysis\build\loop-controls-repro\td2ega_loop_controls.lib
