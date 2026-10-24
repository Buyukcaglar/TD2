@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\scalar-state-repro\td2ega_scalar_state.dll exit /b 2
if not exist analysis\build\scalar-state-repro mkdir analysis\build\scalar-state-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_scalar_state.c /Foanalysis\build\scalar-state-repro\ /Feanalysis\build\scalar-state-repro\td2ega_scalar_state.dll /link /EXPORT:td2ega_scalar_state /IMPLIB:analysis\build\scalar-state-repro\td2ega_scalar_state.lib
