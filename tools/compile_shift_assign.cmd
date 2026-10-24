@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\shift-assign-repro\td2ega_shift_assign.dll exit /b 2
if not exist analysis\build\shift-assign-repro mkdir analysis\build\shift-assign-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_shift_assign.c src\recovered\td2ega_small_state.c /Foanalysis\build\shift-assign-repro\ /Feanalysis\build\shift-assign-repro\td2ega_shift_assign.dll /link /EXPORT:td2ega_shift_assign /IMPLIB:analysis\build\shift-assign-repro\td2ega_shift_assign.lib
