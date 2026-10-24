@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\mutable-control-repro\td2ega_mutable_control.dll exit /b 2
if not exist analysis\build\mutable-control-repro mkdir analysis\build\mutable-control-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_mutable_control.c /Foanalysis\build\mutable-control-repro\ /Feanalysis\build\mutable-control-repro\td2ega_mutable_control.dll /link /EXPORT:td2ega_mutable_control_reset /EXPORT:td2ega_mutable_main /IMPLIB:analysis\build\mutable-control-repro\td2ega_mutable_control.lib
