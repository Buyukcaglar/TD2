@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\finalizer-list-repro\td2ega_finalizer_list.dll exit /b 2
if not exist analysis\build\finalizer-list-repro mkdir analysis\build\finalizer-list-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_finalizer_list.c /Foanalysis\build\finalizer-list-repro\ /Feanalysis\build\finalizer-list-repro\td2ega_finalizer_list.dll /link /EXPORT:td2ega_finalizer_list /IMPLIB:analysis\build\finalizer-list-repro\td2ega_finalizer_list.lib
