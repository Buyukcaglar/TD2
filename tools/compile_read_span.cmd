@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\read-span-repro\td2ega_read_span.dll exit /b 2
if not exist analysis\build\read-span-repro mkdir analysis\build\read-span-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_read_span.c /Foanalysis\build\read-span-repro\ /Feanalysis\build\read-span-repro\td2ega_read_span.dll /link /EXPORT:td2ega_read_span /IMPLIB:analysis\build\read-span-repro\td2ega_read_span.lib
