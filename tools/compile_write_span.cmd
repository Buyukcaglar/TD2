@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\write-span-repro\td2ega_write_span.dll exit /b 2
if not exist analysis\build\write-span-repro mkdir analysis\build\write-span-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_write_span.c /Foanalysis\build\write-span-repro\ /Feanalysis\build\write-span-repro\td2ega_write_span.dll /link /EXPORT:td2ega_write_span /IMPLIB:analysis\build\write-span-repro\td2ega_write_span.lib
