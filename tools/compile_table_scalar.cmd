@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\table-scalar-repro\td2ega_table_scalar.dll exit /b 2
if not exist analysis\build\table-scalar-repro mkdir analysis\build\table-scalar-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_table_scalar.c /Foanalysis\build\table-scalar-repro\ /Feanalysis\build\table-scalar-repro\td2ega_table_scalar.dll /link /EXPORT:td2ega_table_scalar /IMPLIB:analysis\build\table-scalar-repro\td2ega_table_scalar.lib
