@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\delete-file-repro\td2ega_delete_file.dll exit /b 2
if not exist analysis\build\delete-file-repro mkdir analysis\build\delete-file-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_delete_file.c src\recovered\td2ega_table_scalar.c /Foanalysis\build\delete-file-repro\ /Feanalysis\build\delete-file-repro\td2ega_delete_file.dll /link /EXPORT:td2ega_delete_file /IMPLIB:analysis\build\delete-file-repro\td2ega_delete_file.lib
