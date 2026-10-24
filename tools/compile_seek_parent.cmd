@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\seek-parent-repro\td2ega_seek_parent.dll exit /b 2
if not exist analysis\build\seek-parent-repro mkdir analysis\build\seek-parent-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_seek_parent.c src\recovered\td2ega_seek_handle.c src\recovered\td2ega_table_scalar.c /Foanalysis\build\seek-parent-repro\ /Feanalysis\build\seek-parent-repro\td2ega_seek_parent.dll /link /EXPORT:td2ega_seek_parent /IMPLIB:analysis\build\seek-parent-repro\td2ega_seek_parent.lib
