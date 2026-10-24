@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\seek-handle-repro\td2ega_seek_handle.dll exit /b 2
if not exist analysis\build\seek-handle-repro mkdir analysis\build\seek-handle-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_seek_handle.c src\recovered\td2ega_table_scalar.c /Foanalysis\build\seek-handle-repro\ /Feanalysis\build\seek-handle-repro\td2ega_seek_handle.dll /link /EXPORT:td2ega_seek_handle /IMPLIB:analysis\build\seek-handle-repro\td2ega_seek_handle.lib
