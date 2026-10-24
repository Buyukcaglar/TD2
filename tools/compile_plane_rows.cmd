@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\plane-rows-repro\td2ega_plane_rows.dll exit /b 2
if not exist analysis\build\plane-rows-repro mkdir analysis\build\plane-rows-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_plane_rows.c src\recovered\td2ega_plane_span.c /Foanalysis\build\plane-rows-repro\ /Feanalysis\build\plane-rows-repro\td2ega_plane_rows.dll /link /EXPORT:td2ega_plane_rows /IMPLIB:analysis\build\plane-rows-repro\td2ega_plane_rows.lib
