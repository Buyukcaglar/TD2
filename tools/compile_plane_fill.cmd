@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\plane-fill-repro\td2ega_plane_fill.dll exit /b 2
if not exist analysis\build\plane-fill-repro mkdir analysis\build\plane-fill-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_plane_fill.c /Foanalysis\build\plane-fill-repro\ /Feanalysis\build\plane-fill-repro\td2ega_plane_fill.dll /link /EXPORT:td2ega_plane_fill /IMPLIB:analysis\build\plane-fill-repro\td2ega_plane_fill.lib
