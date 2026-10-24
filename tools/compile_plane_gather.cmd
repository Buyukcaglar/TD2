@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\plane-gather-repro\td2ega_plane_gather.dll exit /b 2
if not exist analysis\build\plane-gather-repro mkdir analysis\build\plane-gather-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_plane_gather.c /Foanalysis\build\plane-gather-repro\ /Feanalysis\build\plane-gather-repro\td2ega_plane_gather.dll /link /EXPORT:td2ega_plane_gather /IMPLIB:analysis\build\plane-gather-repro\td2ega_plane_gather.lib
