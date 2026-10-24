@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\point-update-repro\td2ega_point_update.dll exit /b 2
if not exist analysis\build\point-update-repro mkdir analysis\build\point-update-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_point_update.c src\recovered\td2ega_pixel_point.c /Foanalysis\build\point-update-repro\ /Feanalysis\build\point-update-repro\td2ega_point_update.dll /link /EXPORT:td2ega_point_update /IMPLIB:analysis\build\point-update-repro\td2ega_point_update.lib
