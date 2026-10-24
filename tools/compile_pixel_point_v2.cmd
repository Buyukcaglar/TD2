@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\pixel-point-v2-repro\td2ega_pixel_point.dll exit /b 2
if not exist analysis\build\pixel-point-v2-repro mkdir analysis\build\pixel-point-v2-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_pixel_point.c /Foanalysis\build\pixel-point-v2-repro\ /Feanalysis\build\pixel-point-v2-repro\td2ega_pixel_point.dll /link /EXPORT:td2ega_pixel_point /IMPLIB:analysis\build\pixel-point-v2-repro\td2ega_pixel_point.lib
