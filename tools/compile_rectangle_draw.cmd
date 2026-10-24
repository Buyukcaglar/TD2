@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\rectangle-draw-repro\td2ega_rectangle_draw.dll exit /b 2
if not exist analysis\build\rectangle-draw-repro mkdir analysis\build\rectangle-draw-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_rectangle_draw.c /Foanalysis\build\rectangle-draw-repro\ /Feanalysis\build\rectangle-draw-repro\td2ega_rectangle_draw.dll /link /EXPORT:td2ega_rectangle_draw /IMPLIB:analysis\build\rectangle-draw-repro\td2ega_rectangle_draw.lib
