@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\sprite-draw-repro\td2ega_sprite_draw.dll exit /b 2
if not exist analysis\build\sprite-draw-repro mkdir analysis\build\sprite-draw-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_sprite_draw.c src\recovered\td2ega_mask_span.c /Foanalysis\build\sprite-draw-repro\ /Feanalysis\build\sprite-draw-repro\td2ega_sprite_draw.dll /link /EXPORT:td2ega_sprite_draw /EXPORT:td2ega_sprite_kernel /IMPLIB:analysis\build\sprite-draw-repro\td2ega_sprite_draw.lib
