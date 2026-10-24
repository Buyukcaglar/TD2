@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\sprite-logic-repro\td2ega_sprite_logic.dll exit /b 2
if not exist analysis\build\sprite-logic-repro mkdir analysis\build\sprite-logic-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_sprite_logic.c src\recovered\td2ega_mask_span.c /Foanalysis\build\sprite-logic-repro\ /Feanalysis\build\sprite-logic-repro\td2ega_sprite_logic.dll /link /EXPORT:td2ega_sprite_logic /EXPORT:td2ega_sprite_logic_kernel /IMPLIB:analysis\build\sprite-logic-repro\td2ega_sprite_logic.lib
