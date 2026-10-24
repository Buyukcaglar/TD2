@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\draw-sequence-repro\td2ega_draw_sequence.dll exit /b 2
if not exist analysis\build\draw-sequence-repro mkdir analysis\build\draw-sequence-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_draw_sequence.c /Foanalysis\build\draw-sequence-repro\ /Feanalysis\build\draw-sequence-repro\td2ega_draw_sequence.dll /link /EXPORT:td2ega_draw_sequence /IMPLIB:analysis\build\draw-sequence-repro\td2ega_draw_sequence.lib
