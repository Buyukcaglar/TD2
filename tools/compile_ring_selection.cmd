@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\ring-selection-repro\td2ega_ring_selection.dll exit /b 2
if not exist analysis\build\ring-selection-repro mkdir analysis\build\ring-selection-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_ring_selection.c src\recovered\td2ega_byte_ring.c /Foanalysis\build\ring-selection-repro\ /Feanalysis\build\ring-selection-repro\td2ega_ring_selection.dll /link /EXPORT:td2ega_ring_selection /IMPLIB:analysis\build\ring-selection-repro\td2ega_ring_selection.lib
