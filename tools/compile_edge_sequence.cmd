@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\edge-sequence-repro\td2ega_edge_sequence.dll exit /b 2
if not exist analysis\build\edge-sequence-repro mkdir analysis\build\edge-sequence-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_edge_sequence.c /Foanalysis\build\edge-sequence-repro\ /Feanalysis\build\edge-sequence-repro\td2ega_edge_sequence.dll /link /EXPORT:td2ega_edge_sequence /IMPLIB:analysis\build\edge-sequence-repro\td2ega_edge_sequence.lib
