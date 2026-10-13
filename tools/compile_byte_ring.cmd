@echo off
rem Task-local compiler environment; original files are never inputs or outputs.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\byte-ring-repro\td2ega_byte_ring.dll exit /b 2
if not exist analysis\build\byte-ring-repro mkdir analysis\build\byte-ring-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_byte_ring.c /Foanalysis\build\byte-ring-repro\td2ega_byte_ring.obj /Feanalysis\build\byte-ring-repro\td2ega_byte_ring.dll /link /EXPORT:td2ega_byte_ring_step /IMPLIB:analysis\build\byte-ring-repro\td2ega_byte_ring.lib
