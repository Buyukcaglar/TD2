@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\projection-repro\td2ega_projection.dll exit /b 2
if not exist analysis\build\projection-repro mkdir analysis\build\projection-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_projection.c /Foanalysis\build\projection-repro\ /Feanalysis\build\projection-repro\td2ega_projection.dll /link /EXPORT:td2ega_projection_step /EXPORT:td2ega_signed_byte_lookup /IMPLIB:analysis\build\projection-repro\td2ega_projection.lib
