@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\runtime-vectors-repro\td2ega_runtime_vectors.dll exit /b 2
if not exist analysis\build\runtime-vectors-repro mkdir analysis\build\runtime-vectors-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_runtime_vectors.c /Foanalysis\build\runtime-vectors-repro\ /Feanalysis\build\runtime-vectors-repro\td2ega_runtime_vectors.dll /link /EXPORT:td2ega_runtime_vectors /IMPLIB:analysis\build\runtime-vectors-repro\td2ega_runtime_vectors.lib
