@echo off
rem Recovered metadata algorithm only; no original resource input.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\cache-allocate-repro\td2ega_cache_allocate.dll exit /b 2
if not exist analysis\build\cache-allocate-repro mkdir analysis\build\cache-allocate-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_filename.c src\recovered\td2ega_cache_allocate.c /Foanalysis\build\cache-allocate-repro\ /Feanalysis\build\cache-allocate-repro\td2ega_cache_allocate.dll /link /EXPORT:td2ega_cache_allocate /IMPLIB:analysis\build\cache-allocate-repro\td2ega_cache_allocate.lib
