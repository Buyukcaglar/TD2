@echo off
rem Synthetic external storage and metadata only; no original resources.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\cache-acquire-repro\td2ega_cache_acquire.dll exit /b 2
if not exist analysis\build\cache-acquire-repro mkdir analysis\build\cache-acquire-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_filename.c src\recovered\td2ega_paragraph_copy.c src\recovered\td2ega_cache_compact.c src\recovered\td2ega_cache_acquire.c /Foanalysis\build\cache-acquire-repro\ /Feanalysis\build\cache-acquire-repro\td2ega_cache_acquire.dll /link /EXPORT:td2ega_cache_acquire /IMPLIB:analysis\build\cache-acquire-repro\td2ega_cache_acquire.lib
