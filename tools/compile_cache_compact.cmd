@echo off
rem Synthetic external storage and metadata only; no original resources.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\cache-compact-repro\td2ega_cache_compact.dll exit /b 2
if not exist analysis\build\cache-compact-repro mkdir analysis\build\cache-compact-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_paragraph_copy.c src\recovered\td2ega_cache_compact.c /Foanalysis\build\cache-compact-repro\ /Feanalysis\build\cache-compact-repro\td2ega_cache_compact.dll /link /EXPORT:td2ega_cache_compact /IMPLIB:analysis\build\cache-compact-repro\td2ega_cache_compact.lib
