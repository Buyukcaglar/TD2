@echo off
rem Recovered metadata algorithms only; no original resource input.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\cache-query-repro\td2ega_cache_query.dll exit /b 2
if not exist analysis\build\cache-query-repro mkdir analysis\build\cache-query-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_filename.c src\recovered\td2ega_cache_query.c /Foanalysis\build\cache-query-repro\ /Feanalysis\build\cache-query-repro\td2ega_cache_query.dll /link /EXPORT:td2ega_cache_name_present /EXPORT:td2ega_basename_offset /IMPLIB:analysis\build\cache-query-repro\td2ega_cache_query.lib
