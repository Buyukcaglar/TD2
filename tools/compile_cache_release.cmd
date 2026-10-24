@echo off
rem Synthetic external storage and metadata only; no original resources.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\cache-release-repro\td2ega_cache_release.dll exit /b 2
if not exist analysis\build\cache-release-repro mkdir analysis\build\cache-release-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_paragraph_copy.c src\recovered\td2ega_cache_release.c /Foanalysis\build\cache-release-repro\ /Feanalysis\build\cache-release-repro\td2ega_cache_release.dll /link /EXPORT:td2ega_cache_release_fast /EXPORT:td2ega_cache_release_shift /IMPLIB:analysis\build\cache-release-repro\td2ega_cache_release.lib
