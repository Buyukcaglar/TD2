@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\near-clamp-repro\td2ega_near_clamp.dll exit /b 2
if not exist analysis\build\near-clamp-repro mkdir analysis\build\near-clamp-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_near_clamp.c /Foanalysis\build\near-clamp-repro\ /Feanalysis\build\near-clamp-repro\td2ega_near_clamp.dll /link /EXPORT:td2ega_near_clamp /IMPLIB:analysis\build\near-clamp-repro\td2ega_near_clamp.lib
