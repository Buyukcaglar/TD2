@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\raw-write-repro\td2ega_raw_write.dll exit /b 2
if not exist analysis\build\raw-write-repro mkdir analysis\build\raw-write-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_raw_write.c /Foanalysis\build\raw-write-repro\ /Feanalysis\build\raw-write-repro\td2ega_raw_write.dll /link /EXPORT:td2ega_raw_write /IMPLIB:analysis\build\raw-write-repro\td2ega_raw_write.lib
