@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\scan-length-repro\td2ega_scan_length.dll exit /b 2
if not exist analysis\build\scan-length-repro mkdir analysis\build\scan-length-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_scan_length.c /Foanalysis\build\scan-length-repro\ /Feanalysis\build\scan-length-repro\td2ega_scan_length.dll /link /EXPORT:td2ega_scan_length /IMPLIB:analysis\build\scan-length-repro\td2ega_scan_length.lib
