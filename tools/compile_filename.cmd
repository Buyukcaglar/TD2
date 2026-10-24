@echo off
rem Compile recovered algorithm only; no original files are compiler inputs.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\filename-repro\td2ega_filename.dll exit /b 2
if not exist analysis\build\filename-repro mkdir analysis\build\filename-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_filename.c /Foanalysis\build\filename-repro\td2ega_filename.obj /Feanalysis\build\filename-repro\td2ega_filename.dll /link /EXPORT:td2ega_basename_offset /IMPLIB:analysis\build\filename-repro\td2ega_filename.lib
