@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\find-files-repro\td2ega_find_files.dll exit /b 2
if not exist analysis\build\find-files-repro mkdir analysis\build\find-files-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_find_files.c /Foanalysis\build\find-files-repro\ /Feanalysis\build\find-files-repro\td2ega_find_files.dll /link /EXPORT:td2ega_find_first /EXPORT:td2ega_find_next /IMPLIB:analysis\build\find-files-repro\td2ega_find_files.lib
