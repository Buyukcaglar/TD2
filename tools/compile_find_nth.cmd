@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\find-nth-repro\td2ega_find_nth.dll exit /b 2
if not exist analysis\build\find-nth-repro mkdir analysis\build\find-nth-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_find_nth.c src\recovered\td2ega_find_files.c /Foanalysis\build\find-nth-repro\ /Feanalysis\build\find-nth-repro\td2ega_find_nth.dll /link /EXPORT:td2ega_find_nth /IMPLIB:analysis\build\find-nth-repro\td2ega_find_nth.lib
