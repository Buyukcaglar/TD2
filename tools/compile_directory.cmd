@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\directory-repro-v2\td2ega_directory.dll exit /b 2
if not exist analysis\build\directory-repro-v2 mkdir analysis\build\directory-repro-v2
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_directory.c /Foanalysis\build\directory-repro-v2\ /Feanalysis\build\directory-repro-v2\td2ega_directory.dll /link /EXPORT:td2ega_directory_find /IMPLIB:analysis\build\directory-repro-v2\td2ega_directory.lib
