@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\relative-wait-repro\td2ega_relative_wait.dll exit /b 2
if not exist analysis\build\relative-wait-repro mkdir analysis\build\relative-wait-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_relative_wait.c src\recovered\td2ega_small_state.c /Foanalysis\build\relative-wait-repro\ /Feanalysis\build\relative-wait-repro\td2ega_relative_wait.dll /link /EXPORT:td2ega_relative_wait /IMPLIB:analysis\build\relative-wait-repro\td2ega_relative_wait.lib
