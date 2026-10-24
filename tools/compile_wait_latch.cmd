@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\wait-latch-repro\td2ega_wait_latch.dll exit /b 2
if not exist analysis\build\wait-latch-repro mkdir analysis\build\wait-latch-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_wait_latch.c src\recovered\td2ega_wait_control.c /Foanalysis\build\wait-latch-repro\ /Feanalysis\build\wait-latch-repro\td2ega_wait_latch.dll /link /EXPORT:td2ega_wait_latch /IMPLIB:analysis\build\wait-latch-repro\td2ega_wait_latch.lib
