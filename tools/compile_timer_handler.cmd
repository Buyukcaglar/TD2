@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\timer-handler-repro\td2ega_timer_handler.dll exit /b 2
if not exist analysis\build\timer-handler-repro mkdir analysis\build\timer-handler-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_timer_handler.c /Foanalysis\build\timer-handler-repro\ /Feanalysis\build\timer-handler-repro\td2ega_timer_handler.dll /link /EXPORT:td2ega_timer_handler /EXPORT:td2ega_timer_chain_old /IMPLIB:analysis\build\timer-handler-repro\td2ega_timer_handler.lib
