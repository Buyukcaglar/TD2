@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\runtime-message-repro\td2ega_runtime_message.dll exit /b 2
if not exist analysis\build\runtime-message-repro mkdir analysis\build\runtime-message-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_runtime_message.c /Foanalysis\build\runtime-message-repro\ /Feanalysis\build\runtime-message-repro\td2ega_runtime_message.dll /link /EXPORT:td2ega_runtime_message /IMPLIB:analysis\build\runtime-message-repro\td2ega_runtime_message.lib
