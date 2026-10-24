@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\input-bridge-repro\td2ega_input_bridge.dll exit /b 2
if not exist analysis\build\input-bridge-repro mkdir analysis\build\input-bridge-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_input_bridge.c /Foanalysis\build\input-bridge-repro\ /Feanalysis\build\input-bridge-repro\td2ega_input_bridge.dll /link /EXPORT:td2ega_input_bridge /IMPLIB:analysis\build\input-bridge-repro\td2ega_input_bridge.lib
