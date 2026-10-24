@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\gameport-repro\td2ega_gameport.dll exit /b 2
if not exist analysis\build\gameport-repro mkdir analysis\build\gameport-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_gameport.c /Foanalysis\build\gameport-repro\ /Feanalysis\build\gameport-repro\td2ega_gameport.dll /link /EXPORT:td2ega_gameport_sample /EXPORT:td2ega_gameport_initialize /EXPORT:td2ega_gameport_translate /IMPLIB:analysis\build\gameport-repro\td2ega_gameport.lib
