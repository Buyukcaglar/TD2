@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\key-bindings-repro\td2ega_key_bindings.dll exit /b 2
if not exist analysis\build\key-bindings-repro mkdir analysis\build\key-bindings-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_key_bindings.c /Foanalysis\build\key-bindings-repro\ /Feanalysis\build\key-bindings-repro\td2ega_key_bindings.dll /link /EXPORT:td2ega_key_binding /EXPORT:td2ega_key_install /IMPLIB:analysis\build\key-bindings-repro\td2ega_key_bindings.lib
