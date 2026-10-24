@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\runtime-exit-repro\td2ega_runtime_exit.dll exit /b 2
if not exist analysis\build\runtime-exit-repro mkdir analysis\build\runtime-exit-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_runtime_exit.c src\recovered\td2ega_finalizer_list.c src\recovered\td2ega_runtime_diagnostic.c src\recovered\td2ega_runtime_message.c src\recovered\td2ega_runtime_vectors.c /Foanalysis\build\runtime-exit-repro\ /Feanalysis\build\runtime-exit-repro\td2ega_runtime_exit.dll /link /EXPORT:td2ega_runtime_exit /IMPLIB:analysis\build\runtime-exit-repro\td2ega_runtime_exit.lib
