@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\record-controller-repro\td2ega_record_controller.dll exit /b 2
if not exist analysis\build\record-controller-repro mkdir analysis\build\record-controller-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_record_controller.c src\recovered\td2ega_record_flags.c src\recovered\td2ega_record_math.c /Foanalysis\build\record-controller-repro\ /Feanalysis\build\record-controller-repro\td2ega_record_controller.dll /link /EXPORT:td2ega_record_controller /IMPLIB:analysis\build\record-controller-repro\td2ega_record_controller.lib
