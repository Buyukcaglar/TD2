@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\field-controller-repro\td2ega_field_controller.dll exit /b 2
if not exist analysis\build\field-controller-repro mkdir analysis\build\field-controller-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_field_controller.c src\recovered\td2ega_record_math.c src\recovered\td2ega_small_arithmetic.c src\recovered\td2ega_small_algorithms.c src\recovered\td2ega_table_scalar.c /Foanalysis\build\field-controller-repro\ /Feanalysis\build\field-controller-repro\td2ega_field_controller.dll /link /EXPORT:td2ega_field_controller /IMPLIB:analysis\build\field-controller-repro\td2ega_field_controller.lib
