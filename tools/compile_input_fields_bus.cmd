@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\input-fields-bus-repro\td2ega_input_fields_bus.dll exit /b 2
if not exist analysis\build\input-fields-bus-repro mkdir analysis\build\input-fields-bus-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_input_fields_bus.c src\recovered\td2ega_control_bus.c /Foanalysis\build\input-fields-bus-repro\ /Feanalysis\build\input-fields-bus-repro\td2ega_input_fields_bus.dll /link /EXPORT:td2ega_input_fields_bus /IMPLIB:analysis\build\input-fields-bus-repro\td2ega_input_fields_bus.lib
