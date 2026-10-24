@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\config-fields-repro\td2ega_config_fields.dll exit /b 2
if not exist analysis\build\config-fields-repro mkdir analysis\build\config-fields-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_config_fields.c /Foanalysis\build\config-fields-repro\ /Feanalysis\build\config-fields-repro\td2ega_config_fields.dll /link /EXPORT:td2ega_config_fields /IMPLIB:analysis\build\config-fields-repro\td2ega_config_fields.lib
