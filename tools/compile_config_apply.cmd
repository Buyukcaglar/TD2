@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\config-apply-repro\td2ega_config_apply.dll exit /b 2
if not exist analysis\build\config-apply-repro mkdir analysis\build\config-apply-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_config_apply.c src\recovered\td2ega_copy_config.c /Foanalysis\build\config-apply-repro\ /Feanalysis\build\config-apply-repro\td2ega_config_apply.dll /link /EXPORT:td2ega_config_apply /IMPLIB:analysis\build\config-apply-repro\td2ega_config_apply.lib
