@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\pool-setup-repro\td2ega_pool_setup.dll exit /b 2
if not exist analysis\build\pool-setup-repro mkdir analysis\build\pool-setup-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_pool_setup.c /Foanalysis\build\pool-setup-repro\ /Feanalysis\build\pool-setup-repro\td2ega_pool_setup.dll /link /EXPORT:td2ega_pool_setup /EXPORT:td2ega_pool_setup_fixed /EXPORT:td2ega_pool_remaining /IMPLIB:analysis\build\pool-setup-repro\td2ega_pool_setup.lib
