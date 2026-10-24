@echo off
rem Raw recovered stage; validation uses synthetic bytes only.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\prefix-stage-repro\td2ega_prefix_stage.dll exit /b 2
if not exist analysis\build\prefix-stage-repro mkdir analysis\build\prefix-stage-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_prefix_stage.c /Foanalysis\build\prefix-stage-repro\ /Feanalysis\build\prefix-stage-repro\td2ega_prefix_stage.dll /link /EXPORT:td2ega_prefix_stage /IMPLIB:analysis\build\prefix-stage-repro\td2ega_prefix_stage.lib
