@echo off
rem Raw recovered stage; validation uses synthetic ordinary byte pools only.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\run-stage-repro\td2ega_run_stage.dll exit /b 2
if not exist analysis\build\run-stage-repro mkdir analysis\build\run-stage-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_paragraph_copy.c src\recovered\td2ega_run_stage.c /Foanalysis\build\run-stage-repro\ /Feanalysis\build\run-stage-repro\td2ega_run_stage.dll /link /EXPORT:td2ega_run_stage /IMPLIB:analysis\build\run-stage-repro\td2ega_run_stage.lib
