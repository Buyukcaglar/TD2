@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\line-step-repro\td2ega_line_step.dll exit /b 2
if not exist analysis\build\line-step-repro mkdir analysis\build\line-step-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_line_step.c /Foanalysis\build\line-step-repro\ /Feanalysis\build\line-step-repro\td2ega_line_step.dll /link /EXPORT:td2ega_line_step /IMPLIB:analysis\build\line-step-repro\td2ega_line_step.lib
