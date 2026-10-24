@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\key-actions-repro\td2ega_key_actions.dll exit /b 2
if not exist analysis\build\key-actions-repro mkdir analysis\build\key-actions-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_key_actions.c /Foanalysis\build\key-actions-repro\ /Feanalysis\build\key-actions-repro\td2ega_key_actions.dll /link /EXPORT:td2ega_key_action_apply /IMPLIB:analysis\build\key-actions-repro\td2ega_key_actions.lib
