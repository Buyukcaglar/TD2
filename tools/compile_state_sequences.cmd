@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\state-sequences-repro\td2ega_state_sequences.dll exit /b 2
if not exist analysis\build\state-sequences-repro mkdir analysis\build\state-sequences-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_state_sequences.c src\recovered\td2ega_state_messages.c /Foanalysis\build\state-sequences-repro\ /Feanalysis\build\state-sequences-repro\td2ega_state_sequences.dll /link /EXPORT:td2ega_state_sequence /IMPLIB:analysis\build\state-sequences-repro\td2ega_state_sequences.lib
