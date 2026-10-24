@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\input-poll-repro-v2\td2ega_input_poll.dll exit /b 2
if not exist analysis\build\input-poll-repro-v2 mkdir analysis\build\input-poll-repro-v2
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_input_poll.c src\recovered\td2ega_key_dispatch.c src\recovered\td2ega_gameport.c /Foanalysis\build\input-poll-repro-v2\ /Feanalysis\build\input-poll-repro-v2\td2ega_input_poll.dll /link /EXPORT:td2ega_input_poll /EXPORT:td2ega_input_consume_if_stack_group /EXPORT:td2ega_input_direction_bits /IMPLIB:analysis\build\input-poll-repro-v2\td2ega_input_poll.lib
