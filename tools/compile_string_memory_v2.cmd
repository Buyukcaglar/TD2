@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\string-memory-repro-v2\td2ega_string_memory.dll exit /b 2
if not exist analysis\build\string-memory-repro-v2 mkdir analysis\build\string-memory-repro-v2
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_string_memory.c /Foanalysis\build\string-memory-repro-v2\ /Feanalysis\build\string-memory-repro-v2\td2ega_string_memory.dll /link /EXPORT:td2ega_string_memory /IMPLIB:analysis\build\string-memory-repro-v2\td2ega_string_memory.lib
