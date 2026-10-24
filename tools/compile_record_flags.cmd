@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\record-flags-repro\td2ega_record_flags.dll exit /b 2
if not exist analysis\build\record-flags-repro mkdir analysis\build\record-flags-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_record_flags.c src\recovered\td2ega_record_math.c /Foanalysis\build\record-flags-repro\ /Feanalysis\build\record-flags-repro\td2ega_record_flags.dll /link /EXPORT:td2ega_record_flags /IMPLIB:analysis\build\record-flags-repro\td2ega_record_flags.lib
