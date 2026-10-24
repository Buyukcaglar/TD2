@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\record-name-select-repro\td2ega_record_name_select.dll exit /b 2
if not exist analysis\build\record-name-select-repro mkdir analysis\build\record-name-select-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_record_name_select.c src\recovered\td2ega_string_memory.c /Foanalysis\build\record-name-select-repro\ /Feanalysis\build\record-name-select-repro\td2ega_record_name_select.dll /link /EXPORT:td2ega_record_name_select /IMPLIB:analysis\build\record-name-select-repro\td2ega_record_name_select.lib
