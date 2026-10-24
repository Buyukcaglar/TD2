@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\field-text-repro\td2ega_field_text.dll exit /b 2
if not exist analysis\build\field-text-repro mkdir analysis\build\field-text-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_field_text.c src\recovered\td2ega_string_memory.c /Foanalysis\build\field-text-repro\ /Feanalysis\build\field-text-repro\td2ega_field_text.dll /link /EXPORT:td2ega_field_text /IMPLIB:analysis\build\field-text-repro\td2ega_field_text.lib
