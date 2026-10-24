@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\prepare-records-repro\td2ega_prepare_records.dll exit /b 2
if not exist analysis\build\prepare-records-repro mkdir analysis\build\prepare-records-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_prepare_records.c src\recovered\td2ega_byte_ring.c /Foanalysis\build\prepare-records-repro\ /Feanalysis\build\prepare-records-repro\td2ega_prepare_records.dll /link /EXPORT:td2ega_prepare_records /IMPLIB:analysis\build\prepare-records-repro\td2ega_prepare_records.lib
