@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\stream-records-repro\td2ega_stream_records.dll exit /b 2
if not exist analysis\build\stream-records-repro mkdir analysis\build\stream-records-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_stream_records.c /Foanalysis\build\stream-records-repro\ /Feanalysis\build\stream-records-repro\td2ega_stream_records.dll /link /EXPORT:td2ega_stream_records /IMPLIB:analysis\build\stream-records-repro\td2ega_stream_records.lib
