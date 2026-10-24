@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\plane-byte-copy-repro\td2ega_plane_byte_copy.dll exit /b 2
if not exist analysis\build\plane-byte-copy-repro mkdir analysis\build\plane-byte-copy-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_plane_byte_copy.c /Foanalysis\build\plane-byte-copy-repro\ /Feanalysis\build\plane-byte-copy-repro\td2ega_plane_byte_copy.dll /link /EXPORT:td2ega_plane_byte_copy /IMPLIB:analysis\build\plane-byte-copy-repro\td2ega_plane_byte_copy.lib
