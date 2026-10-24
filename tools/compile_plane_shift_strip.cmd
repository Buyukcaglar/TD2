@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\plane-shift-strip-repro\td2ega_plane_shift_strip.dll exit /b 2
if not exist analysis\build\plane-shift-strip-repro mkdir analysis\build\plane-shift-strip-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_plane_shift_strip.c /Foanalysis\build\plane-shift-strip-repro\ /Feanalysis\build\plane-shift-strip-repro\td2ega_plane_shift_strip.dll /link /EXPORT:td2ega_plane_shift_strip /IMPLIB:analysis\build\plane-shift-strip-repro\td2ega_plane_shift_strip.lib
