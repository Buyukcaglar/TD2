@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\view-limits-repro-v2\td2ega_view_limits.dll exit /b 2
if not exist analysis\build\view-limits-repro-v2 mkdir analysis\build\view-limits-repro-v2
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_view_limits.c /Foanalysis\build\view-limits-repro-v2\ /Feanalysis\build\view-limits-repro-v2\td2ega_view_limits.dll /link /EXPORT:td2ega_finish_limits /EXPORT:td2ega_limit_value /IMPLIB:analysis\build\view-limits-repro-v2\td2ega_view_limits.lib
