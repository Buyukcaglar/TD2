@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\far-member-repro\td2ega_far_member.dll exit /b 2
if not exist analysis\build\far-member-repro mkdir analysis\build\far-member-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_far_member.c /Foanalysis\build\far-member-repro\ /Feanalysis\build\far-member-repro\td2ega_far_member.dll /link /EXPORT:td2ega_far_member /IMPLIB:analysis\build\far-member-repro\td2ega_far_member.lib
