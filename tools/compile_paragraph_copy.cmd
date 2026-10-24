@echo off
rem Synthetic external byte storage only; no original resources.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\paragraph-copy-repro-v2\td2ega_paragraph_copy.dll exit /b 2
if not exist analysis\build\paragraph-copy-repro-v2 mkdir analysis\build\paragraph-copy-repro-v2
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_paragraph_copy.c /Foanalysis\build\paragraph-copy-repro-v2\ /Feanalysis\build\paragraph-copy-repro-v2\td2ega_paragraph_copy.dll /link /EXPORT:td2ega_paragraph_copy_forward /EXPORT:td2ega_paragraph_copy_backward /IMPLIB:analysis\build\paragraph-copy-repro-v2\td2ega_paragraph_copy.lib
