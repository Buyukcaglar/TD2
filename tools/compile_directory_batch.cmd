@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\directory-batch-repro\td2ega_directory_batch.dll exit /b 2
if not exist analysis\build\directory-batch-repro mkdir analysis\build\directory-batch-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_directory_batch.c src\recovered\td2ega_directory.c /Foanalysis\build\directory-batch-repro\ /Feanalysis\build\directory-batch-repro\td2ega_directory_batch.dll /link /EXPORT:td2ega_directory_batch /IMPLIB:analysis\build\directory-batch-repro\td2ega_directory_batch.lib
