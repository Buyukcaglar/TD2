@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\block-request-repro\td2ega_block_request.dll exit /b 2
if not exist analysis\build\block-request-repro mkdir analysis\build\block-request-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_block_request.c src\recovered\td2ega_block_adjust.c /Foanalysis\build\block-request-repro\ /Feanalysis\build\block-request-repro\td2ega_block_request.dll /link /EXPORT:td2ega_block_request /IMPLIB:analysis\build\block-request-repro\td2ega_block_request.lib
