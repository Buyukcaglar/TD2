@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\file-paragraphs-repro\td2ega_file_paragraphs.dll exit /b 2
if not exist analysis\build\file-paragraphs-repro mkdir analysis\build\file-paragraphs-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_file_paragraphs.c /Foanalysis\build\file-paragraphs-repro\ /Feanalysis\build\file-paragraphs-repro\td2ega_file_paragraphs.dll /link /EXPORT:td2ega_file_paragraphs /EXPORT:td2ega_header_paragraphs /IMPLIB:analysis\build\file-paragraphs-repro\td2ega_file_paragraphs.lib
