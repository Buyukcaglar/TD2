@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\named-raw-repro\td2ega_named_raw.dll exit /b 2
if not exist analysis\build\named-raw-repro mkdir analysis\build\named-raw-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_named_raw.c src\recovered\td2ega_cache_acquire.c src\recovered\td2ega_cache_allocate.c src\recovered\td2ega_cache_compact.c src\recovered\td2ega_filename.c src\recovered\td2ega_paragraph_copy.c src\recovered\td2ega_file_paragraphs.c src\recovered\td2ega_raw_load.c /Foanalysis\build\named-raw-repro\ /Feanalysis\build\named-raw-repro\td2ega_named_raw.dll /link /EXPORT:td2ega_named_raw_load /IMPLIB:analysis\build\named-raw-repro\td2ega_named_raw.lib
