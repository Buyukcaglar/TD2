@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\packed-load-repro\td2ega_packed_load.dll exit /b 2
if not exist analysis\build\packed-load-repro mkdir analysis\build\packed-load-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_packed_load.c src\recovered\td2ega_cache_acquire.c src\recovered\td2ega_cache_allocate.c src\recovered\td2ega_cache_compact.c src\recovered\td2ega_filename.c src\recovered\td2ega_paragraph_copy.c src\recovered\td2ega_file_paragraphs.c src\recovered\td2ega_raw_load.c src\recovered\td2ega_run_stage.c src\recovered\td2ega_prefix_stage.c /Foanalysis\build\packed-load-repro\ /Feanalysis\build\packed-load-repro\td2ega_packed_load.dll /link /EXPORT:td2ega_packed_load /IMPLIB:analysis\build\packed-load-repro\td2ega_packed_load.lib
