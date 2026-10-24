@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\heap-public-repro\td2ega_heap_public.dll exit /b 2
if not exist analysis\build\heap-public-repro mkdir analysis\build\heap-public-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_heap_public.c src\recovered\td2ega_heap_walk.c src\recovered\td2ega_block_align.c src\recovered\td2ega_block_tail.c src\recovered\td2ega_block_wrapper.c src\recovered\td2ega_block_request.c src\recovered\td2ega_block_adjust.c /Foanalysis\build\heap-public-repro\ /Feanalysis\build\heap-public-repro\td2ega_heap_public.dll /link /EXPORT:td2ega_heap_public /IMPLIB:analysis\build\heap-public-repro\td2ega_heap_public.lib
