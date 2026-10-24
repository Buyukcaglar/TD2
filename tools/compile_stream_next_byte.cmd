@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\stream-next-byte-repro\td2ega_stream_next_byte.dll exit /b 2
if not exist analysis\build\stream-next-byte-repro mkdir analysis\build\stream-next-byte-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_stream_next_byte.c src\recovered\td2ega_stream_pull_byte.c src\recovered\td2ega_read_span.c src\recovered\td2ega_stream_buffer.c src\recovered\td2ega_heap_public.c src\recovered\td2ega_heap_walk.c src\recovered\td2ega_block_align.c src\recovered\td2ega_block_tail.c src\recovered\td2ega_block_wrapper.c src\recovered\td2ega_block_request.c src\recovered\td2ega_block_adjust.c /Foanalysis\build\stream-next-byte-repro\ /Feanalysis\build\stream-next-byte-repro\td2ega_stream_next_byte.dll /link /EXPORT:td2ega_stream_next_byte /IMPLIB:analysis\build\stream-next-byte-repro\td2ega_stream_next_byte.lib
