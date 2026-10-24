@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\indexed-sample-repro\td2ega_indexed_sample.dll exit /b 2
if not exist analysis\build\indexed-sample-repro mkdir analysis\build\indexed-sample-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_indexed_sample.c src\recovered\td2ega_sample_adjust.c src\recovered\td2ega_control_bus.c src\recovered\td2ega_byte_ring.c src\recovered\td2ega_sim_primitives.c /Foanalysis\build\indexed-sample-repro\ /Feanalysis\build\indexed-sample-repro\td2ega_indexed_sample.dll /link /EXPORT:td2ega_indexed_sample /IMPLIB:analysis\build\indexed-sample-repro\td2ega_indexed_sample.lib
