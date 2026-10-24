@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\runtime-report-bus-repro\td2ega_runtime_report_bus.dll exit /b 2
if not exist analysis\build\runtime-report-bus-repro mkdir analysis\build\runtime-report-bus-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_runtime_report_bus.c src\recovered\td2ega_video_reset.c src\recovered\td2ega_plane_fill.c src\recovered\td2ega_timer_control_bus.c src\recovered\td2ega_runtime_dispatch_bus.c src\recovered\td2ega_runtime_exit.c src\recovered\td2ega_finalizer_list.c src\recovered\td2ega_runtime_diagnostic.c src\recovered\td2ega_runtime_message.c src\recovered\td2ega_runtime_vectors.c /Foanalysis\build\runtime-report-bus-repro\ /Feanalysis\build\runtime-report-bus-repro\td2ega_runtime_report_bus.dll /link /EXPORT:td2ega_runtime_report_bus /IMPLIB:analysis\build\runtime-report-bus-repro\td2ega_runtime_report_bus.lib
