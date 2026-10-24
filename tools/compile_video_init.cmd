@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\video-init-repro\td2ega_video_init.dll exit /b 2
if not exist analysis\build\video-init-repro mkdir analysis\build\video-init-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_video_init.c src\recovered\td2ega_plane_fill.c /Foanalysis\build\video-init-repro\ /Feanalysis\build\video-init-repro\td2ega_video_init.dll /link /EXPORT:td2ega_video_init /IMPLIB:analysis\build\video-init-repro\td2ega_video_init.lib
