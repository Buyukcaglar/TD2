@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
if exist analysis\build\music-tick-repro\td2ega_music_tick.dll exit /b 2
if not exist analysis\build\music-tick-repro mkdir analysis\build\music-tick-repro
cl.exe /nologo /TC /std:c17 /W4 /WX /O2 /LD src\recovered\td2ega_music_tick.c /Foanalysis\build\music-tick-repro\ /Feanalysis\build\music-tick-repro\td2ega_music_tick.dll /link /EXPORT:td2ega_music_tick /IMPLIB:analysis\build\music-tick-repro\td2ega_music_tick.lib
