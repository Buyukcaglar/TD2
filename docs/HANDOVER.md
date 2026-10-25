# Project handover and salvage report (24 October 2026)

This file replaces `docs/planning/continuation.md` as the place to start. That file, `backlog.json`, `progress.json` and the P-gate structure are kept for history but no longer drive the work.

## 0. Current state (session 3, 24 October 2026)

M0 "Adopt" is done except the user's play test. M1 "Verify EGA" is done apart from that play test: the planned fixes are in, each with a regression test, and the harness checks whole sim ticks. M2 "Backend split" is done: graphics and audio each sit behind a backend interface, and the EGA frames and the speaker output are unchanged. M3 "CGA" is built: `.\run.ps1 --cga` plays the game with TD2CGA's graphics. The attract loop, the menus, car and scenery select, and player-driven races render in cyan, red and white; TD2CGA's graphics library and the scene renderer's own pixel writers are matched routine by routine in the harness, and a CGA snapshot baseline guards it. Nobody has played CGA yet ([cga.md](cga.md)). The "all DOS resources" phase is Hercules only, by the user's decision: `.\run.ps1 --hercules` runs TD2CGA's Hercules mode, as the original launcher's option 4 does.

- **Code.** The Kylofon port is vendored in `port/td2/` (provenance and local changes in `port/td2/PROVENANCE.md`). Local fixes: 20-bit address wrap, the `INT32_MIN / -1` division guard, EXEPACK bounds checks, and `--user-dir` so scores and `SELECT.DAT` never go to the game folder.
- **Build.** `.\build.ps1` (add `-Clean` for a fresh build) builds `build\td2port.exe` and `build\td2diff.dll` with MSVC 14.44, the VS-bundled CMake and Ninja, and SDL3 3.4.18 built from its source in `analysis/external/sdl3-3.4.18/source`. It builds with no warnings at `/W3`. The exe is a single portable windowed app of about 3 MB: SDL3 and the C runtime are linked statically, and it needs only Windows system DLLs ([native-windows.md](native-windows.md), section 4).
- **Run.** `.\run.ps1` copies `reference\dos` to `runs\game` on first use and plays with `--user-dir runs\profile`. `.\run.ps1 --check` prints `TD2EGA.EXE ok (EGA): image 130240 bytes at 1000:0000, DGROUP 278F`.
- **Snapshot check.** `python tools/snapshots.py` makes three headless runs on a virtual clock and compares their frames and speaker output with the SHA-256 hashes in `tests/ega_snapshots.txt`. The runs are the attract loop, a scripted menu run, and the attract loop with three live graphics switches during its race, which must come back to the attract run's frames. `--cga` and `--hercules` do the same against their own baselines, and `--update` rewrites a baseline.
- **Live graphics switch.** Ctrl+Shift+G cycles EGA → CGA → Hercules ([native-windows.md](native-windows.md), section 1).
  - During a race the race goes on unchanged.
  - On the main menu, car select, scenery select and the difficulty screen, the screen draws itself again in the new mode.
  - On other screens the switch waits for the next of these screens or race frames.
  - The text colours are translated between the adapters' colour numbers.
- **Game data.** `src/app/app_data.c` finds the profile folder and the game folders, unpacks game archives (zip, 7z, rar, lha) into `Profile\Archives`, checks for the base game, and merges the folders' catalogues ([native-windows.md](native-windows.md), section 3). The profile folder holds `settings.ini`: `Profile` next to the exe, `--user-dir`, or `%APPDATA%\TestDrive2`.
- **App menu.** A right click or Ctrl+Shift+M opens the app's context menu (`src/app/`). It holds the graphics mode, the Hercules monitor colour, the window size, full screen, Game files…, About and quit. The menu follows the system's dark or light theme, and the game pauses while it is open.
- **Question windows.** `app_ui_question` is the app's own small themed window for errors at start, the first-start setup, Game files… and About. Without a game folder, the first start asks for the base game's folder or archive and saves it. Game files… lists what is installed and adds an expansion folder or archive, then offers a restart. Only dark mode has been seen; the machine here is set to dark.
  - The attract run is 120 s with a frame every 2 s: the Accolade and DSI logos, credits, the high-score table, the race-against and select menus, skill level and the attract-mode drive with cockpit, traffic, scenery and a crash.
  - The menu run (`menus/` in the baseline) presses keys with `TD2_KEYS`: it opens car select (up, down, down, escape) and scenery select, with a frame every 0.5 s.
  - The images and `audio.wav` go to `runs\snapshots\<adapter>` and are never committed. `tests/test_snapshots.py` checks both adapters (about a minute).
- **Scripted headless runs.** `TD2_KEYS` presses keys at given game times, for example `30:Return,41:Down,56:Up/240` (an SDL scancode name, and optionally how long to hold it). With a script the host logs each press and each saved snapshot with its game time, so a script can be lined up with the screens. `TD2_SNAPSHOT_MS` sets the snapshot interval. Two things to know when writing one: snapshots are only taken of presented frames, so a static screen gives none, and until the first real key the attract demo moves the menu selection at random. Up, Right, Down, Right, Up brings any selection to CLOCK.
- **Not yet done.** Nobody has played a race. The user has been asked to play one race on each scenery (CCC, ec_, TDS2) and report problems. Without `--user-dir` the game creates `%APPDATA%\TestDrive2` as its profile folder. No run has saved a score or `SELECT.DAT` yet, so the write path is untested.
- **Differential harness.** `tools/diffharness/` runs an original function under Unicorn and the port's C function from `build\td2diff.dll` on the same memory snapshot. It compares the returned registers and every changed memory byte, excluding the original's own stack frame. Run it with:

  ```
  $env:PYTHONPATH = "analysis/tools/python;tools"; python -m diffharness
  ```

  It rewrites `docs/verification.md`. Its own tests are in `tests/test_diffharness.py`; they check that it catches deliberate register and memory mismatches. Results: 59 functions match, 40 of them TD2CGA graphics and scene routines (below). The 18 EGA-image functions match on 200 randomised cases each: rand8, curve_sum, free_rev, drag_apply, brake, update_rpm, overrev_check, roadside_hit, obj_place_roadside, road_edges, decode_controls, sound_tick, traffic, pass_collisions, traffic_resync, nearest_ahead, rle_decode and huff_decode. The traffic cases use real stage data: each stage `.DAT` is decoded by the original's own unpackers and its traffic lists are set up as at the start of a stage. The unpacker cases cover every packed PES, PCS and DAT file.
- **PC speaker sound (session 3).** Synthesis moved from `host.c` to `speaker.c`, which has no SDL dependency. It models PIT channel 2 in mode 3: the speaker follows port 61h bit 1 AND the PIT output, a low gate holds the output high, and raising the gate restarts the wave. The square wave is averaged exactly over each sample on a 4× grid, then passes a 9 kHz two-pole low-pass (the cone) and a 10 Hz DC blocker. Aliasing is 20 to 35 dB lower than before, ultrasonic divisors no longer fold into audible whines, and a stopped note settles to silence. Tests are in `tests/test_speaker.py`. Set `TD2_AUDIO_DUMP=<file>.wav` to record what the speaker plays. The user listened and approved it. The cut-offs are in `speaker.h`.
- **Billboard collision (session 3).** For a billboard (type ≥ 50h) the original's crash test reads a stale BP (`cmp bp,14h` at 06c9:4d18). Below 14h the car only bumps instead of crashing. Tracing BP through the sim tick showed exactly where it is set. `decode_controls` (06c9:4281) loads the rpm, which is never below 800. The motion loop loads the road pointer (≥ 3B33h). `obj_place_roadside` (06c9:499a) loads the ring slot it filled (0–7Fh), and `road_edges` loads each right-side zone's end and then the zone length. So a billboard right after a placed object in the same sim step, or inside a short right-side zone, can bump instead of crash. The port now carries this value as `sim_stale_bp` and uses it for the test. Harness cases for all four routines compare BP as an output. `test_billboard_crash_depends_on_stale_bp` pins the rule down, and restoring the old "always crash" rule makes 10 of 200 random cases differ.
- **Neutral clutch grind (session 3).** When fire is released in neutral without a completed shift (fire alone, or a shift that is not possible), the original calls `update_rpm`, which does nothing in neutral, and then `clutch_check` on leftover registers. CX is the rpm that `sound_tick` loaded (06c9:4146), with CL replaced by the throttle-direction byte. When the full joystick read ran, CX is the gameport loop count instead. DX is `fire_held << 8`, usually 0100h. Above about 3,300 rpm, and if engine strength times the still-selected gear ratio passes the power check, this starts the grind tone. The port now carries CX as `sim_stale_cx`, set by `sound_tick` and by `joy_read`. The joystick case uses the port's synthetic stick counts, or 0FA0h, the original's timeout, when no gamepad answers. That keeps gamepad play grind-free, as a centred real stick would be. `test_neutral_fire_tap_grinds_at_high_rpm` pins the rule down, the `decode_controls` cases include fire taps in neutral, and a new `sound_tick` case checks the CX it leaves. Restoring the old skip makes 21 of 300 random cases differ.
- **Traffic seeding (session 3): no behaviour change needed.** Both leftovers were traced. `pass_collisions` takes CX from `traffic()`, which runs just before it. On every exit path `traffic`'s last CX write is `mov cx,[5356]` before a `meet_check`, which never writes CX, so CX is always `same_count8`, as the port assumed. It matters because `pass_check` stores it into a relation when a driver's position is 0, as it is while the police are off the road. `nearest_ahead` keeps the caller's DI only if no entry is picked. Any car inside the stage is always picked, and all 19 stages have at least 6 cars per list with raw positions below 1000, so DI is never used. The `traffic` case (which reaches crashes, opponent crashes and police starts) checks the CX it leaves, and the `nearest_ahead` case runs with a random DI. Both match. An empty list (count 0) makes the original's loops run through 64K of memory; that crashed Unicorn while the cases were being written. The harness now reports such a crash as an error and starts a fresh emulator.
- **Cockpit steering marker (session 3): no behaviour change needed.** `draw_steering` (06c9:3c3a) loads only CL with the marker's y before it saves the background and draws the dot, so CH is left over. It is always 0. Every route to 3ca2 ends in one of three blit routines: the marker restore (9c90) when a marker was saved, the wheel XOR blit (c172) when the wheel pose changes, or, on the first frame after `cockpit_reset` sets `redraw_inst`, `draw_instruments`' last call (9cc2). Every exit of those routines ends with `loop` or `rep`, which leave CX = 0. The masked paths that could leave something else need mask planes, and the marker save sprite at DS:2F7C has planemap 01 02 04 08 (no masks). The port's comment now records this.
- **Whole-tick tests (session 3).** The `sim_tick` harness spec runs the original sim timer routine (06c9:403b) and the port's `sim_timer_routine` for 1,000 calls in a row (100 sim steps, 10 s of game time) from a recorded race state. Each side carries on from its own memory, the two are compared after every call, and the first call that differs is reported. Half the cases take the car out of demo mode and press keys at random, the same on both sides; they reach gear shifts, police chases, crashes and skids. The original gets random registers on every call, as whatever code the timer interrupted would leave, while the port carries its own leftover BP and CX. All 60 cases match. So the results do not depend on the registers at entry, and the leftover BP and CX modelled per routine also agree across whole ticks. Joystick input is off in these cases because the port's gamepad mapping differs from a real stick by design.
  - **Recording states.** The port saves the sim timer routine's entry state (1 MiB of memory, then the leftover BP and CX) when `TD2_STATE_DIR` is set (`host_sim_state` in `host.c`; `TD2_STATE_EVERY` and `TD2_STATE_MAX` set the interval and the count). `.\run.ps1 -RecordStates` plays and saves one state every 10 s to `runs\states`. The current 60 states come from 8 minutes of headless attract mode and cover stages 4 and 2 only. They hold original game data, so they stay in `runs\` and are never committed. Without recorded states the `sim_tick` spec has no cases and its tests are skipped.
  - **Harness changes.** A software interrupt whose vector points into the game's own code now runs that handler, as the CPU would. The drive tick reads keys through INT 16h, which the game points at its own handler (06c9:69b7). BIOS and DOS interrupts still stop the run as an error. Reading the port's memory back now uses `ctypes.string_at`, which made every case about 30 times faster on the port side. New tests: `test_game_interrupt_handler_runs`, `test_sequence_reports_the_first_call_that_differs` and `test_whole_sim_ticks_match`.
- **Repeatable runs (session 3).** With `TD2_VIRTUAL_CLOCK=1` the host's clock advances only while it would otherwise wait, so a headless run depends only on the game and runs about four times faster than real time. `TD2_RUN_SECONDS` ends the run after that much game time. Two runs give byte-identical frames and audio. The WAV dump (`TD2_AUDIO_DUMP`) now gets every sample, even when the audio device falls behind; before, it skipped those, which made dumps differ between runs.
- **Graphics backend (M2, session 3).** The graphics library is split in two.
  - `platform/gfx.c` keeps what TD2EGA and TD2CGA share: target descriptors, clipping, the text state, sprite positioning (hot / raw / own), centred text and outlines.
  - The pixel routines sit behind a `GfxBackend` table (`platform/gfx_backend.h`). The EGA backend is `gfx_ega.c` and `gfx_ega_blit.c`; its code is unchanged, only renamed to static `ega_*` functions.
  - The table holds exactly the routines that TD2CGA implements differently. This was found by aligning the two function indexes (`port/td2/port/td2ega_functions.csv`, `td2cga_functions.csv`) per segment on size, instruction count, call count and strings. Video memory access is confined to the backend: no game code touches the EGA model.
  - The same comparison gives the CGA work list. 119 EGA functions have no identical CGA twin: 61 in the platform library (all the graphics routines, plus `joy_read`, `music_tick`, `huff_decode`, `mem_release_cache` and a few more), 29 in the scene renderer (projection, sky, ground, objects, mirror, cockpit and instruments, `stage_load`), 15 in the simulation and 11 in the game flow screens. M3 has since explained the simulation and scene-renderer ones (next entry).
- **Audio backend (M2, session 3).** The game's sound code stays game logic: the effect and music stream players and the drive tones keep their state in DGROUP, and the game reads some of it back. An `AudioBackend` (`src/audio_backend.h`) only turns the output into samples. The PC speaker backend is in `speaker.c` and the host renders through the active one (`host_set_audio_backend`). A sample-based Amiga backend will also need to hear which effect or song started; those events should be added together with it.
- **CGA against EGA (M3, session 3).** Written up in [cga.md](cga.md); `python tools/cga_compare.py` reproduces it, and `python tools/cga_compare.py <EGA address>` prints one function's differences. `tools/exepack.py` gained `unpack()`, which unpacks TD2EGA, TD2CGA and TD2TDY without the old hash gate (TD2CGA has 11 bytes after its relocation table that are simply ignored).
  - **How it compares.** Disassemblies are compared after normalising the relink. A number that still differs passes only with evidence that it is the moved EGA address: the same bytes at both places, the uninitialised-data shift (CGA's initialised data is 160h shorter), the same offset inside a paired function, a jump table pointing to paired code, the graphics descriptor block, or the same shift shown by two variables in one area.
  - **Simulation.** All 15 simulation functions are the same program in CGA; the port's simulation code serves CGA unchanged.
  - **Scene renderer.** 12 of the 29 scene-renderer functions are identical; the other 17 differ only in drawing and colour values:
    - 2-bit pixels instead of four planes, and 4 pixels per byte instead of 8;
    - dither patterns instead of colour numbers;
    - the crash flash on port 3D9h instead of the palette;
    - a few coordinates forced odd, probably for the dither phase (unconfirmed).
  - **Colours.** The stage `.DAT` files and the sign records hold a CGA pattern next to every EGA colour, and each build reads its own words. `stage_load` therefore differs too. An earlier rule of the comparison had hidden this; it now defers to buffer base addresses the code loads. Code constants map per call site (colour 8 becomes 0 or 9966h), so there is no single colour-to-pattern table.
  - **Backend design.** Written up at the end of [cga.md](cga.md):
    - a CGA `GfxBackend` with colour parameters widened to 16 bits;
    - a `SceneRaster` hook table for the four scene routines that write pixels (span fill, scene `hline`, road marking pixel, crash flash) plus pixels per byte;
    - `COL(ega, cga)` at the colour constants;
    - one `gfx_is_cga()` test each for the forced coordinates and the dropped cliff masks.

    The mask tables are regular and computed, off-screen buffer rows are linear, only the screen is interleaved, and nothing has to be read from TD2CGA at run time. Three earlier claims were corrected:
    - `draw_instruments` changes the needle colour, not a plane mask;
    - the tunnel walls' 80-byte step is a linear row, not interleaving;
    - the ground constant 7 → 0 is the road turning black.
  - **Index mistakes found.** The Kylofon indexes cut some functions short or split them: EGA 06C9:1A37 is the tail of `draw_front_objects`, and 06C9:AF54 is the screen descriptor, not code. The tool corrects for this.
- **CGA backend (M3).** `--cga` (passed through by `run.ps1`) selects it before `gfx_init`; the port still runs on the TD2EGA image and its DGROUP, and loads TD2CGA's `.PCS`/`.CSH` sprite files.
  - **Library.** `gfx_cga.c` transcribes TD2CGA's routines: descriptors and row tables (the screen at B800h interleaved, buffers linear), fills, clear, plot, both lines, text, both dissolves, the grabs, the colour registers 3D8h/3D9h and the RGBI compose. `gfx_cga_blit.c` has the 24 blitters, sharing one body per operation. The PCS fix-up (storage modes 1–3) is `res_fix_pcs_archive` in `res.c`. CGA has no scroll routine; TD2CGA's `car_slide` stacks the old and new car pictures in a 320×176 buffer and copies an 88-row window, and its `car_select` passes the start and end rows the other way round. The port has both versions.
  - **Scene.** `gfx_cga_scene.c` is the CGA `SceneRaster`: span fill, scene `hline` (including its single-byte quirk), road marking pixels and the crash flash on 3D9h. The game code picks colours with `COL(ega, cga)` and byte columns with `XBYTES(n)`.
  - **Backend table.** `GfxBackend` also says which sprite files to load, which fix-up to run and with how much scratch, how unclipped own blits align x (CGA 0FFFCh) and where the cursor glyphs are (TD2CGA builds three small sprites; the port makes them at BC00h).
  - **Checks.** The harness runs TD2CGA's own library under Unicorn (`tools/diffharness/cga.py`): the two sides keep their state at different addresses, so each case writes the same buffer and sprite into both memories, each side's descriptor and row table in its own place, and compares only those bytes. All 24 blitters, the three grabs into sprites, `grab_screen`, `fill_rect`, `fill_rect_clip`, `clear_clip`, `clear_screen`, `plot`, both lines, `draw_text` (random fonts, blanks and line breaks), both dissolves, and the scene's span fill and `hline` match on 200 cases each. Text, span and screen cases also place their DGROUP state in each side's own layout: TD2CGA's text block is 160h lower and its span words 4 bytes lower, and the span state is compared across the two addresses. The original runs with SS = DS, as in the game, because the scene routines index their mask tables with BP. The OR line's cases leave out steep upward lines: TD2CGA takes their start x from a stale stack word, a path the game never draws. Headless runs with `TD2_KEYS` were checked by eye in both adapters: the attract loop, menus, car select with slides both ways, scenery select, the exit prompt, a player race with crashes and the lives message, and (400 s of attract mode) the demo's police stop with the speeding ticket. EGA and CGA reach the same game states at the same times, because they share the simulation and the virtual clock.
  - **Not checked against TD2CGA.** The road marking pixels (inline in `draw_front_objects`) and the crash flash (port 3D9h) are covered only by the snapshots. Stage results, high-score entry and the police ending were not reached in CGA.
- **Hercules mode (all DOS resources).** The original launcher `DUEL.EXE` runs `td2cga.exe herc` for its Hercules option, so Hercules is TD2CGA's game with `herc_init` in place of the CGA mode set and Hercules text mode restored at the end; nothing else in the game reads the Hercules flag. The card shows page 1 at B800h through a 6845 set for 640 × 300 one-bit pixels: each 2-bit pixel becomes two, and every third line comes from a bank that stays clear. `gfx_herc_backend` (`--hercules`) shares the CGA drawing and has its own reset, compose, mode set and shutdown ([cga.md](cga.md), "Hercules mode"). The CGA register writes, including the crash flash, have no effect, as on a real Hercules machine. The CGA cursor glyphs moved from BC00h to C000h, out of Hercules page 1. `python tools/snapshots.py --hercules` checks `tests/herc_snapshots.txt`. The window title now names the mode. Tandy 16-colour (TD2TDY) is out of scope by the user's decision. The unused compile-time CGA/Hercules variants in `build.h` are gone.
- **Amiga version (started).** [amiga.md](amiga.md) has the findings and the plan. `tools/amiga/` reads the Amiga files: load files (`hunk.py`, `disasm.py`), the Rpck packing (`rpck.py`, checked against the game's own unpacker under Unicorn on all 177 packed files in `tests/test_amiga_files.py`) and IFF pictures (`ilbm.py`). `tools/dos_unpack.py` unpacks DOS files in Python. The Amiga sprite archives use the DOS layout and names. Northern Germany (`scen3`), a 2012 fan scenery, is built entirely from copies of the other sets' roads and art, plus its own signs, title picture and high scores. The tools read `runs/amiga`, a copy of the unpacked archive.
- **Northern Germany in the game.** With the Amiga game set and the DOS California and European Challenges present, the app builds it as a DOS scenery in the profile folder's `Northern Germany` folder (`src/app/northern_germany.c`): each stage is the DOS twin of its road, drawn with the DOS archive of its Amiga sprite file, with its German signs converted. It plays in EGA, CGA and Hercules ([amiga.md](amiga.md), "Northern Germany in the port"). The road question is answered: duel reads its road bytes as DOS does, so the Amiga roads' differences are real data differences.
  - **Sprites** (`tools/amiga/shp.py`): 20-byte header and plane-after-plane bitmaps; byte +12 holds the planes a sprite clears and +13 those it sets; the dashboard gauges equal the dashboard picture pixel for pixel. The race screen switches to the dashboard picture's palette at line 116 (duel's own copper list); the palette above is probably `pics/testdrive.pal`. Open: the gear gate and the needle masks come out scrambled.
  - **Roads**: the road bytes index a record table in both versions; records 0–31 agree, the object records are numbered differently, and the side flag differs over long stretches. Open: how the Amiga reads its road bytes (timeboxed, written up in amiga.md).
  - **Music and effects**: `src/amiga/song.c` is the Amiga player translated to C. `tests/test_amiga_song.py` checks it against the original under Unicorn: every custom chip write matches over the whole title song and an effects script. `src/amiga/paula.c` plays it; `tools/amiga/play_song.py` renders a WAV. The user has been sent `runs/amiga-view/titlesong.wav` to listen to.
  - **Race sounds**: `src/amiga/race_sound.c` is the driver `duel` uses during a race (four channel records, plays, loops, period and volume ramps, a vertical blank server and the audio interrupt), and `src/amiga/race_logic.c` the logic that feeds it (the car's engine and turbo samples, the gear change and skid squeal, bump, radar, crash, and the siren's sweep with a Doppler shift). `tests/test_amiga_race_sound.py` and `tests/test_amiga_race_logic.py` check every custom chip write against `duel`'s own code under Unicorn.
  - **The Amiga sound in the game**: `src/amiga/audio_amiga.c` is the Amiga `AudioBackend`. The DOS game reports its songs, each life's start and end, bumps and crashes, and the car's state ten times a second (`audio_backend.h`, `host_sound_event`, `host_sound_drive`). Ctrl+Shift+S or the menu's Sound entry switches between it and the PC speaker at any time; the Amiga game's folder or archive is the `amiga` setting. The user has been sent `runs/amiga-view/attract-amiga.wav` (title song and the demo race) to listen to. The game over sound, the intro speech ("Accolade presents", then "The Duel" and "Test Drive II") and the showroom's starter play too. The output is stereo as Paula wires it (channels 0 and 3 left, 1 and 2 right), so the speech is on the right under music on both sides, as the user heard in the original. The WAV was recorded again in stereo. With the Amiga sound the intro runs at duel's pace (docs/amiga.md, "The intro's pace"), so the showroom's starter sounds while the car opens its window and drives off. The user's rule: the pace follows the sound, Amiga samples with Amiga timing, the PC speaker with DOS timing, whatever the graphics.
  - **Decompiling**: `tools/amiga/ghidra.ps1` writes all of `duel` to `runs/amiga-ghidra/duel.c` (A4 small data and the jump stubs set up).
- **Adding a function to the harness** takes three steps: add an adapter in `tools/diffharness/adapters.c`, add a `Spec` with an input generator in `tools/diffharness/cases.py`, and rebuild.

### Next steps (in order)

1. **Play test.** Ask the user for the results of one race on each scenery (CCC, ec_, TDS2), ideally recorded with `.\run.ps1 -RecordStates`. Their states would add player-driven races on every scenery to the `sim_tick` cases.
2. **CGA play test.** Ask the user to play one race in CGA (`.\run.ps1 --cga`) and compare it with their memory of the original, especially the palette and the dither.
3. **Finish M3's checks.** A scripted run to a stage end and the high-score entry, in both adapters, added to the snapshot runs. Holding Up alone leaves the road at the first sharp curve, so the script needs steering.
4. **Hercules play test.** Ask the user to look at `.\run.ps1 --hercules`. The monitor colour (white, green, amber) is now a choice in the app's context menu.
5. **Native Windows phase.** The user defined it on 24 October 2026, and [native-windows.md](native-windows.md) is the design and the order of work: single exe, the pending-switch mechanism with the race switch, screen redraw on switch, the app UI layer (context menu, dark mode, question windows), then the game data manager. The race graphics state a switch must rebuild is fully listed there (ten archives, thirteen handle tables, five buffers, the scenery colours). The user decided: Ctrl+Shift+G switches the graphics, Ctrl+Shift+M or a right click opens the menu, settings live next to the exe when writable. Steps 1 to 4 are done:
   - the single exe;
   - the race switch and the menu screens' switch;
   - the context menu (right click or Ctrl+Shift+M: graphics mode, Hercules monitor colour, window size, full screen, quit). It follows the system's dark or light theme and pauses the game while it is open.
   Step 5 is done:
   - `Profile\settings.ini` next to the exe, which saves the menu's choices;
   - game and expansion folders, with the base-game check;
   - catalogues merged from each folder's `CARS.DAT`/`SCENES.DAT`;
   - zip, 7z, rar and lha archives: libarchive is built static by `build.ps1`, with a one-line patch so Amiga LhA archives are recognised;
   - the themed question windows, the first-start setup, and the Game files… and About entries.
   The app icon is in. Still open in this phase: a look at the windows in the light theme, and macOS (step 6, later). The next phase is the Amiga recovery: its sound and music behind the same switch, and its sceneries, Northern Germany among them.
6. **Amiga phase** ([amiga.md](amiga.md), section 4). The Amiga audio is in (music, race sounds, live switch). Next: ask the user how the Amiga sound sounds (the two WAVs in `runs/amiga-view`, or `.\run.ps1` and Ctrl+Shift+S with the Amiga game's folder or archive), Done since: the road question, Northern Germany in the game, and its own title picture as its scenery icons. Next: the Amiga graphics backend; for Northern Germany, the Amiga traffic sprites (optional). The backend is started: the EGA model with a fifth plane (`--amiga-graphics`, [amiga.md](amiga.md), "The Amiga graphics backend"), which shows the EGA frames exactly without the Amiga files, and with them the option, difficulty and scenery choice screens in their Amiga form (each target has its palette, a picture may split it at a line, and the Amiga sprites are read from their archives; see the section). Fixed since: Ctrl+Shift+G now works in the intro and attract screens, a switch to the Amiga sound goes on with the song where the DOS song is, and the picture is fitted again after a resize or Alt+Enter while nothing is drawn. These screens change with duel's wipes (box, bars, circle, sweep, bands, checks; see "Screen changes"). Done since: "Accolade presents" (the bar that slides in and cuts its line through the letters) and the title ("The Duel", then 33 yellow lines that fly into "TEST DRIVE II", then the letters, and the top-to-bottom wipe out), with the title's colours and line table read from `duel` at run time (`amiga/hunk.c`). The Amiga sprite byte +12 turned out to be the planes a sprite clears, not sets. The intro's showroom now shows the player's chosen car, then the computer's, as duel's does, in every mode (the user asked; TD2 itself always shows cars 0 and 1). The snapshot runs pin their cars to the F40 and the 959 with a `select.dat` of their own, because the shipped `SELECT.DAT` picks the RUF; the baselines were rewritten for that. The intro's showroom is in its Amiga form too: the side views in an 84-line viewport that duel scrolls to drive the cars off, the window opening and the wheels turning. The car choice is in its Amiga form too: the car on the blue board over a high-resolution band with its data (the frame is 640 wide while it shows), duel's viewport slides between cars, and the player's car driving off. The high scores are in their Amiga form: the cars' logos, each in its own colours by a palette split of its own, and the scores in duel's places. The data disks' cars keep their colours in a bare `CMAP` chunk, which the readers now take (before, their showroom, car choice and logos kept the colours shown before them). Game over is too: the dripping red letters, then duel's fade, which also ends the high scores. The results pages are in duel's colours and boxes too, with TD2's figures and words. The gas station is in its Amiga form: the scenery's station with the section's sign, the car in its own colours below the picture's split, and duel's text scroller. The name entry shows the car's rear picture with duel's field. The game's end is duel's: the gas station again with the attendant and a police officer, and the jail message when the player outran the police. The race now has duel's cockpit over TD2's road: the dashboard picture in its own colours from line 116 and the section's road colours above, the roof with its digits, radar lights and progress dots, the pillar, the mirror frame round TD2's mirror picture, the hood (crumpled after a crash), the turning wheel with its marker, the two needles, and the gear gate with its knob. The road is in duel's colours (sand, the dark road, the sky from the road data's pens) with duel's sprites in place of TD2's: the scenery, the traffic, the police and the opponent, each DOS archive matched to the Amiga archive with most of its sprites by name and size; other DOS sprites on Amiga targets are drawn in the nearest colours. The race's messages are in duel's box with duel's words (lives left, out of gas, the blown engine). The small gauges (turbo, oil temperature, oil pressure, fuel) and duel's road bands are in too, and the California and European races were checked by eye. The Amiga form's intro goes from the title to the high scores, as duel's does (no DSI logo or credits), so `tests/test_amiga_graphics.py` presses its keys 7 s earlier. Next in it: the backend in the Ctrl+Shift+G cycle and the menu.
7. **Snapshot coverage.** Once the play test has recorded states, rendering a frame from a recorded race state would add player-driven scenes.

### Open questions

- Is the playable game correct over a full race? Waiting on the user's play test, in EGA and CGA.
- Which palette did real CGA cards, and EGA or VGA cards in CGA mode, show for mode control 0Eh? The port shows cyan, red and white, the documented behaviour on an RGB monitor.
- Harness speed: a single call is a few milliseconds; a 1,000-call `sim_tick` case takes about 5 s, so that spec is capped at 60 cases. Copying only changed pages would make longer sequences cheap.

## 1. TL;DR

- **Goal (unchanged).** A native Windows Test Drive II built on portable C. It reads the user's original DOS files and supports EGA, then CGA. Later it adds Amiga graphics, music and sound effects, plus the Amiga "Northern Germany Challenge" scenery, all switchable live during play.
- **What the previous agent did.** Eleven days (13–22 October), with one commit on 13 October. It produced:
  - 12.5k lines of x86-literal C leaf functions;
  - 1,293 JSON "receipts" taking 205 MB;
  - 178 copies of one map file and 175 of another;
  - a 203–461 engineer-day estimate.

  There is no playable result. The rest of this report calls that previous agent "the predecessor".
- **What already exists.** A third-party, MIT-licensed, playable C11/SDL3 reimplementation of TD2EGA (Kylofon, `reference/repos/kylofon-test-drive-2-sdl3`, commit `352b568`, v0.1.0, about 11.7k lines). The predecessor reviewed it, then admitted only 11 functions from it. All 11 were functions it had already recovered itself.
- **Verified in this session.** The existing MSVC build of a patched Kylofon copy loads our `TD2EGA.EXE`:

  ```
  analysis/candidates/kylofon-r03-v1/native-build-v1/candidate/td2r03_full.exe
  ```

  - `--check` printed `TD2EGA.EXE ok (EGA): image 130240 bytes at 1000:0000, DGROUP 278F`.
  - A normal launch opened the game and was still running when killed after 6 seconds.
  - Both runs used a scratch copy of `reference/dos`. The originals are unchanged.
  - Nobody has played it through yet.
- **Recommendation.** Make the Kylofon port this project's codebase. Verify it by playing and by bulk differential tests. Then add CGA as a second presentation backend, and do the Amiga work on top of a backend/provider split. Details are in section 7. The work prompt for the next session is in [NEXT-SESSION-PROMPT.md](NEXT-SESSION-PROMPT.md).

## 2. Requirements (from `docs/planning/roadmap.md`, still valid)

1. Recover portable C from `TD2EGA.EXE` (primary), then analyse `TD2CGA.EXE` graphics.
2. Decode every supplied DOS resource, including data embedded in the EXEs.
3. Native Windows game on that C core. It reads the user's files and ships no original media.
4. Analyse and decompile the supplied Amiga game (`reference/amiga/TestDrive2&DataDisks_v1.1_HD_JOTD.lha`, JOTD HD install v1.1, not WHDLoad). Distinguish its patches from original disk behaviour.
5. Amiga graphics, animation, music and SFX, selectable live alongside EGA, CGA and PC Speaker. Graphics, music and effects switch independently, with no simulation reset.
6. Northern Germany Challenge scenery (route and gameplay, not just media) when its files are supplied. The candidate is the Amiga tree `scen3`.

Hard rules that stay:

- `reference/` is read-only.
- No original media in the repo or in a distributable.
- Game runs use a writable copy of the data.
- DOS audio is PC Speaker only (no AdLib).
- Tandy is context only, not a deliverable.

## 3. Why the project stalled (do not repeat)

1. **Fidelity at the wrong level.** Every C function had to match the original under Unicorn on:
   - all 1 MiB of RAM, flags (including AF), stack aliasing and DS≠SS profiles;
   - two load segments.

   Functions already passed were then re-recovered as "bus" variants (`timer_handler`, `timer_handler_bus`, `timer_handler_bus_flags`). None of this composes into a game: every module takes the raw 1 MiB memory and private register structs.
2. **Write-once evidence bureaucracy.** Every step produced new versioned receipts that could not be overwritten, plus "consumed maker" scripts that must not be rerun. Whole-program maps were regenerated after each step: `td2ega-control-map-v1..v178.json` and `td2ega-resource-consumer-map-v1..v175.json`, about 650 KB each. In addition there were eight acceptance gates per function and custody audits re-hashing all 250 originals.
3. **Refusal to assign meaning.** It would not name the 100 Hz timer, the RNG, the race states or the copy protection. No game-level model ever formed, and every document ends with "gates remain open".
4. **Reuse treated as a compliance exercise.** It found a working port and spent the remaining days on admission and custody reviews.
5. **Unreadable handoffs.** `continuation.md` has words run together ("actualSSframe", "nativev1REGISTERED") and is 27 KB of status for a project with no executable output.

## 4. Salvage inventory

### Keep and use

| Asset | Path | Why |
|---|---|---|
| Kylofon port (read-only clone) | `reference/repos/kylofon-test-drive-2-sdl3` | Playable EGA game in C plus format docs, specs, symbol tables and EGA/CGA/TDY function indexes |
| Patched Kylofon copy and build | `analysis/candidates/kylofon-r03-v1/candidate/`, `candidate-fixes-v2.patch`, `native-build-v1/` | Proven MSVC build on this machine. The patch adds a 20-bit wrap, a division guard, a user-profile directory and a stricter EXE loader |
| Direct MSVC build script | `tools/build_kylofon_candidate_v1.py` | Working cl/link recipe (it refuses to reuse an existing output folder) |
| SDL3 3.4.18 VC SDK | `analysis/external/sdl3-3.4.18/sdk/SDL3-3.4.18` | Includes the `cmake/` config |
| EXEPACK unpacker and tests | `tools/exepack.py`, `tests/test_exepack.py` | Validated three ways. Use it for CGA and TDY too |
| Unpacked EGA image | `analysis/derived/td2ega-v1/` (`TD2EGA.image.bin`, `TD2EGA.unpacked.exe`, `relocations.json`) | Image SHA-256 `8db38a02…59c4`, 130,240 bytes, 1,652 relocations |
| Unpacker-stub check | `tools/validation/verify_exepack_loader.py` | Runs the original stub under Unicorn |
| Ghidra headless runner and scripts | `tools/run_ghidra.ps1`, `tools/ghidra/*.java` | Ghidra 12.1.3 and JDK 21 are borrowed from `C:\Projects\Civ1RE\tools\` |
| Ghidra projects and exports | `analysis/ghidra-projects/TD2EGA*.gpr`, `analysis/exports/td2ega-v1/` (363 decompiled functions) | Starting point for CGA and verification |
| Flow crawler | `tools/map_ega_flow.py`, output `analysis/flow/indirect-v8/` | Function and instruction map |
| Unicorn/Capstone install | `analysis/tools/python` (unicorn 2.1.4, capstone 5.0.9) | Use `PYTHONPATH=analysis/tools/python` |
| Harness template | `tools/validate_music_tick.py` or `tools/validate_bios_block.py`, plus `tools/validation/twenty_bit_bus.py` | Base for one generic differential harness |
| Registries | `docs/recovery/functions.json` (440 functions), `docs/recovery/resources.json` (305) | Address and range data. Ignore the gate fields |
| Fact documents | `docs/recovery/td2ega-{startup,startup-abi,main-state,state-and-consumers,resource-cache,mutable-platform,timer-control,timer-handler,music-tick,effect-tick,keyboard,key-bindings,key-actions,input-poll,gameport,prefix-stage,run-stage,state-loop,sim-controller,line-draw,sprite-draw,projection}.md` | Exact semantics, useful when verifying Kylofon code |
| Planning facts | `docs/planning/resources.md`, `dos-executables.md`, `amiga-evidence-and-plan.md`, `evidence/reference-manifest.json`, `evidence/resource-observations.json`, `evidence/amiga-member-inventory.json`, `evidence/whdload-source-examination.json` | File inventory, hashes and signatures |
| Working data copy | `analysis/inputs/dos/` (249 files, including TD2CGA, TD2TDY and DUEL) | Do not run games here either; copy it first |

### Reference only (do not extend)

- `src/recovered/*.c|h` (165 modules) and their `tools/compile_*.cmd` and `tools/validate_*.py`. These are exact behaviour notes for about 30 meaningful routines: byte ring, cache, both codec stages, music and effect ticks, keyboard, gameport, timer, line, rectangle and sprite drawing. They are not game code.
- `docs/planning/kylofon-*.md` and `docs/recovery/kylofon-*.md`. The useful content is summarised in section 6.

### Noise (safe to archive out of git later)

- `td2ega-control-map-v1..v177.json` and `td2ega-resource-consumer-map-v1..v174.json` (351 files, 173 MB). On 24 October 2026 they were moved out of git to `analysis/archive/recovery-evidence-maps/`; `analysis/` is gitignored. Only v178 and v175 remain in `docs/recovery/evidence/`. Links to those earlier versions in old documents are now broken; the files themselves are in the archive.
- Per-function `*-validation-vN.json`, `*-build-*.json`, `*-diagnostics-*.json`, the audits and `analysis/history/`.
- The roughly 300 `analysis/{prepare,refine,checkpoint,archive,inspect}_*_vN.py` scripts.
- `docs/planning/kylofon-effort-review.md` and the engineer-week estimates.

Nothing has been deleted. Apart from the map copies above, everything was committed as-is on 24 October 2026.

## 5. Technical fact digest

Addresses are load-relative `seg:off` in the unpacked EGA image. Items marked *[unverified]* are a reader's observation and have not been checked against code.

### Executables

| | TD2EGA | TD2CGA | TD2TDY |
|---|---|---|---|
| File size (bytes) | 114,421 | 104,160 | 103,905 |
| Unpacked image (bytes) | 130,240 | 119,872 | 119,744 |
| Packed entry (CS:IP) | 1AEC:0012 | 186A:0012 | 1858:0012 |
| Original entry | 13A8:03F8 | 1136:03F8 | 1104:03F6 |
| Relocations | 1,652 | 1,652 | 1,674 |
| DGROUP | 178F | 151D | 1505 |

- All three are EXEPACK-packed, with an identical 283-byte stub.
- **CGA has 11 unexplained bytes after its packed data:** `FF 40 00 FF FF 00 00 FF FF 00 00`.
- Built with Microsoft C 5.x in the medium memory model: 22 far code segments, DS = SS = DGROUP. The DSI assembly library from TD1 is linked in.
- **EGA segments:**
  - `0000`: main and DISKID check
  - `00c0`/`010c`: titles
  - `0143`/`019e`: selection and showroom
  - `0267`: gas station, results and filename builders
  - `0432`: CARS/SCENES/select
  - `0645`: high scores
  - `06c9`: driving game at 0000–5CFF, DSI library at 5D00–CD9F
  - `13a3`/`13a8`: C runtime and protection
  - `16a7`–`1769`: helpers, dialogs, UNFLIP
- `DUEL.EXE` menu choices: 1 → `td2cga.exe`, 2 → `td2tdy.exe`, 3 → `td2ega.exe`, 4 → `td2cga.exe herc`.

### Runtime model (EGA)

**Startup.** `13A8:03F8` is the CRT start. It far-calls `main` at `0000:07B3`.

**main, in order:**
1. Resource pool init (`06C9:6F86`).
2. Video: Hercules if `argv[1]=="herc"`, otherwise EGA init `06C9:90E8` (mode 0Dh, palette from DS:6848).
3. Keyboard ISR install (INT09 → 6907, INT16 → 69B7).
4. Load `voices.bin`, then `songs.bin`.
5. Working surface `B0FE(320,200,0F)`.
6. DISKID and copy-protection checks.
7. Menu loop `00C0:039C`, then session `019E:06C5` → stage load `0267:15E4` → race loop `06C9:1B2C`.

**Copy protection.** `13A8:002E` patches its own code. On failure it sabotages: the 1BF7 tail writes to the INT21 vector segment, and the sim branches at 424A, 4275 and 42AD are flipped. Kylofon writes the "passed" state.

**Race loop `06C9:1B2C`.** Each frame runs 11 helpers, then checks the signed byte DS:5490:
- 0 = continue;
- negative = exit;
- 1–9 = dispatch through the table at DS:2302 (handlers 374F, 3532, 3643, 36E0, 371F, 372B, 3737, 3743, 3713). These are probably crash, police, finish and fuel states; Kylofon names them.

**Timer.** The PIT divisor is 0x2E9C, about 100 Hz. The ISR `61BF` calls a far callback list at DS:5F12 (five slots):
- music `75EA`
- sound effects `6269`
- sim tick `403B` (the sim steps every 10th tick)
- `0143:019E`

Flag 5EFE pauses all callbacks.

**RNG.** `06C9:780E` is a byte ring: cursor DS:66E6 and 256 bytes at 66E8, updated as `b=(b<<1)|(b<0x80)`.

**Input.**
- Key-down table at 62BA+scancode.
- Gameport at port 201h.
- Ctrl hotkeys: J joystick on, K joystick off, S sound effects, Q music, P pause, X quit.

**Resource cache and loaders.**
- 48 descriptors of 18 bytes at DS:68E2.
- Packed loader `6D50` dispatches to RLE `6B02` or Huffman `7C16`.
- Graphics loader `1748:000E` tries `.PES` then `.ESH` and runs UNFLIP.

**Literal `0040:046C` read** (5D83/5D8D, physical 086C, not the BIOS tick). It is used only by the protection delay check, so it has no gameplay effect.

### DOS formats (mostly from Kylofon `FORMATS.md`, consistent with our observations)

**Packed files.**
- Header: `u8 type`, then `u24` unpacked size. Type 1 = RLE, 2 = Huffman, `0x80|k` = k passes; `0x82` = Huffman, then RLE.
- Huffman codes are canonical and read LSB-first. RLE uses an escape table.
- PES and most PCS start with 0x82. The ten EC_ PCS files are a single RLE pass (type 01).

**Archives.** `u32 total`, `u16 count`, `char[4]` names, `u32` offsets measured from the end of the table.

**Sprites.**
- Header: `u16 wbytes, h, hot_x, hot_y; s16 x, y; u8 planemap[4]`.
- PES is EGA planar, with planes selected by planemap nibbles.
- PCS is CGA 2 bpp, with storage modes 1–3 in the high nibble of `planemap[2]`.
- Names ending in `M` are masks.

**Car files.**
- `.BIN` (847 bytes; CAMA is 896, and its extra 49 bytes are unread): 0x34F bytes are copied to DS:23A6. The record holds gears, rpm values, the grip constant, ratios, the shift gate, engine strength, an 81-entry torque curve and the cockpit layout.
- `O.BIN` (32 bytes): 16 words of opponent acceleration.
- `.SS`: ASCII `frames standing ticks` followed by 4-character sprite names.

**Stage `.DAT`** (19 files).
- Packed. The unpacked data is an image of DS:346A–52C7; the game copies a fixed 0x1E5E bytes.
- Contents: 20-byte scenery name, 128 road records `[flags,curve,pitch,object]`, objects, zones, colours, length, traffic (up to 50 cars per direction), then the road byte stream.
- One road unit is 256 sub-units, and 420 units make a mile.

**`.SGN`.** 20 billboard records with NUL-terminated text. Only `TDS20.SGN` exists for the master scenery.

**`.FNT`.** Vector font: 64 offsets, then 4-byte line segments, each glyph ending `FF FF`.

**Catalogs and saves.**
- `CARS.DAT`: 12 cars (F40 P959 CAMA DODG GOAT GT50 STNG VETT ROSS COUN LOTU RUF).
- `SCENES.DAT`: CCC (7 stages), `ec_` (6), TDS2 (6).
- `SELECT.DAT`: drive numbers, then car, opponent and scenery.
- `*HISC.DAT`: 340 bytes, a dump of DS:90B8 with a 32-bit additive checksum.
- `DISKID.DAT`: 9 bytes, meaning unknown (protection).

**Audio.**
- `SONGS.BIN`: song → pattern → 2-byte event sequencer.
- `VOICES.BIN` is just `0D 0A`. Voice records are 32 bytes and are probably read from the bytes that follow in memory (SONGS).
- Driving effects come from TD1's effect player.

**Duplicates.**
- CCCCAR1/2 = TDS2CAR1/2.
- CCC.FNT = EC_.FNT.
- `.SS` groups: CAMA = STNG, F40 = LOTU, GOAT = GT50, ROSS = RUF = VETT.

### CGA bootstrap (from Kylofon `port/`)

- `port/td2cga_functions.json` (440 functions) and `td2tdy_functions.json` exist.
- *[unverified]* 325 of 444 EGA functions have identical size, instruction count, calls and strings in CGA. The segments map one-to-one (EGA 06c9 → CGA 06cf, 0267 → 026e, 13a8 → 1136). Names in `port/symbols.csv` (1,091 entries) can therefore be carried over by segment ordinal and call graph.
- The non-matching functions are the CGA work list: graphics library, scene renderer and PCS fix-up.
- CGA video ports are touched at `06cf:345c`, `5c18`, `5e86` and `5ede`.

### Amiga (nothing reverse-engineered yet)

**Archive.** 352 members; 7-Zip 25.01 at `C:\Program Files\7-Zip\7z.exe` extracts it. Main executable `duel` (108,868-byte hunk); launcher `DuelHD`; `sfx/song` (26,852-byte hunk: replay code plus data).

**Formats.**
- 53 ILBM, 2 8SVX and 177 `Rpck`-wrapped members. Some use `PPkc` (PowerPacker).
- *[unverified]* Raw samples are `u32 BE len`, `u16 BE rate`, then 8-bit PCM.

**Car data** *[unverified]*.
- `*.b2` = the DOS `*O.BIN` byte-swapped.
- `*.b` is a 1,670-byte big-endian car record sharing DOS's grip constant.
- `vectorsigns*` use the DOS SGN offset table in big-endian.

**`scen3`, the Northern Germany Challenge candidate** *[unverified]*.
- 37 members with road files 0–6.
- Its `scen.dat2` is byte-identical to scen2's (`scen/euro_`).
- Most roads and shapes are byte copies from other trees under new names. Only `roaddata1` is unique, and some sign files are edited. It may be a remix, not an original data disk. Verify before building a route importer.

**Tools.** No Amiga tools are installed: no emulator, no 68k disassembler, no hunk parser and no Rpck/PowerPacker unpacker. Ghidra handles 68000 Amiga hunks.

## 6. Kylofon port: status and known deviations

**What it is.**
- `td2port/src`, about 11.7k lines: `host.c` (SDL3), `platform/` (gfx, blit, res, timer, sound, input, prompts) and `game/` (flow, scene, sim, ai, traffic, cockpit).
- It loads the user's TD2EGA.EXE, un-EXEPACKs it into `mem[]` and uses the original DS/CS tables in place.
- It has no CGA (`build.h` stops with `#error` when `TD_CGA` is set) and no PCS loader in C. The Python tools do handle PCS.
- The 100 Hz simulation tick is kept; drawing runs at an emulated 15 fps.

**Deviations the predecessor found** (`docs/recovery/kylofon-r02-r03-results.md`, `kylofon-r04-boundary-review.md`):

| Deviation | Player impact |
|---|---|
| `bios_ticks` reads 0040:006C instead of literal 046C | None (unused) |
| No 20-bit wrap; `INT32_MIN/-1` UB; heuristic EXE loader | None with real data (the patch fixes them) |
| Neutral `clutch_check` skipped (`sim.c:265`) | Missing grind tone |
| Billboard collision always crashes; original tests a stale BP for types ≥0x50 (`sim_motion.c:436`) | Some billboard hits may not crash in the original |
| Traffic DI/CX seeding (`sim_traffic.c:244,367`) | Rare |
| Cockpit steering-marker Y forced to CH=0 (`scene_cockpit.c:207`) | Maybe a pixel |
| Short stage DAT zero-filled instead of leaving stale bytes (`flow_stage.c:518`) | Unknown, probably none |
| 15 fps draw pacing; dissolves paced to the timer | Feel difference; configurable |
| PC speaker audio is a square wave synthesised once per 10 ms tick (`host.c:102`) | Audible quality gap |
| About 26 game text format strings compiled into C | Only matters if strict media-free source is wanted; they can be read from the EXE at their DS offsets |

There are 6 `TODO(verify)` and 81 `PORT:` markers in the source; these are good test priorities.

**Build recipe (proven).** MSVC 19.44 from VS 2022 BuildTools 17.14:
- `vcvars64.bat 10.0.26100.0 -vcvars_ver=14.44`
- `cl /TC /std:c17 /W3 /O2 /utf-8 /MD /D_CRT_SECURE_NO_WARNINGS`
- Link SDL3.lib, bcrypt and the Win32 libraries.

See `tools/build_kylofon_candidate_v1.py`. Alternatively use CMake with `-DSDL3_DIR=…/sdl3-3.4.18/sdk/SDL3-3.4.18/cmake` from an x64 Native Tools prompt. VS-bundled cmake exists; no standalone cmake or ninja is on PATH.

**Run.**

```
td2r03_full.exe --game-dir <writable copy of reference\dos> --user-dir <dir>
```

Without `--user-dir`, the patched build creates `%APPDATA%\TestDrive2\KylofonAdmission`. The unpatched upstream build writes `SELECT.DAT` and `*HISC.DAT` into the game folder.

**Licence.** MIT (Krzysztof Kania). Keep `LICENSE` and note the fork. SDL3 is zlib-licensed.

## 7. Recommended plan

The order still follows the user's sequence (EGA → CGA → resources → native → Amiga → switching). EGA phases 1–3 collapse into "adopt and verify" because a working EGA C core already exists.

| Milestone | Content | Done when |
|---|---|---|
| **M0 Adopt** | Import the Kylofon source into `port/` (or `src/td2/`) with its LICENSE and provenance note. Apply the useful parts of `candidate-fixes-v2.patch`. One CMake build with MSVC and SDL3 3.4.18. A `run.ps1` that copies the data to a scratch folder | The user plays a full race from a clean checkout |
| **M1 Verify EGA** | One generic Unicorn differential harness (original function vs Kylofon C on the same `mem[]` image), run in bulk with ranked results. Fix clutch, billboard, traffic and cockpit. Better speaker synthesis. Headless snapshot tests via `TD2_SNAPSHOT_DIR` | Harness runs over N functions in one command; fixed deviations have regression tests |
| **M2 Backend split** | Introduce `gfx_backend` and `audio_backend` interfaces at `platform/gfx.h` and `sound.h`. The EGA backend must stay pixel-identical | EGA snapshots unchanged |
| **M3 CGA** | Unpack TD2CGA, build the EGA→CGA crosswalk from the function indexes, implement the CGA backend (PCS loader, 2 bpp with an interleaved screen, the CGA palette, colours from the data files; design in `docs/cga.md`). Hotkey switch between EGA and CGA | CGA is playable and switchable live |
| **M4 Resource closure** | `tools/` corpus scan: every one of the 249 DOS files gets a parser or a written disposition | Table generated by script |
| **M5 Amiga RE** | Extract the LHA to `analysis/amiga/`. Write a hunk parser and Rpck/PowerPacker unpackers. Ghidra 68k on `duel`. Decode ILBM, shapes, samples and `sfx/song` replay. Establish what `scen3` really is | Amiga assets decode to inspectable PNG/WAV files privately |
| **M6 Amiga providers and switching** | Amiga gfx and audio backends; atomic switch at a frame boundary; independent music and SFX switching | Switch mid-race with no state change |
| **M7 Northern Germany Challenge** | Route, sign and object converter from `scen3` into the DOS stage model | Full drive through all sections |

## 8. Decisions made in this handover and decisions open

**Made (recommended, user may veto).**
- Build on Kylofon.
- Abandon whole-RAM/flag-exact per-function proofs and the P-gate bureaucracy.
- Keep `reference/` read-only.
- Verify by playing plus targeted differential tests.

**Open for the user.**
1. *Resolved 24 October 2026:* the versioned maps were archived and everything else was committed.
2. Kylofon fork layout: vendor it as a subtree in this repo (recommended) or keep a separate fork repo?
3. Should the strict "no game text compiled into C" policy remain? It matters only for public distribution.
