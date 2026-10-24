# Native Windows phase: design and plan

What the "native Windows" phase means now that the game runs on SDL3, what it has to change, and in what order. The requirements are the user's (2026-10-24):

- Graphics, and later the Amiga version's sound and music, switch on the fly with one key combination that is the same on Windows and on a later macOS build.
- The app ships as a single portable exe.
- Every dialog and window follows the operating system's theme (light or dark).
- No in-game features. Every app feature lives in the app's own context menu or in question windows, never inside the game picture.
- The user needs at least the base DOS game: two cars and the Master scenery. The car and scenery expansions and the Amiga version are optional and can be added later.

## 1. Live graphics switching

### What a switch has to rebuild

The port always runs TD2EGA's game logic. EGA, CGA and Hercules differ only in the graphics backend (`platform/gfx_backend.h`), in which sprite files they load (`.PES`/`.ESH` or `.PCS`/`.CSH`), and in one scenery colour word per stage. EGA and CGA runs reach identical game states at identical times (snapshot runs), so a switch never touches the simulation. It has to rebuild the following.

- **Loaded sprite archives.** Every screen loads its archives by name through `load_shapes`, which picks the extension from the backend. Most screens load, draw and release them at once. A race keeps ten archives for the whole stage (`stage_handles[]` in `game/flow_stage.c`: road, cop, dash, opponent road, the scenery's three traffic cars, scenery, signs and font; signs and font are not graphics but sit in the same load order).
- **Handle tables.** A race looks up thirteen sprite tables by name in those archives: in `main_view_load`, `mirror_load`, `stage_load` (scenery, road, three traffic sets, two cop sets) and `cockpit_load` (dash, dash digits). The simulation and the drawing code refer to sprites only through these tables (`hnd()`); nothing else in the race keeps a pointer into an archive.
- **Buffers.** The page buffer, which is freed during a race, and in a race the main view, the mirror, the instrument cluster and the gear box (`gfx_create_buffer`). Their layout depends on the backend, and their descriptors live in the backend's pool.
- **Scenery colours.** `scene_colours_load` reads the CGA or EGA word from the stage file.
- **Adapter state.** The EGA palette, the CGA registers, the Hercules mode register, and the picture on the screen.

### How a switch is applied

A switch request (key combination or context menu) only sets a pending flag. The game applies it at a safe point, where nothing is half drawn.

- **In a race**, at the top of the drive loop in `run_stage`, between two frames. The switch frees the race buffers and releases the race archives in reverse load order, swaps the backend, loads the same files again with the other extension, and runs the graphics halves of `stage_load`, `main_view_load`, `mirror_load` and `cockpit_load` again: the table lookups, the buffers, the scenery colours, and the cockpit drawn onto the screen. It does not run their resets of positions, fuel and timers. It then sets the HUD, gear gate and instrument redraw flags. The race goes on from the same state on the next frame. During a message, the crash sequence or the stage-end sequence, the switch waits for the drive loop.
- **On other screens** (menus, car and scenery choice, difficulty) the screen's input wait returns a redraw signal when a switch is pending. The screen releases its archives, applies the switch, then draws again from its top with its current choices kept.
- **Applying the switch** calls the backend's `shutdown`, `gfx_set_backend`, then `reset` and `set_mode`, and re-points the host's frame source, which changes the window's size ratio (Hercules is 640 × 300).

### Where it stands

The race switch is built (step 2 below).

- **The key.** `host.c` turns Ctrl+Shift+G into `HOST_CMD_NEXT_GRAPHICS` and keeps the key from the game, including its release. `main.c` passes the command to `gfx_request_next_backend`, which only records the next mode. `TD2_KEYS` scripts accept the combination as `40:Ctrl+Shift+G`.
- **Applying it.** `gfx_apply_pending_backend` (`gfx.c`) does the work:
  - it puts back the load image's screen descriptor and row table, which the EGA backend uses and the CGA backends overwrite;
  - it clears the Hercules flag;
  - it runs the new backend's `reset` and `set_mode`;
  - it points the window at the new frame size.
- **In the race.** `run_stage` checks for a pending switch at the top of each frame. `race_switch_graphics` (`scene.c`) frees the four race buffers. `stage_shapes_switch` (`flow_stage.c`) releases the eight sprite archives, applies the switch and loads them again. `race_switch_graphics` then reruns the scenery colours, `main_view_load`, `mirror_load`, the sprite tables (`stage_find_handles`, split out of `stage_load`) and `cockpit_load`, and sets the redraw flags. Archives released by the switch stay in the file cache, so switching back reuses them.
- **On the menu screens** (step 3 below). The main menu, car select, scenery select and the difficulty screen read keys with `getkey_timeout_switch` (`flow.c`), which returns `KEY_SWITCH` as soon as a switch is pending. The screen releases its sprite archives, and `flow_switch_graphics` applies the switch and makes the page buffer again in the new layout. The screen then draws itself again from its top, keeping the current choice; the attract demo carries on.
- **Text colours.** The game keeps its text colours in memory as the colour numbers of the mode that set them (`COL`). A switch to the other adapter translates them through the pairs the text uses: EGA 0Fh is CGA 3, EGA 0 is CGA 0, and so on.
- **Other screens** (titles, credits, showroom, gas station, police stop, results, high scores) show for a few seconds or wait inside the original's own routines. A switch asked for there stays pending until the next menu screen or race frame. This could be extended screen by screen if it matters in play.

### How it is tested

`tools/snapshots.py` has two switch runs for each adapter, which go round all three modes and back:
- `switch` is the attract run with Ctrl+Shift+G at 45, 52 and 60 s, during the demo drive;
- `menuswitch` is the menu run with Ctrl+Shift+G on the main menu, in car select and in scenery select.


- `round_trip()` checks the frames after the last switch against the run without switches:
  - `switch`, from 62 s on, frame by frame. The race keeps its frame count, and an identical race shows that the switch left it as it was.
  - `menuswitch`, from 64 s on, by game time. A screen that draws itself again shows a different number of frames.
- It also checks that some earlier frame differs, so a switch did happen.
- The frames in each mode are also hashed in the baselines.
- All three adapters pass. From EGA, the drive is shown in CGA, then Hercules, then EGA again, and the rest of the attract loop is identical.
- **Not covered.** A switch at one moment is not compared with a run that used the other mode from the start. The screen redraws change the timing of the attract demo's random menu moves, so such runs part ways.

### Sound

DOS sound is PC Speaker only, so there is nothing to switch until the Amiga phase. The same pending-switch mechanism and the same key combination family will switch between PC Speaker and the Amiga's samples and music then.

## 2. App UI: context menu and question windows

The game picture stays the original game. App features live in `src/app/`:
- `app_ui.h` is the operating-system layer, with one implementation per system: `app_ui_win32.c` now, `app_ui_macos.m` later.
- `app_menu.c` builds the menu and carries out the choice, the same on every system.

The context menu, the pause, the theme and the question windows are built (steps 4 and 5 below).

- **Context menu.** It opens with a right click on the window or with Ctrl+Shift+M. It lists:
  - Graphics: EGA, CGA, Hercules, and "Next mode" (Ctrl+Shift+G). The current or pending mode has the radio mark.
  - Hercules monitor: white, green or amber, which changes the picture at once. This answers the phosphor question without a decision now. The choice is saved in the settings.
  - Window size: 1× to 4×, and full screen (Alt+Enter).
  - Game files…: what is installed, and adding an expansion folder or archive (section 3).
  - About Test Drive II: the version, where the game files come from, the licences and the key combinations.
  - Quit.
  On Windows it is a Win32 popup menu (`TrackPopupMenuEx`) on the SDL window's handle. On macOS it will be an `NSMenu`.
  The menu opens inside `host_pump`, at any point of the game, so every command is one that is safe at any time. A graphics choice is only a request, applied at the next safe point (section 1).
- **Question windows.** Used for errors, confirmations, the first-start setup, Game files and About. On Windows, the standard message box and task dialog do not follow dark mode, so `app_ui_question` draws its own small window: a text and up to a few buttons, the first one the default, Esc or the close box for the last.
  - It uses the system's message font at the window's DPI, and wraps the text at about 440 pixels.
  - In dark mode it has a dark background and text, the dark title bar (`DWMWA_USE_IMMERSIVE_DARK_MODE`) and the dark Explorer theme on its buttons. In light mode it uses the standard colours.
  - It is modal: the owner window is disabled while it is open, and the game is paused.
  - The folder and archive pickers are the Windows file dialog (`IFileOpenDialog`), which follows the theme. The archive picker filters zip, 7z, rar, lha and lzh.
  - Checked in dark mode only: the machine here is set to dark. Light mode is still to be looked at.
  - On macOS, `NSAlert` and `NSOpenPanel` will follow the theme by themselves.
- **Theme.** SDL3 does this already for its windows: on creation and on every theme change, `WIN_UpdateDarkModeForHWND` does three things.
  - It calls uxtheme's undocumented `SetPreferredAppMode(AllowDark)` (ordinal 135, Windows 10 1903 and later) and `AllowDarkModeForWindow`.
  - It sets the title bar's dark mode.
  - So a popup menu owned by the window follows the system's app theme with no code of ours: dark title bar and dark menu, checked on Windows 11.
- **Pausing.** While a menu or dialog is open the game stops. A Win32 popup menu runs its own message loop, and the game must not count that time.
  - `host_pause_begin` pauses the sound device.
  - `host_pause_end` moves the tick clock and the frame pacing on by the paused time, so no ticks are owed, and resumes the sound.
- **Keys.** The app swallows its own combinations before the game's keyboard handler sees them. The game reads raw scan codes, so the combinations must avoid every key it uses. Ctrl+Alt is not usable: on many European layouts, Turkish included, it is AltGr.

## 3. Game files

### What the base game is

The base DOS game is 73 files, about 600 KB:
- the three executables (`TD2EGA.EXE`, `TD2CGA.EXE`, `TD2TDY.EXE`) and `DUEL.EXE`;
- the common screens (`ACCOLADE`, `TESTDRV2`, `DSITITLE`, `GAMEOPT`, `GAMEDIFF`, `GASSTUFF`, `ENDGAME`, `COP`, `ROAD`);
- `SONGS.BIN` and `VOICES.BIN`;
- the catalogues `CARS.DAT`, `SCENES.DAT`, `SELECT.DAT` and `DISKID.DAT`;
- the two cars, Ferrari F40 (`F40*`) and Porsche 959 (`P959*`);
- the Master scenery (`TDS2*`).

Each sprite file comes as `.PES` and `.PCS`. The port needs `TD2EGA.EXE`, because it runs that image's data. The optional sets in this copy are:

| Set | Files | Prefixes |
|---|---|---|
| The Supercars | 55 | ROSS, COUN, LOTU, RUF, VETT |
| The Muscle Cars | 55 | CAMA, DODG, GOAT, GT50, STNG |
| California Challenge | 32 | CCC |
| European Challenge | 34 | EC_ |

A car is its `.BIN`, `O.BIN`, `.SS`, and its `DASH`, `REAR`, `ROAD` and `ST` sprite files. A scenery is its stage `.DAT` and `.SGN` files, its font, its `CAR1`–`CAR3` traffic and its other sprite files.

The DOS version has two scenery expansions, the California Challenge and the European Challenge, both in this game copy. The Amiga version has three more, one of them the fan-made Northern Germany scenery; they belong to the Amiga phase.

### How the app finds them

Built (`src/app/app_data.c`; step 5 below, first half).

- **Catalogues.** The original learns which cars and sceneries exist from `CARS.DAT` and `SCENES.DAT`. Each car or scenery disk had its own pair, which the game's INSTALL option read. The app does the same with folders: it reads the `CARS.DAT` and `SCENES.DAT` of every game folder, base first, and merges the entries in that order. It keeps only the cars and sceneries whose files are all there, and writes the result to the profile folder, which the game reads before the game folders.
  - A car is complete with its `.BIN`, `O.BIN`, `.SS` and its `DASH`, `REAR`, `ROAD` and `ST` sprite files.
  - A scenery is complete with its `CAR1`–`CAR3` and `ICON` sprite files. Its stage count is the listed one, cut to the stage files present.
  - Sprite files must be there as both `.PES` and `.PCS`, so that live switching works.
- **Base-game check.** At start the first game folder must hold the base game (the list in "What the base game is"). Otherwise the app says which file or set is missing and that expansions are optional.
- **Game folders.** In order, they are `--game-dir`, the settings' `game` and `expansion` folders, `Game` next to the exe, or `Game` in the working directory. They are only read; the game finds each file in the first folder that has it.
- **Profile folder.** It holds `settings.ini`, the high scores, `SELECT.DAT` and the generated catalogues. It is `--user-dir`, else `Profile` next to the exe when that folder is writable (portable), else `%APPDATA%\TestDrive2`. The settings live there rather than loose beside the exe, so test runs with `--user-dir` never see a player's choices.
- **Settings.** `settings.ini` holds `game`, `expansion` (any number), `graphics`, `hercules_monitor`, `scale` and `fullscreen`. The menu writes it on each change, and the command line overrides it.
- **Archives.** The game and expansion files may also come inside zip, 7z, rar (4 and 5) or lha/lzh archives (the user's requirement, 24 October 2026).
  - A `game` or `expansion` entry that names a file is unpacked once into `Profile\Archives\<archive name>` (`src/app/app_archive.c`, libarchive). A `.unpacked` marker records the archive's size and time, so a changed archive is unpacked again.
  - The game folder used is the shallowest folder inside that holds `CARS.DAT`, `SCENES.DAT` or `TD2EGA.EXE`.
  - Paths that would leave the destination are skipped.
- **Archive libraries.** libarchive 3.8.1 with zlib 1.3.1 and xz 5.8.1 (liblzma) are built static with the static C runtime by `build.ps1`, once, into `analysis/external/archive-libs/install`. Each comes from its official GitHub release.
  - The libarchive and zlib downloads match their published SHA-256.
  - xz publishes no checksum on GitHub, only a signature, which was not checked.
  - `build.ps1` patches one line of libarchive. Its LHA reader took a level 1–3 header only with the MS-DOS attribute 20h, but Amiga LhA writes protection bits there (00h, 02h). The user's Amiga archive was therefore "Unrecognized archive format". libarchive reads the attributes it uses from the extended headers, so the patch accepts any value in that byte.
- **Tested archives.**
  - The base game zipped with an extra folder level, plus the Supercars expansion as a 7z, play like the folders: seven cars.
  - libarchive's own RAR 4, RAR 5 and LHA (lh7) test archives unpack.
  - The user's Amiga archive (`TestDrive2&DataDisks_v1.1_HD_JOTD.lha`, 352 files, lh5) unpacks with every file's checksum passing.
- **Tested folders.** A base-only folder (73 files) lists two cars and the Master scenery. Adding a separate Supercars folder with its own `CARS.DAT` lists seven cars. The full game folder gives the same catalogues as its own files, and every snapshot is unchanged.

- **First start.** Without `--game-dir`, a set `game` folder or a `Game` folder next to the exe, a question window says that the base DOS game is needed and that expansions are optional. Its buttons choose a folder, choose an archive, or quit. The choice is checked, saved as `game`, and the start goes on. A folder without the base game says what is missing and asks again.
- **Game files….** The menu entry lists the base game and each expansion as the player chose them (the archive, not its unpacked folder), then the complete cars and sceneries by name. Add folder… and Add archive… pick an expansion and check it. One with no complete car or scenery is refused with a message. Otherwise it is saved as an `expansion` entry and the window offers a restart, which starts the exe again with the same command line.
- **Errors at start** (no base game, a broken archive, no profile folder) come in the same question window rather than only on the console.

## 4. Single portable exe

Done for the build (step 1 below). `build\td2port.exe` is about 3 MB and needs only Windows system DLLs.

- **SDL3 is linked statically.** The SDL 3.4.18 source release (`SDL3-3.4.18.tar.gz`, SHA-256 checked against the release's published digest) is unpacked in `analysis/external/sdl3-3.4.18/source`. The top-level CMake build adds it with `SDL_STATIC=ON` and `SDL_SHARED=OFF`; `build.ps1` passes `TD2_SDL_SOURCE`. SDL's zlib licence allows this without conditions on the binary.
- **The C runtime is linked statically too** (`CMAKE_MSVC_RUNTIME_LIBRARY` = `MultiThreaded`), so no Visual C++ runtime DLLs are needed.
- **The exe is a windowed app** (`/SUBSYSTEM:WINDOWS`, still entered at `main`), so no console window opens. Output a caller redirects (the snapshot tool, `run.ps1`'s pipe) works as before. Otherwise the exe writes to the console it was started from. Like any windowed app, it returns to a terminal prompt at once when started directly, so `run.ps1` pipes its output to wait for it.
- **An embedded manifest** (`td2port.manifest` via `td2port.rc`) gives common controls v6, per-monitor DPI awareness v2 (SDL3's own default anyway), the UTF-8 code page and `asInvoker`. A version resource and the app icon go with it. The icon (`td2port.ico`, 16 to 256 pixels) is made from the user's own artwork, not original game media. SDL gives its window class the exe's first icon, so the window and the taskbar show it too.
- **Archive libraries** (libarchive, zlib, liblzma) are linked statically as well (section 3).
- **Settings** go to `Profile\settings.ini` next to the exe when that folder is writable, which makes the app truly portable. Otherwise they go to the per-user folder (`%APPDATA%\TestDrive2`). This is the user's decision (section 3).
- The command-line options stay for scripts and tests.

## 5. Order of work

1. **Single exe.** Static SDL3 and C runtime, manifest, version resource. Done; the snapshots, tests and harness are unchanged.
2. **Pending-switch mechanism and the race switch.** Done, with the `switch` snapshot run.
3. **Screen redraw on switch.** Done for the four menu screens, with the `menuswitch` snapshot run. Other screens leave the switch pending.
4. **App UI layer on Windows.** Done: the context menu with the system theme, Ctrl+Shift+M and right click, pausing, and the graphics, monitor, window size, full screen and quit commands. The question windows move to step 5.
5. **Game data manager.** Done: settings file, portable profile, game and expansion folders, base-game check, merged catalogues, archives (zip, 7z, rar, lha), the question windows, the first-start setup, and the Game files… and About entries.
6. **macOS** (later): the same `app_ui` interface with AppKit.

## Decisions (user, 24 October 2026)

- **Key combination:** Ctrl+Shift+G cycles the graphics mode (EGA → CGA → Hercules). Ctrl+Shift+S will switch the sound in the Amiga phase; it also makes the game's Ctrl-S code (13h, sound on/off), so the app must keep it from the game, as it does with Ctrl+Shift+G (07h, unused by the game). Ctrl+Shift+M or a right click opens the context menu. Ctrl means the Control key on macOS too, so the combination is the same on both systems.
- **Settings and profile:** next to the exe when that folder is writable, otherwise `%APPDATA%\TestDrive2`.
- **SDL source:** downloaded; the exe links SDL3 statically (section 4).
