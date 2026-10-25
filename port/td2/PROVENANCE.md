# Provenance

This folder is a vendored copy of the Kylofon Test Drive II SDL3 port.

- Upstream: https://github.com/kylofon/test-drive-2-sdl3
- Commit: `352b56824d8c91e938b8f0794a71afca9a276193` (v0.1.0, 18 September 2026)
- Imported: 24 October 2026, by plain file copy from the read-only clone at `reference/repos/kylofon-test-drive-2-sdl3`.
- Licence: MIT, Copyright (c) 2026 Krzysztof Kania. The full text is in [LICENSE](LICENSE) and must stay with the code.

## What was copied

- `td2port/` (sources and CMakeLists)
- `LICENSE`, `FORMATS.md`
- `port/spec/*.md`, `port/*.csv`, `port/*_functions.json`, `port/RE_GUIDE.md`

Upstream's tools, README, CI files and generated tables were not copied.

## Local changes

This is a fork. Changes made in this repository after the import:

- `mem.h`: addresses wrap at 20 bits, and 16/32-bit reads and writes wrap per byte, as on the 8086 bus. `idiv32_16` treats `INT32_MIN / -1` as a divide error instead of undefined behaviour.
- `mem.c`: the EXEPACK unpacker checks the relocation count and the packed span before using them.
- `--user-dir DIR`: high scores and `SELECT.DAT` are written to a profile folder, never the game folder. Files there shadow the game folder's copies. The default is the SDL preference folder (`%APPDATA%\TestDrive2` on Windows).
- PC speaker: synthesis moved to `speaker.c` (band-limited PIT mode-3 model with a speaker filter); `host_speaker` takes both port 61h bits. `TD2_AUDIO_DUMP` records the output as WAV.
- Billboard collision: `roadside_hit` decides crash or bump from the BP value the original leaves behind (`sim_stale_bp`), instead of always crashing.
- Neutral clutch grind: releasing fire in neutral runs the clutch check on the leftover CX (rpm or gameport count, `sim_stale_cx`) and DX, as the original does, instead of skipping it.
- Graphics: the library is split into a shared front (`gfx.c`) and an EGA backend (`gfx_ega.c`, `gfx_ega_blit.c`, formerly `gfx.c` and `gfx_blit.c`) behind `GfxBackend` (`gfx_backend.h`). Audio: the host renders through an `AudioBackend` (`audio_backend.h`); the PC speaker backend is in `speaker.c`.
- `TD2_VIRTUAL_CLOCK` and `TD2_RUN_SECONDS`: developer aids for repeatable headless runs. `TD2_HOLD_SECONDS` stops the game at a game time and keeps its frame in the window, for the README's screenshots (`tools/screenshots.py`). The `TD2_AUDIO_DUMP` file now gets every sample even when the device falls behind.
- Packaging: the exe is a windowed app with an embedded manifest and version resource (`td2port.rc`), linked statically with SDL3 (built from source by the top-level build) and the C runtime. `main` attaches to the parent console for its messages. The port's `CMakeLists.txt` still falls back to an installed SDL3 when built on its own.
- Live graphics switching (Ctrl+Shift+G, `gfx_apply_pending_backend`, the race and menu-screen switch points) and the app's context menu in `src/app/` (docs/native-windows.md).
- Game data (`src/app/app_data.c`): several game folders, the base-game check, catalogues merged from each folder, `settings.ini` in the profile folder ("Profile" next to the exe by default). `host_init` no longer takes the game folder; `host_add_game_dir` adds each one.
- Game archives (`src/app/app_archive.c`): zip, 7z, rar and lha game files, unpacked with libarchive (static, built by `build.ps1`, with a one-line patch that lets its LHA reader take Amiga LhA headers).
- Question windows (`app_ui_question`, `app_ui_pick_path` in `src/app/app_ui_win32.c`): start errors, the first-start setup, and the menu's Game files… and About entries.
- `TD2_STATE_DIR`: a developer aid (`host_sim_state`, called at the top of `sim_timer_routine`) that saves the sim timer routine's entry state for the differential harness.

Git history in this repository records each later change.

## Third-party data

- **Topaz font** (`td2port/src/platform/topaz.c`): the Amiga's ROM font, used for the Amiga form's text.
  - Source: `raw/Topaz_a500_v1.0.raw` from the amigafonts collection, https://github.com/rewtnull/amigafonts, commit `d42987535d94ebbfb51e64fee76f9974c6ae145a` (17 January 2020), SHA-256 `a2eb9796b82bcad885211e14684960352aaaca559ea82cb3cbd7dec3fdbaafb0`. Downloaded 25 October 2026.
  - Change: the file is 8x16 with every row twice; the table keeps one row of each pair (8x8).
  - Copyright: Topaz is (c) Amiga Inc. The raw version of Topaz is (c) dMG/t!s^dS! (dMG of TrueSchool and Divine Stylers, who pixeled, vectorised and converted the collection).
  - Licence: the collection's README releases its fonts "under the GPL-FE license", the GNU General Public License with the font exception (https://www.gnu.org/licenses/gpl-faq.html#FontException). It names no GPL version. This licence differs from the MIT licence of the code around it; the font ships inside the exe under its own licence, the user's choice (25 October 2026).

The original game and its data are (c) 1987 Accolade / Distinctive Software Inc. and are not part of this code.
