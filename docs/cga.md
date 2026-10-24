# TD2CGA against TD2EGA

How the CGA executable differs from the EGA one we already run, function by function, the design of the CGA backend that follows from it, where that backend stands, and TD2CGA's Hercules mode. `python tools/cga_compare.py` produces every number here; `python tools/cga_compare.py 06c9:0c17` prints one function's differences side by side. It reads both executables from `runs/game` and unpacks them in memory with `tools/exepack.py` (`unpack()`; it also handles TD2TDY).

## Summary

- **The simulation is the same program in both.** All 15 simulation functions that looked different are identical once the relink is accounted for. They differ only in where variables, tables and functions sit. The port's simulation code serves CGA unchanged.
- **The scene renderer's differences are all about drawing.** Of the 29 scene-renderer functions that looked different, 12 are identical after relinking. The other 17 differ only in how pixels reach the screen and which colour values they use:
  - 2-bit pixels in one buffer instead of four planes;
  - dither patterns instead of colour numbers;
  - the colour-select port instead of the palette.
- **The game data already carries CGA colours.** Each scenery `.DAT` and each sign record holds a CGA pattern next to every EGA colour, and each build reads its own.
- **So a CGA backend is mostly a presentation job.** The game state and the projection are shared; what changes is the pixel routines, the colour values, and four scene helpers that write pixels themselves. The design is at the end.

## Status

The backend is built as designed and plays: `.\run.ps1 --cga`.
- **Code.**
  - `platform/gfx_cga.c`: the library.
  - `gfx_cga_blit.c`: the blitters.
  - `gfx_cga_scene.c`: the `SceneRaster` hooks.
  - `res_fix_pcs_archive` in `res.c`: the PCS fix-up.
  - `car_slide_cga` in `game/flow_screens.c`.
  - `COL(ega, cga)` and `XBYTES(n)` at the game code's constants.
- **Checked against TD2CGA's own code** (`tools/diffharness/cga.py`, 200 cases each): the 24 blitters, the three grabs into sprites, `grab_screen`, `fill_rect`, `fill_rect_clip`, `clear_clip`, `clear_screen`, `plot`, `draw_line`, `draw_line_or`, `draw_text`, both dissolves, and the scene's span fill and `hline`.
- **Checked by snapshots and by eye.** `tests/cga_snapshots.txt` holds the attract loop and a scripted menu run. Scripted runs also reached the scenery screens, the exit prompt and player races with crashes.
- **Covered only by snapshots.** The road marking pixels and the crash flash. Stage results, high-score entry and the police ending have not been reached in CGA.
- **Deliberate differences.**
  - For a steep line drawn upwards, TD2CGA's OR line takes its start x from a stale stack word. The port uses x1; the game only draws straight OR lines.
  - A ground span ending before the current x would make TD2CGA's `rep stosb` run through 64K. The port writes nothing; the shipped spans are always ordered.

## Hercules mode

`DUEL.EXE`, the original launcher, offers four modes. Option 1 runs `td2cga.exe` (CGA or Tandy 4-colour), option 2 `td2tdy.exe` (Tandy 16-colour), option 3 `td2ega.exe`, and option 4 runs `td2cga.exe herc`. So Hercules is TD2CGA's game, not TD2EGA's. TD2EGA has a Hercules branch too, but its drawing still writes the EGA planes, and the launcher never uses it. Tandy 16-colour is out of scope by the user's decision.

- **What changes.** TD2CGA's `main` calls `herc_init` (06CF:5E86) instead of the CGA mode set (06CF:8854) when `argv[1]` is `herc`, and at the end it calls `video_shutdown` (06CF:5EDE), which restores Hercules text mode. Nothing else reads the Hercules flag (DS:5D0E): every drawing routine is the CGA one, writing the CGA layout at B800h.
- **What the monitor shows.** `herc_init` sets BIOS mode 4, then programs the Hercules card: 3BFh = 3, the 6845 from DS:5D10, page 1 (B800h) cleared, and 3B8h = 8Ah (graphics, video on, page 1). The 6845 table gives 40 character columns of 16 pixels and 100 character rows of 3 scan lines (R1 = 28h, R6 = 64h, R9 = 2). Scan line k of a character row reads bank k at offset k × 2000h. Row r therefore shows game row 2r from bank 0, game row 2r+1 from bank 1, and a line from bank 2, which stays clear. The picture is 640 × 300 one-bit pixels:
  - each 2-bit pixel becomes two 1-bit pixels (colour 1 lights the right one, 2 the left one, 3 both);
  - every third line is dark, which stretches the 200 game rows over the taller Hercules raster.
- **What has no effect.** The game's CGA register writes (`gfx_video_hook`, the crash flash on 3D9h) go to ports that a Hercules machine does not have, so there is no flash.
- **Port.** `gfx_herc_backend` in `gfx_cga.c` (`--hercules`) shares the whole CGA drawing table and has its own reset, compose (640 × 300), `set_mode` (`herc_init`) and shutdown. The monitor colour is a white phosphor, a port choice; the original card shows whatever the monochrome monitor's phosphor was. The CGA cursor glyphs moved from BC00h, inside Hercules page 1, to C000h. `tests/herc_snapshots.txt` holds the same two runs as the EGA and CGA baselines.

## Layout of the two executables

| | TD2EGA | TD2CGA |
|---|---|---|
| Unpacked image | 130,240 bytes | 119,872 bytes |
| Entry | 13A8:03F8 | 1136:03F8 |
| DGROUP (relative) | 178F | 151D |
| Initialised DGROUP data | 83D0h bytes | 8270h bytes |
| Graphics library segment | 06C9 | 06CF |
| Live target descriptor / screen descriptor | CS:AF3A / CS:AF54 | CS:913E / CS:9158 |

- The 22 segments correspond one to one, in the same order (for example 0267 → 026E, 0432 → 0439, 13A8 → 1136).
- CGA's initialised data is 160h bytes shorter, so every uninitialised variable (the whole race state from about DS:8270 on) sits 160h lower in CGA: `clock_seconds` is DS:942E in EGA and DS:92CE in CGA.
- Initialised tables move by varying amounts (C4h, C8h, E0h, F8h, 104h) because CGA's tables of colours, sprites and patterns have different sizes. For example, the stage file buffer is DS:346A in EGA and DS:3366 in CGA.
- The graphics library's target descriptor has the same 13-word layout in both builds; only its place in the code segment differs.

## How functions are compared

- **Pairing.** Functions come from the Kylofon indexes (`port/td2/port/td2{ega,cga}_functions.json`). They are paired segment by segment by aligning size, instruction count, call count and strings. Pairs are then corrected from the calls: when two paired functions call something at the same place, the two callees are twins.
- **Normalising the relink.** Both disassemblies are rewritten before comparing:
  - Branch targets become instruction labels compared through the alignment, and jumps that leave a function name the function they land in.
  - Calls become the EGA name of the callee, and segment constants become the EGA segment.
- **Accepting a moved address.** A number that differs counts as the same only if the CGA value is provably the moved EGA address. The evidence is one of:
  - the same bytes at both places;
  - the uninitialised-data shift;
  - the same offset inside a paired function;
  - a jump table whose entries point to paired code;
  - the graphics descriptor block;
  - a shift that at least two different variables in the same area show in the code.

  A single coincidence cannot pass, so what is left is a real difference.
- **Buffers whose base the code loads.** When the code loads a buffer's base address as a constant (the stage file buffer, the sign record, the dashboard digit handles), the buffer moves by that base's shift. This overrules the neighbouring-variables rule, which had hidden that CGA reads different words of the same records (see "Colours").
- **Index mistakes this corrects.**
  - The indexes sometimes stop a function early (unfollowed jump tables, or the last function of a segment): CGA `police_start`, `steer_update` and `main_menu`. Each function is therefore compared up to the next indexed function, and a cut function gets its twin's length.
  - One EGA index entry, 06C9:1A37, is the tail of `draw_front_objects`; another, 06C9:C030, is the tail of the XOR blitter. 06C9:AF54 is not code at all: it is the screen descriptor.

## Simulation (15 functions): all identical after relinking

`steer_update`, `sim_timer_routine`, `decode_controls`, `curve_sum`, `overrev_check`, `motion`, `roadside_hit`, `traffic`, `meet_check`, `push_behind`, `ai_road_scan`, `ai_lane_min`, `police_reset`, `police_start`, `police_drive`.

Every difference in them was a moved variable, table, jump table or function, or an index cutting the function short.

## Scene renderer (29 functions)

**Identical after relinking (12):** `main_view_load`, `project_front_rows`, `build_spans_front`, `interp_span`, `project_mirror_rows`, `fix_cut_lines_mirror`, `clamp_edge_mirror`, `run_stage`, `sim_stage_start`, `engine_smoke_sequence`, `draw_ticket`, `msg_missed_gas`.

**Different (17), all in drawing or colour values:**

| Function | What CGA does differently |
|---|---|
| `stage_load` | Reads the scenery colours from the CGA words of the stage file (offsets 320h, 324h, 328h, 32Ch, 330h) instead of the EGA words 2 bytes later. |
| `draw_front`, `draw_mirror` | No longer copy the target's four plane segments (CS:AF3C..AF42) to DS:5420..5426; the CGA target is one 2-bit buffer. The fall fills use patterns: water colour 9 → 4444h, cliff colour 6 → 8822h. |
| `span_fill_to` | Rewritten for 2 bits per pixel. EGA writes four planes with per-plane colour bytes (DS:5428..5458). CGA writes one buffer with the low byte of a 16-bit pattern (kept at DS:09BE), with 4-pixel masks (DS:531C). The pattern is rotated by 2 bits on odd rows (`test si,2; ror bx,1; ror bx,1`), which turns 8888h into a checkerboard. |
| `hline` | EGA calls `gfx_draw_line` with a y coordinate. CGA takes a row address, draws the span itself with left and right masks for 4 pixels per byte (DS:5320..532B), and uses the high byte of the colour as the pattern, rotated by 2 bits on odd rows. It does not clip. |
| `draw_sky_front`, `draw_sky_mirror` | Before the horizon blit, both coordinates are forced odd (`or ax,1; or di,1`). Probably this keeps the sprites' dither in step with the background; not confirmed. |
| `draw_ground_front`, `draw_ground_mirror` | The road colour 7 (grey) becomes 0 (black). One extra store clears the first byte of each row before the spans; it has no visible effect, because the first span always rewrites that byte. |
| `draw_tunnel_walls_front`, `draw_tunnel_walls_mirror` | Pass `hline` a row address from the buffer's row table and step it by one row (80 bytes in the front view, 20 in the mirror) where EGA steps y by 1. The wall colour 8 becomes the pattern 9966h in the middle and 0 at the sides. |
| `draw_front_objects`, `draw_mirror_objects` | Road markings are ORed white pixels at 4 pixels per byte; EGA's centre dot is yellow (colour 14). Cliff colour 6 → 8822h, tunnel dark 8 → 0. Several object positions are forced odd or even. The cliff decorations are drawn without their AND masks. The white band across the road uses the scene `hline` (pattern FFFFh, row table, no clipping) instead of clipped lines. The sign board, post and lettering colours come from the CGA words of the sign record (offsets 0Eh, 12h, 0Ah instead of 0Ch, 10h, 08h). |
| `crash_sequence` | The crash flash writes the colour-select register (port 3D9h, 0 on even frames, 30h on odd ones) instead of loading the EGA palettes DS:2E10 / DS:2E08 through `gfx_set_palette`; at the end it only calls `gfx_video_hook`, which restores 30h. |
| `draw_steering` | The marker's save position is aligned to 4 pixels (`and dx,0FFFCh`) instead of 8. |
| `draw_instruments` | The speed and rev needles are drawn with FFFFh (white pattern) instead of colour 15. |
| `create_buffer_like` | Width in pixels is the byte width times 4, not 8. |

## Other differences worth knowing

- **`gfx_video_hook`.** Empty in EGA. CGA writes the mode-control register (3D8h ← 0Eh) and the colour-select register (3D9h ← 30h).
- **`gfx_set_mode`.** CGA sets BIOS mode 4 with palette 1 and a black background. The hook's 0Eh then sets the black-and-white bit, which on an RGB monitor gives the third CGA palette: cyan, red and white. Bit 4 of 30h selects the bright versions, so the crash flash is a dim/bright flicker.
- **Menus and game flow.** Same code with CGA colours (0Fh → 3, 6 → 2, 4 → AAAAh, 0Ah → 5555h) and pixel/byte shifts of 2 instead of 3. `car_slide`, the car-selection slide, builds the picture in an extra 320×176 buffer, where EGA scrolls the screen with write-mode-1 copies, which CGA hardware does not have. `load_shapes` looks for `.PCS`/`.CSH` files and gives the sprite fix-up 3EAh paragraphs of scratch (16,032 bytes) instead of 1F6h (8,032). `car_select` passes `car_slide` its start and end rows the other way round. The prompts (`exit_prompt`, `status_strip`, `pause_prompt`, `joy_calibrate_screen`) use text colour 1 and outline AAAAh for EGA's 15 and 4.
- **Graphics library.** All of it differs. The pairing there is weaker, because CGA's library has different routines in a different order. Pairs that the scene code calls are reliable, since they come from call-site votes. The harness has since confirmed the pairs of the 38 library routines it tests; others may still be wrong.

## Colours

What a colour value means depends on the build and, in CGA, on the routine that receives it.

- **EGA.** A colour number 0..15 through the palette. Callers often pass the number repeated in every nibble (2222h) or FFh/FFFFh; the routines use the low 4 bits.
- **CGA.** A pixel is 2 bits: 0 black, 1 cyan, 2 red, 3 white (bright while 3D9h bit 4 is set). Colours are patterns of 4 pixels per byte:

| Routine | Colour argument |
|---|---|
| `gfx_fill_rect` (06CF:8438) | A word: the high byte fills even rows and the low byte odd rows. |
| `gfx_draw_line` (06CF:80AE) | The low byte, masked to each pixel. |
| `gfx_plot` (06CF:9BA6) | A 2-bit pixel value. |
| `gfx_clear_screen` (06CF:8032) | A word stored over the whole screen. |
| Scene `span_fill_to` | A word: the low byte; on odd rows the word is first rotated by 2 bits. |
| Scene `hline` | The high byte; on odd rows rotated by 2 bits. |

**Where CGA's colour values come from:**
- **Data files.** Both builds load the same files and pick different words:
  - Scenery colours in the stage `.DAT`: CGA reads offsets 320h, 324h, 328h, 32Ch and 330h for left, right, shoulder, sky and far; EGA reads 322h..332h. In one recorded race these are 8888h/2222h for both sides, AAAAh/8888h shoulder, 5555h/BBBBh sky and 8888h/6666h far: a cyan sky over red dither in CGA, and light cyan over green in EGA.
  - Sign records (copied to DS:52E4 in EGA, DS:51E0 in CGA): CGA reads the words 2 bytes after EGA's, at 0Ah (lettering), 0Eh (board) and 12h (posts).
- **Code constants.** These differ per call site, so there is no single EGA-to-CGA table: colour 8 becomes 0 in the tunnel mouths and 9966h in the tunnel walls.

| EGA | CGA | Where |
|---|---|---|
| 6 (cliff) | 8822h | cliff walls, fall fills, objects |
| 7 (road) | 0 | ground |
| 8 (tunnel) | 0 | tunnel mouths, wall sides |
| 8 (tunnel wall) | 9966h | tunnel wall middle |
| 9 (water) | 4444h | fall into water |
| 14 / 15 (markings) | white pixels | road markings |
| 15 (needles, road band) | FFFFh | instruments, white band |
| 0Fh, 6, 4, 0Ah (menus) | 3, 2, AAAAh, 5555h | game flow screens |

## Data tables

- **Masks.** CGA keeps several 4-entry mask tables: DS:531C..532F for the scene, and DS:66D8, 66DC, 676E, 6772 for the library. They are the regular 2-bit masks and shifts (FF 3F 0F 03, C0 30 0C 03, and so on). The backend computes them rather than reading them from TD2CGA.
- **Row tables.** Every buffer descriptor points to a table of row addresses (word 0Ah, as in EGA). Off-screen buffers are linear: 80 bytes per row for the 320-pixel front view, 20 for the 80-pixel mirror. Only the screen at B800h is interleaved: even rows from offset 0, odd rows from 2000h, 80 bytes each. The CGA `create_buffer` builds these tables.
- **Colours.** From the data files, or the constants listed above.
- **Hardware state.** Mode control 0Eh, colour select 30h (0 during the crash flash).
- **Sprites.** The `.PCS` files (2 bits per pixel, storage modes 1–3), next to the `.PES` files EGA uses. The PCS loader and the CGA blitters are the largest remaining piece.

## CGA backend design

The aim is one copy of the game and scene logic, with the CGA differences behind the existing `GfxBackend` table plus a few named switches. Live switching (a later milestone) then means swapping the backend and reloading the scenery colours.

1. **Graphics library: a second backend.** `gfx_cga.c` and `gfx_cga_blit.c` implement the `GfxBackend` routines for a 2-bit buffer:
   - colour arguments as in the table above;
   - descriptors with linear rows for buffers and the interleaved screen;
   - the PCS loader, blitters, dissolves, scroll and grabs;
   - `video_hook` storing 0Eh/30h;
   - `compose` mapping 2-bit pixels through the cyan, red and white palette, with the intensity bit.

   The colour parameters in `GfxBackend` and the `gfx_*` front widen from `u8` to `u16`. The EGA backend keeps using the low byte, so the EGA snapshots must not change.
2. **Scene hooks.** Four routines in the scene code write pixels themselves, so the backend gets a small `SceneRaster` table:

   ```c
   typedef struct SceneRaster {
       u8 px_per_byte;                                    /* 8 EGA, 4 CGA */
       void (*view_begin)(void);                          /* after selecting the view's buffer (EGA: cache plane segments) */
       bool (*span_to)(u16 *row, s16 end, u16 colour, bool odd_row);  /* span_fill_to; true when the row is full */
       void (*hline)(s16 x0, s16 x1, s16 y, u16 colour);  /* scene hline; CGA uses the row table and no clipping */
       void (*marking)(u16 row, s16 x, bool centre);      /* road marking pixel: yellow/white or white */
       void (*crash_flash)(bool flash);                   /* EGA palette swap, CGA port 3D9h */
   } SceneRaster;
   ```

   Each EGA hook is today's code moved out of `scene_draw.c`, `scene_objects.c` and `scene.c`. The CGA hooks follow 06CF:0C1C (`span_fill_to`), 06CF:0C8E (`hline`), the marking blocks of 06CF:0CED, and 06CF:3505. `draw_steering` and `create_buffer_like` use `px_per_byte`.
3. **Colours by name.** Scene and flow code state both values where the original has a constant, for example `fill(..., COL(6, 0x8822))`, with `COL` picking by the active backend. `stage_load` and the sign drawing read the CGA or EGA word of the record. Since `stage_load` copies the scenery colours into DS:534A..5352, that copy becomes a small function to call again on a live switch.
4. **Small per-site differences.** These are not worth a hook, so they use one `gfx_is_cga()` test each:
   - the coordinates forced odd or even (sky, cliff sprites, objects);
   - the cliff decorations drawn without masks.
5. **What stays as it is.** The simulation, the projection and the 12 identical scene functions. The port keeps running on the EGA image's DGROUP: the CGA build's tables are only needed where listed above, and none has to be read from TD2CGA at run time.

**Verification.**
- The four CGA scene hooks and the CGA library routines get harness cases against TD2CGA's own code. Their outputs are buffer bytes, not DGROUP, so the different data layout matters only for placing the inputs: the harness can translate the few DS addresses with `cga_compare`'s mapping.
- A CGA snapshot baseline like the EGA one comes once the backend draws whole frames.
- Playing a race in CGA is the final check.

**Open questions.**
- Whether the forced-odd coordinates are about the dither phase; this can be checked once frames render.
- Which palette real CGA cards, and DOSBox with `machine=cga`, show for 3D8h = 0Eh. Cyan, red and white is the documented behaviour on an RGB monitor; EGA and VGA cards in CGA mode may differ.
