# Amiga version: files, findings and plan

Started 24 October 2026. The source is the user's archive `reference/amiga/TestDrive2&DataDisks_v1.1_HD_JOTD.lha`: Jean-François Fabre's HD install of the Amiga game with its car and scenery disks. `docs/planning/amiga-evidence-and-plan.md` is the earlier inventory (file hashes and first bytes); this file replaces its plan.

For the tools, unpack the archive once into `runs/amiga` (gitignored): the app does this itself when the archive is added under Game files, and `runs/amiga` is a copy of that folder. All tools below read from there.

## 1. What is in the archive

| Folder | Content |
|---|---|
| root | `duel` (the game), `DuelHD` (the HD patch loader), the catalogues `cars.dat0`, `scen.dat0`, `select.dat0` |
| `cars` | Ferrari F40 and Porsche 959 (base disk) |
| `cars1` | The Muscle Cars: `camo`, `dodge`, `gt500`, `gto`, `stingray` |
| `cars2` | The Supercars: `coun`, `lotu`, `ross`, `ruf`, `vett` |
| `pics` | title, option and difficulty screens, game over, end game, the road sprites |
| `scen` | Master Scenery (`sc1_`, 6 stages) |
| `scen1` | California Challenge (`rock_`, 7 stages) |
| `scen2` | European Challenge (`euro_`, 6 stages) |
| `scen3` | Northern Germany Challenge (`euro_` names again, 7 road files). Its title picture reads "2012 Janusz_Mombasajoe" and names Ostsee, Lüneburger Heide, Wesertal, Teutoburger Wald, Harz and A7. |
| `sfx` | samples and the music player `song` |

The catalogue files have the same records as the DOS `CARS.DAT` and `SCENES.DAT`: a count, then a path (`cars/p959`, `scen/sc1_`) and a display name per entry, big-endian.

**Northern Germany is built from the other sets.** Every sprite file in `scen3` is a byte copy of a Master, California or European file, under another name (for example its `euro_mercedes.shp` is the European `euro_thunderbird.shp`). Six of its seven road files are copies of stages of the other sets, for example `euro_roaddata4` is the Master `sc1_roaddata4`. New are `euro_roaddata1`, six of the seven sign files, the title picture `euro_icon` and its high scores. So Northern Germany can also be shown with the DOS art of the sets it borrows from, once each Amiga set is matched to its DOS set.

## 2. File formats found

- **Program files** (`tools/amiga/hunk.py`). `duel` is an AmigaDOS load file: 71 KB code, 31 KB data, and an overlay node of 21 KB code. It is compiled C (Lattice/SAS style: small data through A4, `link`/`unlk` frames), with no symbols. `sfx/song` is a separate load file with its symbols: the music and effect player (`_PlaySong`, `_PlaySfx`, `_StopSong`, `_FadeSong`, `SongInt` and so on, 3 KB of code) and 21 KB of chip-memory data (the song and its instruments). `tools/amiga/disasm.py` disassembles with Capstone's 68000 mode at the addresses `hunk.load` gives.
- **Rpck packing** (`tools/amiga/rpck.py`). 177 files start with `Rpck`, the unpacked size and a run-length stream: a signed count byte, a run of `n + 1` copies for `n ≥ 0`, `-n` literal bytes otherwise. The loader is at `$1e5d0` in `duel`, the unpacker at `$1e518`. `tests/test_amiga_files.py` runs the game's own unpacker under Unicorn (as a 68000) on all 177 files and compares with the Python one: all match. Six streams write one byte past the stated size; the game's buffer takes it.
- **Pictures** (`tools/amiga/ilbm.py`). Full screens (title, options, difficulty, the dashboards, the rear views, the scenery title pictures, the gas stations) are IFF ILBM, 320 × 200, 5 bitplanes (32 colours), ByteRun1. The `.p` files are ILBM palettes alone. The `.sb` files are 640 × 200 in 4 colours. All decode and look right.
- **Sprite archives** (`.shp`, Rpck-packed; `tools/amiga/shp.py`). They are the DOS archive layout, big-endian: a long (`PPkc` or a size), an entry count, the 4-character names, the offsets, the data. The names follow the DOS names, so a DOS sprite can be matched to its Amiga sprite by archive and name.
  - Each sprite is a 20-byte header and its bitplanes, one after the other: width in bytes, height, hot spot x and y, screen position x and y, two bytes of planes set to one wherever the sprite is drawn, and up to six bytes that say which screen planes each stored plane goes to (a stored plane may go to several, `03` or `1f`). Colour 0 where no stored plane is set is transparent.
  - Checked: the dashboard's turbo gauge and fuel and oil gauges, drawn at their stated positions, equal the dashboard picture pixel for pixel (a test in `tests/test_amiga_files.py`). The roof, pillar, mirror, hood and steering wheel land where they belong.
  - Open: the race screen's palette. The cockpit sprites drawn with the dashboard picture's palette give some wrong colours (the steering wheel, the gear gate), so the race screen probably changes colours part way down. To be read from `duel`'s screen setup.
  - Not all names match. The DOS archives keep separate EGA masks (`fc0M` next to `fcr0`). The Amiga road archive also holds the police car, which DOS keeps apart. The Amiga dashboard has more instruments (`fuel`, `oilp`, `oilt`, `trb0`, `swhl`).
- **Road data.** The DOS stage `.DAT` holds what the Amiga version splits over `roaddata<n>`, `slicedata` and `vectorsigns<n>`. `tools/dos_unpack.py` unpacks DOS files in Python (Huffman and RLE passes, archive entries) for these comparisons.
  - **DOS.** The road is a byte per road unit from DGROUP 3B51h (stage file offset 6E7h). Bit 7 is a side flag, and the low 7 bits index the stage's 128 records of 4 bytes at 347Eh (file offset 14h): flags, curve, pitch, object. The curves in those records run 0, 1, 2, 4, 6, …, -1, -2, -4, ….
  - **Amiga.** `roaddata<n>` is a header of 125 words, then the road bytes up to an `FF`. The loader is `$165ec`: it copies header words into game variables (many times 10) and takes the road length as the byte count less 2Dh. The header also names scenery sprite files (`desertmountain.shp`). `slicedata` is the same file in every scenery, and its values are the DOS record curves times 8, so it is the Amiga record table.
  - **Pairing.** The Master stages pair by number: each Amiga road is a little longer than its DOS twin (1426 against 1342 units for stage 0, and so on for all six). The road bytes are mostly the same runs with other record numbers (DOS `3b` where the Amiga has `46`) and some local differences.
  - **Next.** Match the two record tables, translate the Amiga road bytes, and compare with the DOS stages. Then map the header words to the DOS stage fields (the ratings are there: Amiga 70, 110, 150 mph against DOS 80, 110, 150).
  - **Northern Germany's roads** are, in order: California 6, a new road, Europe 3, California 2, Master 4, Europe 5, Europe 1.
- **Decompiling.** `tools/amiga/ghidra.ps1` lays out `duel` with `hunk.py`, imports it into Ghidra as 68000 code with A4 = `$2957e` (Lattice small data), marks a function at every `link a5`, and writes all 451 functions to `runs/amiga-ghidra/duel.c`. Global variables come out as their absolute addresses.
- **Sound.** 
  - Five IFF 8SVX samples: `accolade`, `test_drive_ii`, `the_duel` (speech), `starter`, `gameover`.
  - Six raw samples with a small header: `Bump`, `crash`, `shortcrash`, `radar`, `siren`, `Squeal`.
  - Each car's `engine` and `turbo` files (Rpck-packed in some cars).
  - `song`: player code plus data, as above.

## 3. How the Amiga version fits the port

The port stays one game: the DOS game logic running the TD2EGA image. The Amiga version adds three things to it, each found and checked against the Amiga files and code:

1. **Amiga audio**, a second `AudioBackend` beside the PC speaker. The game's sound calls (effects, engine, music) become Amiga samples played on four Paula-like channels; the music player in `song` is translated to C from its 68000 code. The switch works like the graphics switch, on its own key and menu entry. This needs the sound events the backend design in [HANDOVER.md](HANDOVER.md) already notes as missing: which effect or song started.
2. **Amiga graphics**, a fourth `GfxBackend`: a 320 × 200, 32-colour frame. Screens come from the ILBM pictures, sprites from the `.shp` archives by the DOS names. Where the Amiga screens differ (the dashboard's extra instruments), the backend draws the Amiga version from the DOS game's state where that state exists.
3. **Courses.** A converter from Amiga road data to DOS stage files, checked by converting the three Amiga sets that have DOS twins and comparing with the DOS files. Then Northern Germany is converted the same way and played with the DOS game logic, in every graphics mode.

Everything is read from the user's files at run time and derived files go to the profile folder; nothing from the game is committed.

## 4. Order of work

1. **Formats.** Done: load files, Rpck, ILBM, the sprite archives and sprites. Next: the race screen's palette, the raw sample header, the engine samples.
2. **Courses.** Map `roaddata`, `slicedata` and `vectorsigns` to the DOS `.DAT` and `.SGN`, using the Master scenery's six stages against `TDS20`–`TDS25`. Then California and Europe against `CCC` and `EC_`, then Northern Germany. Match each Amiga sprite set to its DOS set.
3. **Amiga audio.** The `song` player in C, the samples, the effect mapping, the live switch.
4. **Amiga graphics.** The sprite decoder, the backend, the screens, the switch.
5. **Data manager.** Recognise an Amiga game folder or archive (it has `duel` and `cars.dat0`) as the source of the Amiga sound, graphics and Northern Germany.

## 5. Open questions

- Does the Amiga game logic differ from DOS in ways a player would notice (the extra dashboard instruments suggest fuel or oil pressure play a part)? To be read from `duel` when the dashboard is drawn.
- `scen3` has seven road files but its title picture names six stages. One of the seven may be unused; the stage count in its catalogue entry or in `duel` will say.
