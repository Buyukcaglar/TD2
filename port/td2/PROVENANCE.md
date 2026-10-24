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

Git history in this repository records each later change.

The original game and its data are (c) 1987 Accolade / Distinctive Software Inc. and are not part of this code.
