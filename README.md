# Test Drive II: The Duel for Windows

A native Windows version of Accolade and Distinctive Software's *Test Drive II: The Duel* (1989). It plays the original DOS game from your own copy of its files, in four graphics modes you can switch between at any moment, even in the middle of a race: **EGA**, **CGA**, **Hercules**, and **Amiga**. With the Amiga version's files it also plays the Amiga music and sound, and adds the Amiga-only **Northern Germany Challenge** scenery.

It is not an emulator. The game code is a C reimplementation of the original executable, built on [Kylofon's Test Drive II SDL3 port](https://github.com/kylofon/test-drive-2-sdl3). It comes as one portable `TD2.exe` of about 4 MB with no DLLs to install.

**The original game is not included.** You need your own copy of the DOS *Test Drive II*. Only the base game is required: two cars and the Master scenery. The expansions and the Amiga version are optional.

## Screenshots

Each scene is the same moment of the same run in every mode: the same keys pressed at the same game times, frozen at the same game time, in the same 960 × 720 window. The Amiga intro runs at the Amiga game's own pace, so its first two shots are taken a little later in the run.

### Intro: Accolade

| EGA | CGA |
|:---:|:---:|
| ![Accolade presents, EGA](docs/screenshots/accolade-ega.png) | ![Accolade presents, CGA](docs/screenshots/accolade-cga.png) |
| **Hercules** | **Amiga** |
| ![Accolade presents, Hercules](docs/screenshots/accolade-herc.png) | ![Accolade presents, Amiga](docs/screenshots/accolade-amiga.png) |

### Intro: the Ferrari F40

| EGA | CGA |
|:---:|:---:|
| ![The Ferrari F40 in the intro, EGA](docs/screenshots/ferrari-ega.png) | ![The Ferrari F40 in the intro, CGA](docs/screenshots/ferrari-cga.png) |
| **Hercules** | **Amiga** |
| ![The Ferrari F40 in the intro, Hercules](docs/screenshots/ferrari-herc.png) | ![The Ferrari F40 in the intro, Amiga](docs/screenshots/ferrari-amiga.png) |

### Main menu

| EGA | CGA |
|:---:|:---:|
| ![Main menu, EGA](docs/screenshots/menu-ega.png) | ![Main menu, CGA](docs/screenshots/menu-cga.png) |
| **Hercules** | **Amiga** |
| ![Main menu, Hercules](docs/screenshots/menu-herc.png) | ![Main menu, Amiga](docs/screenshots/menu-amiga.png) |

### In the race

| EGA | CGA |
|:---:|:---:|
| ![In the race, EGA](docs/screenshots/race-ega.png) | ![In the race, CGA](docs/screenshots/race-cga.png) |
| **Hercules** | **Amiga** |
| ![In the race, Hercules](docs/screenshots/race-herc.png) | ![In the race, Amiga](docs/screenshots/race-amiga.png) |

`python tools/screenshots.py` takes these shots again.

## Quick start

1. Download `TD2.exe` from the [latest release](https://github.com/Buyukcaglar/TD2/releases/latest).
2. Put it in a folder of its own that you can write to, such as one in Documents or on the Desktop. Do not use Program Files.
3. Double-click `TD2.exe`. On the first start it asks where your game is. Choose either:
   - the folder that holds the DOS game (`TD2EGA.EXE`, `CARS.DAT`, `SCENES.DAT` and the rest), or
   - an archive of it: zip, 7z, rar or lha. The app unpacks it once into its profile folder.

   You can also skip the question: put the game files in a folder named `Game` next to `TD2.exe`.
4. Play. **Ctrl+Shift+G** switches the graphics mode. A **right click** on the window, or **Ctrl+Shift+M**, opens the app's menu.

Optional extras:

- **Expansions** (The Supercars, The Muscle Cars, California Challenge, European Challenge): open the menu, choose **Game files…**, then **Add folder…** or **Add archive…**. The app offers a restart, and the new cars and sceneries are in the lists.
- **Amiga graphics and sound**: open the menu, choose **Sound → Amiga game files…**, and pick the Amiga version's folder or archive (for example a WHDLoad `.lha`). Amiga then joins the Ctrl+Shift+G cycle, and **Ctrl+Shift+S** switches between the PC speaker and the Amiga sound.
- **Northern Germany Challenge**: set the Amiga game files and add the DOS California and European Challenges. The scenery appears in the scenery list from the next start, in every graphics mode.

If Windows says "Windows protected your PC", click **More info**, then **Run anyway**. The exe is not code-signed.

### Keys

| Key | Action |
|---|---|
| Arrow keys or numeric keypad | Steer, accelerate and brake. Shifting works as in the original. |
| Esc | Leave the current race or menu |
| Ctrl+P / Ctrl+S / Ctrl+Q | Pause / sound on or off / music on or off (the original's keys) |
| Ctrl+K / Ctrl+J | Keyboard / joystick. A gamepad acts as the joystick: press Ctrl+J to calibrate it. |
| **Ctrl+Shift+G** | Next graphics mode: EGA → CGA → Hercules → Amiga |
| **Ctrl+Shift+S** | PC speaker or Amiga sound |
| **Ctrl+Shift+M** or right click | The app's menu (the game pauses while it is open) |
| Alt+Enter | Full screen |

### Where it keeps things

The app never writes to your game folder. Settings (`settings.ini`), high scores and your last car and scenery choice go to a `Profile` folder next to `TD2.exe`, so the whole folder can move to a USB stick. If that folder cannot be written, they go to `%APPDATA%\TestDrive2`.

## What this project adds

The [Kylofon port](https://github.com/kylofon/test-drive-2-sdl3) recreated the EGA version of the game in C on SDL3. It removed the copy protection and disk handling, added gamepad support, and paced the screen effects to the game's timer. This project builds on it as follows.

### Graphics

- **CGA.** The graphics of `TD2CGA.EXE`: four colours (cyan, red and white on black), with the original's dither patterns and its CGA sprite files. Its graphics routines were transcribed one by one and checked against the original code.
- **Hercules.** The original launcher's Hercules option: the CGA game shown on a 640 × 348 monochrome screen, in a white, green or amber monitor colour of your choice.
- **Amiga.** The screens of the Amiga version, drawn from the Amiga game's own files in 32 colours:
  - the intro: "Accolade presents", the title, the DSI logo and the credits, and the showroom with your chosen cars;
  - the menus, car choice, scenery choice, high scores, results pages, gas station, game over and name entry;
  - the race, with the Amiga cockpit and gauges, the Amiga road colours, roadside posts, mountains and drifting clouds, the Amiga sprites, and the cracked windscreen after a crash;
  - the Amiga game's wipes, dissolves and fades;
  - the Amiga's Topaz font.

  Without the Amiga files this mode shows the EGA pictures.
- **Live switching.** Ctrl+Shift+G changes the mode at any time. A race goes on without a break; a menu, results page or other screen draws itself again in the new mode. The mode you pick is used again at the next start.
- **Clean scaling.** The picture keeps the 4:3 shape of the original monitor at any window size, and pixel-art sampling keeps every row and column the same height. Window sizes run from 1× to 4×, plus full screen.

### Sound

- **A better PC speaker.** The speaker is modelled from the timer chip's square wave, band-limited, through a filter that imitates the speaker cone. This removes the harsh aliasing and the whine of the plain approach.
- **Amiga music and sound effects.** The Amiga game's music player was translated to C and checked against the original code, write for write to the sound chip. It plays through an emulation of Paula, the Amiga's sound chip, in stereo. In a race you hear the Amiga engine and turbo, gear changes, skids, bumps, crashes, the radar detector and the police siren with its Doppler shift. The intro speaks "Accolade presents" and "Test Drive II".
- **Live switching.** Ctrl+Shift+S changes the sound at any time; a song goes on from where it was. The intro follows the timing of the sound you choose.

### Content

- **Northern Germany Challenge.** The Amiga version's seven-stage fan scenery from 2012, rebuilt as a DOS scenery from the Amiga files and the DOS California and European Challenges, with its own German signs, traffic and title picture. It plays in every graphics mode.
- **Only the base game is required.** The app checks for the base DOS game and says what is missing. It merges the car and scenery lists of every folder or archive you add.

### A Windows app

- **One portable exe.** SDL3, the archive libraries and the C runtime are linked statically, so `TD2.exe` needs only the DLLs that come with Windows.
- **Game archives.** The game, the expansions and the Amiga version can stay packed as zip, 7z, rar or lha. Amiga LhA archives work too, thanks to a small fix to libarchive.
- **App menu and windows in the system's look.** The context menu, the first-start setup, **Game files…** and **About** follow Windows' dark or light theme. Nothing of the app is drawn inside the game picture.
- **First-start setup.** The app asks for the game folder or archive, checks it and remembers it.

### Accuracy

- The 8086's 20-bit address wrap, a guard against a division crash, and bounds checks in the unpacker of the compressed executable.
- Two quirks of the original are reproduced exactly, because they change how it plays. A billboard can sometimes only bump the car instead of crashing it, because the original reads a value left over from earlier code. Releasing the button in neutral at high revs can grind the gears, for the same kind of reason.
- A **differential test harness** runs functions of the original executable under the Unicorn CPU emulator and the matching C functions on the same memory, and compares the results. 59 functions match, among them whole 10-second runs of the simulation from recorded races.
- **Snapshot tests** play the attract mode, the menus and a full race to the name entry on a virtual clock in EGA, CGA and Hercules, and compare every frame and the speaker's sound with saved hashes. The same runs check that live switches come back to the same frames, and that the Amiga mode without Amiga files draws exactly the EGA frames.

## Building from source

You need Windows, the Visual Studio 2022 Build Tools (MSVC 14.44, Windows SDK 10.0.26100, and the CMake and Ninja that come with them) and Python 3 for the tests.

1. Unpack the sources of these libraries (from their official releases):
   - SDL 3.4.18 into `analysis\external\sdl3-3.4.18\source`;
   - libarchive 3.8.1, zlib 1.3.1 and xz 5.8.1 into `analysis\external\archive-libs\libarchive-3.8.1`, `zlib-1.3.1` and `xz-5.8.1`.
2. Run `.\build.ps1`. It builds the libraries once, then `build\TD2.exe`.
3. Copy your DOS game into a folder named `reference\dos` and run `.\run.ps1`. It plays from a copy in `runs\game`.

`CLAUDE.md` lists the test commands. `docs/HANDOVER.md` describes the current state in detail, and `docs/native-windows.md`, `docs/cga.md` and `docs/amiga.md` describe each part.

## Credits

- **Upstream port:** [kylofon/test-drive-2-sdl3](https://github.com/kylofon/test-drive-2-sdl3) by **Krzysztof Kania** (Kylofon), MIT licence. This project starts from its v0.1.0 (commit `352b568`). The vendored copy, its licence and every local change are in [`port/td2/`](port/td2/PROVENANCE.md). If you enjoy it, consider [supporting the upstream author](https://buymeacoffee.com/krzysztofkania).
- **Topaz font:** the Amiga's Topaz is © Amiga Inc. The version used here is the raw A500 Topaz from the [amigafonts](https://github.com/rewtnull/amigafonts) collection by **dMG/t!s^dS!** (dMG of TrueSchool and Divine Stylers), who pixeled, vectorised and converted it. It is released under the GPL with the font exception, and is embedded in the exe for the Amiga mode's text.
- **Libraries:** [SDL 3](https://www.libsdl.org/) (zlib licence), [libarchive](https://www.libarchive.org/) (BSD licence), [zlib](https://zlib.net/) (zlib licence) and [xz / liblzma](https://tukaani.org/xz/) (0BSD).
- **Test tools:** [Unicorn](https://www.unicorn-engine.org/) and [Capstone](https://www.capstone-engine.org/) for the differential harness, and [Ghidra](https://ghidra-sre.org/) for analysis.
- **The game:** *Test Drive II: The Duel* © 1989 Accolade, developed by Distinctive Software Inc. Its files are not part of this repository or of the releases.

## Licence

The port's code is under the MIT licence; see [`port/td2/LICENSE`](port/td2/LICENSE). The Topaz font data in `port/td2/td2port/src/platform/topaz.c` keeps its own licence, the GPL with the font exception. *Test Drive II*, its artwork, music and data belong to their owners and are not distributed here. The screenshots above show the original game's artwork, rendered by this program, to illustrate what it does.

## AI assistance

This project's code, tools, tests and documentation were written largely by AI coding assistants (Anthropic's Claude, through Claude Code), directed and play-tested by the maintainer. AI-written code can contain mistakes that look plausible. Testing here is extensive but not complete; please report anything that behaves differently from the original.

## No warranty, no liability

This software is provided "as is", without warranty of any kind, express or implied, including fitness for a particular purpose. The authors and contributors accept no liability for any damage, data loss or other harm that arises from using it. You are responsible for owning a legitimate copy of the original game and for complying with the laws that apply to you. This is an unofficial fan project. It is not affiliated with or endorsed by Accolade, Distinctive Software, Electronic Arts, Atari, Amiga Inc., Ferrari, Porsche or any other rights holder. All trademarks belong to their owners.
