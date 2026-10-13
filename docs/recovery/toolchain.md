# Phase 0 toolchain discovery and execution recipe

Verified 2026-10-13. Phase 0 and Phase 1 are now authorized, with TD2EGA first. This record covers analysis dependencies and compiler discovery. It does not claim that a game was executed, a Ghidra import succeeded, or recovered C compiled. The toolchain researcher ran only native tool help/version discovery; no original game was passed to any tool. Machine-readable versions, hashes and limits are in [toolchain-discovery.json](evidence/toolchain-discovery.json).

## Selected shortest path

Reuse the existing **Ghidra 12.1.3 PUBLIC** and **Temurin JDK 21.0.12.1+1** under `C:\Projects\Civ1RE\tools` as read-only application files. Keep every TestDrive2 project, log, settings directory, temporary file and cache under this repository's private `analysis` tree. Do not open another project's Ghidra database or edit shared launch configuration. The root agent explicitly accepted this reuse.

Use the root-owned isolated Python/Capstone tooling for bounded disassembly and a primary EXEPACK reconstruction, then compare against the acquired independent author-published native `exepack.exe`. Import only the independently validated derived EGA MZ image. Importing the packed original would mainly expose its unpacker rather than establish recovered game code.

No large download is needed. The installed Ghidra release archive would be 569,445,154 bytes if acquired again; it was not downloaded. The independent EXEPACK binary and source together total only 1,349,277 bytes and were downloaded with root coordination into `analysis/tools/exepack-1.4.0`.

## Verified installed tools

| Tool | Selected path and evidence | Readiness limit |
| --- | --- | --- |
| Ghidra | `C:\Projects\Civ1RE\tools\ghidra_12.1.3_PUBLIC`; local application properties identify version 12.1.3, build 2026-Aug-17, source revision `8b4c91d4d5bd1549622bfbade0df199585b98365`, minimum Java 21 | Headless launcher, native decompiler, Base.jar and x86 language files exist and selected hashes are recorded. This is not a full installed-tree authenticity audit or a completed TestDrive2 launch. |
| JDK | `C:\Projects\Civ1RE\tools\jdk-21.0.12.1+1`; `java -version` confirms Temurin 21.0.12.1+1-LTS, Windows x86_64 | Runtime launches. No Java source was compiled here. |
| MSVC | `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe` | `/Bv` reports compiler 19.44.35228 for x64 and its passes. It then reports D8003 because no source was supplied, as expected. This is availability/version evidence, not a successful compilation. |
| Windows SDK | `C:\Program Files (x86)\Windows Kits\10`, version 10.0.26100.0 | UCRT `stdio.h`, `libucrt.lib`, `Windows.h` and x64 `kernel32.lib` exist; the selected MSVC include tree contains `stdint.h`. |
| 7-Zip | `C:\Program Files\7-Zip\7z.exe`, version 25.01 | Available for bounded archive inspection; executable hash recorded. |

Visual Studio Professional 2026 also has MSVC 14.51.36231 installed, but the recipe pins the existing VS 2022 Build Tools toolset to avoid changing compiler selection implicitly. Java, Ghidra, MSVC, standalone ndisasm/rizin/radare2/objdump, and DOSBox-X were not found on the original PATH. No DOSBox-X executable was found in the bounded inspected roots `C:\Tools`, `C:\Program Files`, `C:\Program Files (x86)` and `C:\Projects\Civ1RE`; this is not an exhaustive whole-disk absence claim.

The root agent owns Python dependencies and installed Capstone/Unicorn separately. Record distribution, Python binding and native-library versions independently: root observed Capstone distribution 5.0.9 while `capstone.__version__` reports 5.0.7. Do not overwrite one with the other. Their full wheel locks remain in the root's dependency evidence.

## Independent EXEPACK comparison tool

Acquired from the [author's EXEPACK page](https://www.bamsoftware.com/software/exepack/):

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| [exepack.exe](https://www.bamsoftware.com/software/exepack/exepack.exe) | 1,299,501 | `95eb32789d47fb88f8bdc50b6f14c6a441915339a37ebb06a1c044e0288b62eb` |
| [exepack-1.4.0.tar.gz](https://www.bamsoftware.com/software/exepack/exepack-1.4.0.tar.gz) | 49,776 | `212f3ec55822dc67763ab79534e5c9cd5fc2cf127a557a983a6b95ae4ad89ecf` |

The source Cargo.toml declares 1.4.0 and COPYING declares CC0. The precompiled binary has no supported `--version` option; `--help` succeeds. Its exact binary hash, URL and acquisition date therefore pin it separately from the source package version; binary-to-source reproducible build equivalence has not been established. No Rust compiler was installed and the source was not built.

The inspected source CLI reads the input and creates the output file, so **always choose a separate output path**. Its documented comparison command is:

```powershell
& 'C:\Projects\TestDrive2\analysis\tools\exepack-1.4.0\exepack.exe' `
  -d '<private-packed-EGA-copy>' '<new-independent-derived-MZ>'
```

This command was not run by the toolchain researcher. Root owns EGA reconstruction and comparison. Compare decoded image bytes, entry/stack semantics and normalized relocation records independently; rebuilt MZ envelopes can differ without implying different game image bytes. Preserve all discrepancies and header transformations. Do not overwrite a prior output or original. Help/format acceptance is not proof of a correct unpacked image.

The source's annotated stub catalog covers 16-byte and 18-byte metadata variants; its 283-byte stub example has an explicit skip field. That supports compatibility investigation with the observed EGA layout, but does not identify an exact historical packer version without a byte comparison. The separate source project [unEXEPACK](https://github.com/w4kfu/unEXEPACK/tree/db26f9e2d23af37e6508436b62cb98cbbb86a275) was pinned by remote commit lookup only; it was not downloaded or built.

## Isolated Ghidra headless command

The selected installed `x86.ldefs` explicitly provides language `x86:LE:16:Real Mode` and compiler specification `default` (`x86-16.cspec`). The installed [headless manual](C:/Projects/Civ1RE/tools/ghidra_12.1.3_PUBLIC/support/analyzeHeadlessREADME.html) documents loader, processor, compiler, no-analysis, logs and CPU limits. Its [launch properties](C:/Projects/Civ1RE/tools/ghidra_12.1.3_PUBLIC/support/launch.properties) document settings/cache/temp overrides. Official release requirements are available in the pinned [Ghidra 12.1.3 getting-started guide](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/GhidraDocs/GettingStarted.md).

Run the following in a dedicated process after root has produced and admitted the derived MZ. Replace the placeholder with that exact path. All directories named below must exist first; root owns their creation. Setting `JAVA_TOOL_OPTIONS` also carries isolation properties into Java launcher helper processes. These variables are process-scoped; no global/user environment changes or shared tool edits are required.

```powershell
$env:JAVA_HOME = 'C:\Projects\Civ1RE\tools\jdk-21.0.12.1+1'
$env:JAVA_TOOL_OPTIONS = '-Duser.home=C:\Projects\TestDrive2\analysis\ghidra-user -Dapplication.settingsdir=C:\Projects\TestDrive2\analysis\ghidra-settings -Dapplication.cachedir=C:\Projects\TestDrive2\analysis\ghidra-cache -Dapplication.tempdir=C:\Projects\TestDrive2\analysis\ghidra-temp -Djava.io.tmpdir=C:\Projects\TestDrive2\analysis\ghidra-temp'
$env:GHIDRA_HEADLESS_MAXMEM = '2G'
$egaImportArgs = @(
  'C:\Projects\TestDrive2\analysis\ghidra-projects', 'TD2EGA',
  '-import', '<validated-derived-EGA-MZ>',
  '-loader', 'MzLoader',
  '-processor', 'x86:LE:16:Real Mode', '-cspec', 'default',
  '-noanalysis', '-max-cpu', '2',
  '-log', 'C:\Projects\TestDrive2\analysis\logs\ega-import.log',
  '-scriptlog', 'C:\Projects\TestDrive2\analysis\logs\ega-import-script.log'
)
& 'C:\Projects\Civ1RE\tools\ghidra_12.1.3_PUBLIC\support\analyzeHeadless.bat' @egaImportArgs
```

Initial import intentionally saves a **new TestDrive2 analysis database**. Do not pass `-readOnly` when the goal is to persist import results; that mode discards program changes. Do not use `-overwrite` or another project's project directory. Check the import/loader log and independently reconstruct the segment/relocation/entry map before enabling analysis. Subsequent analysis should use a bounded timeout and serialized access to this database; per-function exports need success/failure/timeouts recorded separately. Java scripts can drive headless analysis without adding PyGhidra dependencies.

This recipe is based on inspected local launcher/docs. Actual launcher behavior and successful EGA import remain to be checked by root. The MZ loader's automatic segment/register assumptions require manual review; tool import does not admit recovered C contracts.

## C17 compilation path

Use the installed VS 2022 environment script and selected toolset in the **same cmd process** as compilation. A `.bat` invoked from PowerShell does not propagate its environment back into the parent PowerShell session. The concrete compiler is the `cl.exe` path above. Its environment script is:

`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat`

Command shape for root's real recovered C slice, with source/output placeholders replaced:

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 10.0.26100.0 -vcvars_ver=14.44
cl.exe /nologo /TC /std:c17 /W4 /WX /c "<recovered-source.c>" /Fo"<private-output.obj>"
```

The two lines belong in one dedicated cmd process or task-local compile script. Root owns that build action. [Microsoft's C standard switch documentation](https://learn.microsoft.com/en-us/cpp/build/reference/std-specify-language-standard-version?view=msvc-170) confirms `/TC` and `/std:c17`; use fixed-width, explicitly defined arithmetic rather than optional language features whose availability differs across compilers. Compiler version, flags, exact source and output hashes must accompany each admitted compilation. This discovery did not create a synthetic smoke-test source or compile recovered code.

## Future DOSBox-X oracle pin

The future oracle specification uses [DOSBox-X 2026.10.01](https://github.com/joncampbell123/dosbox-x/releases/tag/dosbox-x-v2026.10.01), tag commit `b6abbd5980a885f5f310a4088c59a8688d1b116c`. The immutable [debugger documentation](https://raw.githubusercontent.com/joncampbell123/dosbox-x/b6abbd5980a885f5f310a4088c59a8688d1b116c/README.debugger) and [full reference configuration](https://raw.githubusercontent.com/joncampbell123/dosbox-x/b6abbd5980a885f5f310a4088c59a8688d1b116c/dosbox-x.reference.full.conf) were checked. The upstream Win64 portable ZIP is 44,575,207 bytes with published digest `3c50915e63aefe35777d65ebb4391a06b4a2c2342e4c75cbee6bbda4c6916e33`.

No emulator was downloaded or started. That digest identifies a release **archive**, not an installed executable. Exact executable hash, debugger availability, runtime configuration and fixture repeatability remain future lock/validation fields. DOSBox-X does not promise instruction cycle accuracy; pinning alone is not original hardware fidelity.

## Observed import command correction

The initial attempt used the loader display name and failed during command parsing. The actual successful Windows command uses `-loader MzLoader`; the log then confirms Old-style DOS Executable (MZ), `x86:LE:16:Real Mode` and `default`. Root saved the database and compared every loaded image byte/relocation independently; see [import validation](evidence/td2ega-ghidra-import.json). The Python Capstone wheel/distribution is 5.0.9 while its binding reports 5.0.7; both identities and the native API version are recorded in [dependency evidence](evidence/python-dependencies.json). Do not substitute the reported binding version for the pinned wheel hash.
