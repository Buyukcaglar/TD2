# Project risks decisions and effort

The order and final features are requirements; the implementation choices below are proposed baselines. No unresolved item requires a permission question during this planning task. Resolve each at its stated development gate using evidence, then obtain a product preference only where alternatives change the requested behavior.

## Decisions and open questions

| ID | Current position | Resolution point |
| --- | --- | --- |
| D01 | EGA is the primary DOS source; CGA follows | Confirm edition hashes before recovery |
| D02 | Portable C17 core, thin Windows host, proposed SDL3/CMake | Pin compilers/dependencies at bootstrap; keep core host independent |
| D03 | No original resources in the distributable, including EXE-embedded media | Classify code constants versus resources in phase 2 and audit packaging in phases 3/5 |
| D04 | User supplied originals remain external/read only | Design loader/cache/profile paths before native integration |
| D05 | DOS EGA gameplay remains canonical during media switches | Compare Amiga differences in phase 4; retain documented distinctions |
| D06 | Extra scenery is Northern Germany Challenge, confirmed by user | Verify candidate `scen3` member association and completeness in phase 4 |
| D07 | Northern Germany Challenge is required when necessary files validate | Implement route/content import and full acceptance in phase 5 |
| D08 | DOS audio is PC Speaker music/effects; Amiga music/sound effects remain in scope | User-confirmed audio scope; recover and validate those providers |
| Q02 | Which exact DOS and Amiga editions/patches are supplied? | Baseline hashes, loader/patch mapping and optional original-media comparisons |
| Q03 | Are all original Amiga disks needed for historical fidelity available? | Analyze supplied tree first; ask for specific missing owned files only when essential |
| Q04 | Which graphics/audio combinations are complete per car/scenery? | Semantic coverage matrix in phases 4/5; no invented replacements |
| Q05 | What are the exact scheduling, audio and display timebases? | Code recovery and controlled original comparisons |
| Q06 | Can cross-platform music phase map continuously? | Recover both sequencers, define cue/loop mapping, test transitions before final acceptance |
| Q07 | Which Windows baselines and optional input devices matter? | Select during native host work; Windows x64 is the current proposed first target |
| Q08 | Can newer third-party patch source be used, and which behavior does it change? | Member/license/byte review before reuse; keep enhanced behavior out of original baseline |
| Q09 | Do extra-scenery assets have faithful DOS counterparts? | Provider coverage review; retain explicit unavailability if no evidence-backed mapping exists |

## Risk register

| Risk | Evidence or reason | Mitigation and completion impact |
| --- | --- | --- |
| Packed code analyzed as game code | Common EXEPACK-family stub and inner relocations | Validate derived image independently before function recovery |
| Misloaded segmented addresses | Near/far aliasing, relocations and loader heuristics | Preserve address provenance and verify DS/ES/SS per function |
| False code/data boundaries | Compressed/embedded data and indirect dispatch | Reachability-led analysis plus consumer references; unknown paths stay open |
| C changes arithmetic | 16 bit wrap, signedness and host width/UB differences | Instruction-derived contracts and boundary differential vectors |
| Premature phase completion | Resource semantics depend on recovered consumers | Phase 1 code contracts precede phase 2 full schemas; integrated behavior closes later |
| One decoder per extension assumed | PCS prefixes differ; `.pal` may be ILBM; `song` may be code | Consumer-led format dispatch and full-corpus disposition |
| Original media leaks into executable | Art/text/audio/data embedded in original EXEs | External extraction/loaders plus binary/archive audits |
| Patched Amiga becomes original oracle | Supplied HD patch; modern WHDLoad changes render/simulation | Version/patch map and separate edition labels |
| Extra scenery merges with Europe | Reused `euro_` names and identical catalog | Namespaced content IDs and semantic route identity |
| Extra scenery treated as artwork only | Route geometry/events affect gameplay | Dedicated content normalization and complete-session acceptance |
| Missing cross-profile object/media | Platform content may differ | Coverage matrix, complete-provider preflight and explicit unavailable combinations |
| Switching corrupts state | Caches, animation metrics and audio ownership differ | Atomic commit with canonical-state invariants and failure rollback |
| Emulator evidence overstates fidelity | Timing approximations and patch handling | Repeatability checks and separate physical-timing escalation where needed |
| Large combinatorial verification cost | Twelve cars, multiple routes/modes/providers | Full per-content coverage, targeted interactions and expanded combinations on evidence of divergence |
| Unbounded resource inputs | Nested packs and optional archives | Length/allocation/path validation with synthetic malformed fixtures |
| Source reuse provenance uncertain | New patch members have mixed/unclear license notices | Review exact versions before reuse; use references as evidence without copying until resolved |

## Effort assumptions

These are engineering planning estimates, not measurements from a completed prototype or promises of calendar dates. They assume one experienced full-time reverse engineer/developer, approximately 40 hours per engineer-week, supplied usable media, no large unknown protection system beyond the observed loaders, and meaningful fidelity validation. User review, hardware access and missing input waits are separate elapsed time.

| Phase | Initial effort range in engineer-weeks | Main uncertainty |
| --- | ---: | --- |
| Custody/tool/evidence bootstrap | 0.5 to 1.5 | Existing tool availability and edition decisions |
| EGA portable C recovery then CGA comparison | 12 to 28 | Unpacked code complexity, indirect paths, arithmetic/scheduling and behavior evidence |
| Complete DOS resource recovery | 6 to 14 | Compression layers, embedded data, audio and exceptional resource variants |
| Native Windows DOS release | 8 to 16 | Integration, input/scheduling, audio, full-content runtime/fidelity validation |
| Amiga code/resource/content recovery | 10 to 24 | Patch provenance, custom packs, music code and scenery mapping |
| Media switching and extra scenery completion | 6 to 14 | Cross-profile coverage, audio transitions, route normalization and final validation |
| **Strict-order total before contingency** | **About 43 to 98** | Ranges sum; not a probabilistic forecast |

Reserve roughly 25 to 40 percent additional effort for discoveries, fidelity defects and rework; this yields a deliberately broad envelope around 55 to 140 engineer-weeks. Small independent recovery/format tasks can reduce elapsed time with multiple workers, but core model ownership, phase gates and integration are serial constraints. Do not divide the total mechanically by headcount.

The new Amiga patch source could substantially reduce address/contract discovery effort, but it is modified assembly rather than recovered original portable C. Its licensing, byte identity and behavior changes must be understood before estimating the benefit. A successful unpack command or decoded image is not grounds to shrink the full validation estimate by itself.

## Re-estimation checkpoints

1. After validated EGA unpacking and a representative code map: replace assumed code complexity with actual function/dispatch/segment counts.
2. After recovering one meaningful simulation slice and EGA/CGA comparison: measure function-recovery rate and differential-debugging cost.
3. After decoding one representative member of every actual format family: count unique codec/schema paths and exceptional cases.
4. After native first complete session: assess integration defects and full-corpus/fidelity review workload.
5. After Amiga patch/media and Northern Germany Challenge mapping: revise normalization and switching coverage effort.

Report remaining tasks and actual acceptance evidence at each checkpoint. Do not turn broad estimates into completion dates before these discoveries.
