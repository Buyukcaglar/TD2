# Test Drive II recovery progress

22 October 2026 Kylofon supplement: [P1-R04 is complete as a source-selection decision](kylofon-r04-reuse-decision.md). The [normative allowlist](evidence/kylofon-reuse-decisions-v2.json) selects 10 groups: six value groups covering 11 already-recovered entries and four support groups; the [origin manifest](evidence/kylofon-reuse-origin-manifest-v2.json) retains provenance and license conditions. Existing [P1-R02/R03 evidence](kylofon-r02-r03-results.md) remains 2,233 admitted original-body vectors and 380 separate support checks, with four live-SS aliases excluded. No extraction/integration, new recovered entry, runtime execution or phase gate is added. Accepted native/function/resource totals and the unfinished early-exit registration below remain unchanged; P1-05 is still the frontier. Originals and the reference clone remain unchanged. The [current estimate](../planning/kylofon-effort-review.md) is 203–461 engineer-days, approximately 41–93 engineer-weeks before reserve. Read the [continuation record](../planning/continuation.md) before recovery work.

Checkpoint: 18 October 2026. **Phase 0 is complete. Phase 1 is in progress, with TD2EGA first.** This is development progress, superseding the earlier planning-only status for those two phases.

## Completed at this checkpoint

- Original custody verified for all 250 files; metadata baseline and 249 verified DOS working copies persisted.
- Local source control initialized with originals, binary payloads, analysis databases, tools/downloads and captures excluded.
- Toolchain, address/evidence conventions, five validated schemas and a pinned future execution-oracle specification established.
- TD2EGA recovered as a 130,240-byte load image; 1,652 relocations and original entry/stack validated by independent methods, including the original loader at two load segments.
- Ghidra real-mode project saved; all imported image bytes and relocations independently checked. Automatic function/decompiler outputs remain hypotheses.
- Startup/main candidates and the principal data/stack group mapped statically.
- P1-03 startup ABI reviewed; 17 bounded DS/SS ranges saved and read back in a separate Ghidra project. Near-data pointers, pushed-CS far frames, RETF 2 cleanup and saved far-return JMP are retained.
- Sixty isolated reader cases confirm the anomalous physical `086C` read. Timer semantics and the historical cause remain unresolved.
- Current control inventory: 440 function candidates, 44 explicit indirect sites plus one reconstructed saved-near RET mechanism and 28 open target-bound/writer obligations. Discovery does not establish their semantic contracts.
- Resource registry: 249 DOS file identities and 56 embedded candidate byte-source/caption/sequence/lookup/input/mask/control spans, with consumer candidates and unresolved format/lifetime gates retained.
- 215 native C17 exports covering292 original entries compiled and compared with original instructions: byte-ring, basename, query, allocation/discard, both paragraph moves, compaction/acquisition, both release policies and a bounded prefix byte-producing stage. The 164 comparison suites contain7,132,350 vectors; shared caller ownership and core integration remain open.
- Twelve initial-image tail cases verify physical `0086` writes in CLC state;2,048 later cases distinguish that path from the mutator-installed RETF state. Sixteen packed-loader ABI cases use mocked callees and do not establish codec execution.
- Forty-eight later packed-loader composition cases execute actual cache/allocation/copy/codec instructions with synthetic file services. They remain separate from supplied-resource decoding and real I/O.
- Main's fourteen control regions and sixty cache call sites have static reviews; full caller/state-machine validation remains open.

- Main-called startup mutator:1,920 synthetic equipment-query cases; retry composition224 cases; four state-specific control ledgers and six additional saved DS ranges. These do not establish whole-program transition coverage.

## Read and reproduce

| Document | Purpose |
| --- | --- |
| [Preparation/loop caller composition](td2ega-prepare-loop-composition.md) | Actual root/preparer/byte-source/DS reader and bounded state/platform composition |
| [Report parent and keyboard cleanup](td2ega-runtime-report-bus.md) | Late SS forwarding, ordered cleanup and explicit formatter boundary |
| [Runtime dispatch and prepared termination](td2ega-runtime-dispatch-bus.md) | CurrentCS/DS/SS metadata, retired handlers and exact argument cleanup |
| [Complete initialization with actual SS](td2ega-session-init-bus.md) | Ordered prefix writes, live call frames, conditional ring aliases and raw stream |
| [Native timer registration tail](td2ega-timer-startup-tail-bus.md) | Actual601C/614C bodies and caller frames; earlier3F40 remains open |
| [Callback metadata with actual SS](td2ega-timer-callback-bus.md) | Live arguments, ordered publication, matched removal and fatal prefix |
| [Timer startup and cleanup with actual SS](td2ega-timer-control-bus.md) | Live arguments, postIDIV flag validity and exact vector guards |
| [Published caller through whole403B](td2ega-timer-full-state-tick.md) | Full prior corpus under actual6269-first caller; lifetime remains open |
| [Handler with partially exposed child FLAGS](td2ega-timer-handler-bus-flags.md) | Partial child prefix masks and source flag-regaining |
| [Effect callback with actual SS](td2ega-effect-tick-bus.md) | Literal command words, raw lookup envelope and actual far returns |
| [Handler and old-vector bridge with actual SS](td2ega-timer-handler-bus.md) | Nine saved words, INT/IRET and far callbacks; body composition remains open |
| [403B with actual SS and callee bodies](td2ega-state-tick-bus.md) | Far-root and nonlocal-return conventions; handler lifetime remains open |
| [Whole420A with actual SS and FLAGS](td2ega-input-update-bus.md) | Actual caller frames, motion FLAGS and installed handler composition |
| [Input roots with actual SS and FLAGS frames](td2ega-input-poll-bus.md) | Actual installed handler/callees, modeled INT words and undefined-AF validity |
| [Key dispatcher with actual SS and callback return control](td2ega-key-dispatch-bus.md) | Argument/guard/table aliases and a retired-child interface |
| [Gameport with actual SS and ordered port state](td2ega-gameport-bus.md) | Caller-clean far roots, calibration, saved-BP aliases and serialized IN bound |
| [Installed keyboard handler with actual SS](td2ega-keyboard-bios-bus.md) | Pending/saved-word aliases and IRET versus RETF 2 |
| [Motion FLAGS before conditional clamps](td2ega-motion-flags-bus.md) | Full FLAGS operands and actual SS multiply return |
| [Motion, multiplication and scanner with actual SS](td2ega-motion-scan-bus.md) | Plain RETF, RETF 8 and ES scanner/caller flags |
| [Input fields with actual SS returns](td2ega-input-fields-bus.md) | Four additional interfaces, overlapping target views and broad BH lookup |
| [Whole source and callback controller](td2ega-sim-controller.md) | Actual4674/25-body composition; valid indirect domain remains open |
| [Sample and limit fields with actual SS returns](td2ega-sample-fields-bus.md) | Additional412C/4639 bus interfaces and two overlapping raw views |
| [Indirect targets with independent DS and SS](td2ega-sim-dispatch-bus.md) | Eleven additional bus interfaces; conditional stable-ring termination proof |
| [Indexed width lookup and post-child state](td2ega-indexed-sample.md) | Actual4C85, AH remainder and cached BP decision |
| [Threshold-window writes and a conditional near call](td2ega-window-controllers.md) | Actual4AFA/4B5D, signed CL and extra SS frame |
| [Signed thresholds and interpolated transitions](td2ega-threshold-transition.md) | Actual4B9A, IDIV prefixes and BP changes |
| [Conditional byte-source guards](td2ega-sample-guards.md) | Actual49E7/4A19/4D26, ZF and conditional consumption |
| [Byte-source caller and state adjustments](td2ega-sample-adjust.md) | Actual4A2E, IF1 and conditional control-table writers |
| [Current-view fill paths](td2ega-view-fill.md) | Actual843E, DF and three arithmetic/color paths |
| [In-place shift and optional strip](td2ega-plane-shift-strip.md) | ActualAE62, byte MULs and full zero-width LOOP |
| [Nibble-selected plane byte gather](td2ega-plane-gather.md) | ActualAC40, live SS locals and raw COPY |
| [Three live point updates](td2ega-point-sequence.md) | Actual3A91/3AB8/BA3C and live input ordering |
| [Cached old and new point calls](td2ega-point-update.md) | Actual3AB8/BA3C, cache ordering and near-return flags |
| [Current-stream byte reader](td2ega-stream-next-byte.md) | Actual18B0/0B42, DEC sign guard and pushed-CS callers |
| [Stream fill and first-byte read](td2ega-stream-pull-byte.md) | Actual0B42 allocator-reader and shared service limits |
| [Raw DOS read and text lookahead](td2ega-read-span.md) | Actual247C/094A and DS/SS lookahead context |
| [Plane-byte copy](td2ega-plane-byte-copy.md) | ActualC784 live SS locals and row arithmetic |
| [Alternative exit-video paths](td2ega-exit-video.md) | Actual5FBC/642E/840A and word-port traces |
| [Word-port and plane-byte point](td2ega-pixel-point.md) | ActualBA3C widths, live planes and SS aliases |
| [Actual discard callers](td2ega-discard-wrappers.md) | Actual0083/38D4 and retained argument frames |
| [Far-descriptor discard](td2ega-discard-object.md) | Actual782C/7490 full SS and control aliases |
| [Literal BIOS reset requests](td2ega-video-reset.md) | Actual642E/840A and returned-AL request context |
| [EGA video initializer](td2ega-video-init.md) | Actual90E8/840A and BIOS palette parameter interface |
| [EGA executable fallback](td2ega-fallback-mode.md) | Actual5F64/BIOS and raw port/word effects |
| [Plane fill trace](td2ega-plane-fill.md) | Actual840A/six ports/DF fill and SS qualification |
| [Dual name selection](td2ega-dual-name-select.md) | Actual0651/two queries/signed IMUL and BSS |
| [Record name selection](td2ega-record-name-select.md) | Actual0730/signed count/BSS and far frames |
| [Inherited write span](td2ega-write-span.md) | Actual2600/stack carry/nonlocal far exit |
| [Stream byte push](td2ega-stream-push-byte.md) | Actual21D6/cursor-count/backward byte/ordered aliases |
| [Stream buffer setup](td2ega-stream-buffer.md) | Actual0BE8/AX-only stream/signed metadata index |
| [Public heap wrapper](td2ega-heap-public.md) | Actual26A8/init ZF/current BP/plain far return |
| [Segmented heap walk](td2ega-heap-walk.md) | Actual26F1/raw headers/DS-ES/returned DF |
| [Block alignment/retry](td2ega-block-align.md) | Actual27D4/ESword/masks/required ZF |
| [Block metadata tail](td2ega-block-tail.md) | Actual280E/required ZF/ordered metadata |
| [Block wrapper and ZF](td2ega-block-wrapper.md) | Actual2830/DSswitch/required ZF |
| [Block request](td2ega-block-request.md) | Actual2852/28C0/SSframe/DOS48-4A |
| [Block adjustment](td2ega-block-adjust.md) | Actual28C0/inherited BP/DOS4A/raw metadata |
| [Field text](td2ega-field-text.md) | Actual0432:0006/copy/trim/forward spaces |
| [Record projection](td2ega-record-projection.md) | Actual0201/do-once records/partial outputs |
| [Mode controller](td2ega-mode-controller.md) | Actual53A6/nonlocal parent return/raw near tables |
| [Raw number field](td2ega-number-field.md) | Actual20F0/SSlocal/wordwrap/rawcursor |
| [Record dispatch](td2ega-record-dispatch.md) | Actual56ED/raw near dispatch/literal two-word unwind |
| [Secondary fields](td2ega-secondary-fields.md) | Actual50A1, dynamicDIV and ordered partial-word commits |
| [Control compositions](td2ega-control-controllers.md) | Actual5A6F/44EA with full SS children and tail jumps |
| [Control bus interface](td2ega-control-bus.md) | Five control entries, literalSS/CF and bounded324A table |
| [Seek composition](td2ega-seek-parent.md) | Actual2AD8 with three far225E calls and full SS |
| [Handle seek](td2ega-seek-handle.md) | Actual225E query/end/restore/final DOS42 paths |
| [Handle close](td2ega-close-handle.md) | Actual223E/DOS3E/error mapper and full returned state |
| [Field controller](td2ega-field-controller.md) | Actual5880 with five arithmetic/table children |
| [Pair controller](td2ega-pair-controller.md) | Actual595F and5A25 with caller status-flags review |
| [Record controller](td2ega-record-controller.md) | Actual4D3F, mutable SS FLAGS and near children |
| [Record return flags](td2ega-record-flags.md) | Defined FLAGS mask, actual ZF consumers and raw PUSHF obligation |
| [Long arithmetic](td2ega-long-arithmetic.md) | Word-DIV quotient/remainder, actual multiplier and literal RETF8 |
| [Runtime wrappers](td2ega-runtime-wrappers.md) | Two guard/reset roots with actual child bodies and far frames |
| [First ring consumer](td2ega-ring-selection.md) | Complete019E0004, actual shared ring and SS frame aliases |
| [Member reordering](td2ega-member-reorder.md) | ActualC838/C701, segmented transpose, caller scratch and DF |
| [Record sequence](td2ega-record-sequence.md) | Actual5ADA with six near helper sites and complete SS frames |
| [Raw radix text](td2ega-radix-text.md) | Word/dword entries, raw radix and actual SS output aliases |
| [Raw record arithmetic](td2ega-record-math.md) | Five near kernels with signed borrow, explicit DS and ring updates |
| [Relative raw wait](td2ega-relative-wait.md) | Actual CLI/read/STI reader, SS target and two-word guards |
| [Far member address](td2ega-far-member.md) | Raw header/table arithmetic and normalized AX/DX/CF conventions |
| [Small algorithms](td2ega-small-algorithms.md) | Signed clamp/byte ratio/SS-counter label minimum pad |
| [Raw record helpers](td2ega-stream-records.md) | Signed-byte side setup, byte membership, inclusive pool scan |
| [Runtime exit request](td2ega-runtime-exit.md) | Actual helper/close chain through prepared DOS4C boundary |
| [Runtime vector cleanup](td2ega-runtime-vectors.md) | Actual saved-DS/LDS ordering and synthetic vector services |
| [Runtime diagnostic](td2ega-runtime-diagnostic.md) | Actual messages/callback frames/raw XOR guard AX |
| [Runtime messages](td2ega-runtime-message.md) | Actual lookup/output/RETF2, external bounded prefix/end marker open |
| [Runtime callback list](td2ega-finalizer-list.md) | Raw reverse walk, far operand/SS alias and six caller slices |
| [Delete file wrapper](td2ega-delete-file.md) | Synthetic DOS41 plus actual shared near-error mapper |
| [Small arithmetic](td2ega-small-arithmetic.md) | Record LOOPzero, signed/unsigned division and ordered pair writes |
| [Table/scalar selectors](td2ega-table-scalar.md) | Raw lookup/error bytes/signed fields and near/far frames |
| [String memory](td2ega-string-memory.md) | Raw copy/compare/casecompare/fill, incoming DF and stack aliases |
| [Near string scan](td2ega-scan-length.md) | Incoming DF, bounded REP and last-compare carry |
| [Bytecase/scalarstate](td2ega-scalar-state.md) | Rawbyte/word effects andISAwidth reconciliation |
| [Near-pointer shift assignment](td2ega-shift-assign.md) | ActualCL-byte child andcallee-cleanRETF4/SP+8/CF contract |
| [Input/counter wait roots](td2ega-wait-roots.md) | Fullfarframes, rawinputAX anddistincthigh/low comparisons |
| [Raw create/write wrappers](td2ega-raw-write.md) | Mutablelengths, stalehandleclose andexpliciterrorfarcall boundary |
| [Bound words andsnapshot](td2ega-config-fields.md) | OrderedSS/CS aliases, DFdistinction andrawfarreturns |
| [Actual configuration caller](td2ega-config-apply.md) | Orderedsourcepair, nestedfarframes andrawchildreturns |
| [Forward copy/CS writers](td2ega-copy-config.md) | Five/two/one-word interfaces andsharedCSplane/bounds publication |
| [Small DOS/BIOS wrappers](td2ega-small-platform.md) | Explicit returnedservice DS/BP/flags andrawAPI/frame boundaries |
| [Finite state/read/copy helpers](td2ega-small-state.md) | Literal086C, rawcounter, bytecounts, pairedstate andnear/farframe contracts |
| [AND/OR/XOR sprite families](td2ega-sprite-logic.md) | Two-word interfaces, raw logic/DF/count/tail and byte-device operands |
| [Actual fill/sprite chain](td2ega-fill-sprite-composition.md) | Four prepared sprite pools and actual rectangle/sprite children |
| [Sprite entries and copy kernels](td2ega-sprite-draw.md) | Two/four-word far-pointer ABIs, materialized SS frames and copy dispatch |
| [Six mask helpers](td2ega-mask-span.md) | Byte-overflow/count/DF distinctions and exact RAM/device operations |
| [Actual drawing caller chains](td2ega-drawing-composition.md) | Actual line/rectangle/edge/fill bodies with mutable far argument pools |
| [Rectangle code and mutable arguments](td2ega-rectangle-draw.md) | Clipped caller words, per-plane color-byte shifts and explicit synthetic device bus |
| [Line code and isolated device bus](td2ega-line-draw.md) | Complete line body, divide-fault prefixes and explicit synthetic port/device traces |
| [Prepared edge sequence](td2ega-edge-sequence.md) | Two or three prepared five-word far-call pools |
| [Actual plane rows](td2ega-plane-rows.md) | Caller composition preserves early discarded-return row continuations |
| [Plane RAM span](td2ega-plane-span.md) | SS mask read, ordered plane writes and explicit discarded-near-return jump |
| [Draw sequence orchestration](td2ega-draw-sequence.md) | Retained argument pools, raw loops and ordinary-leaf ABI boundaries |
| [Actual finish-loop chain](td2ega-finish-loop-composition.md) | Four actual near callees and nested lookup/RET6/limit bodies |
| [Limit stages](td2ega-view-limits.md) | Signed owners, wrapped adjustments and four actual near helper calls |
| [Record interpolation](td2ega-record-interpolate.md) | DS/SS record views, prepared triplets and actual self-modifying callee |
| [Line-step contract](td2ega-line-step.md) | Self-modifying INC/DEC, DF stores, count quirks and near RET6 |
| [Additional line mutation](td2ega-line-mutation.md) | Ordered INC/DEC code writes and near RET6; body recovery pending |
| [Projection and signed lookup](td2ega-projection.md) | Raw indexed math, signed division fault prefixes and external tables |
| [Near clamp helper](td2ega-near-clamp.md) | Signed clamp order, zero LOOP count and open actual-caller bounds |
| [Loop controls](td2ega-loop-controls.md) | Three root controls with distinct near/far frames, CS state and argument lifetimes |
| [Loop data preparation](td2ega-loop-prepare.md) | DS record filtering, arithmetic overflow and output/source aliases |
| [State/platform composition](td2ega-state-platform-composition.md) | Actual reviewed state handlers, waits and installed keyboard in one bounded comparison |
| [State messages](td2ega-state-messages.md) | Eleven message/helper contracts and near/far argument lifetimes |
| [Input bridge](td2ega-input-bridge.md) | Ordered far-pointer publication, BIOS polling/draining and installed-handler compositions |
| [State sequences](td2ega-state-sequences.md) | SS point sources, DS globals and actual platform-helper composition |
| [BIOS block](td2ega-bios-block.md) | Raw BIOS10AX1002 pointer interface and corrected resource labels |
| [Global deadline](td2ega-wait-latch.md) | Raw global deadline publication/wait and argument aliases |
| [Custody and baseline](custody-and-baseline.md) | Original identity, working-copy policy and Phase 0 gate |
| [Toolchain](toolchain.md) | Pinned versions/hashes and isolated commands |
| [Evidence conventions](evidence-conventions.md) | IDs, coordinates, confidence and separate gates |
| [Future execution oracle](oracle-spec.md) | Pinned DOSBox-X profile/fixtures; not installed or exercised |
| [EGA unpacking](td2ega-unpacking.md) | Transform, allocation, image and relocation proof |
| [Independent loader check](independent-unpack.md) | Original-stub execution stopping before application entry |
| [Startup analysis](td2ega-startup.md) | Entry, DS/SS, runtime scaffolding, main candidate and open anomalies |
| [Startup ABI review](td2ega-startup-abi.md) | Reviewed helper conventions, symbolic segment ownership, saved tool corrections and isolated address check |
| [First C helper](td2ega-byte-ring.md) | Exact contract, build, comparisons and limits |
| [Function registry](functions.json) | 440 registered candidates with separate semantic/build/differential gates |
| [Control-flow map](td2ega-control-flow.md) | Reviewed discovery/disposition map; 28 indirect bounds/writer obligations remain open |
| [Byte-ring callers](td2ega-byte-ring-callers.md) | Eight unique direct call sites, shared main/interrupt consumption and pending lifetime/reset ownership |
| [State and consumers](td2ega-state-and-consumers.md) | Dispatch writers, dynamic filenames, raw interfaces and low-memory tail anomaly |
| [Resource registry](resources.json) | Stable file/embedded IDs; format and per-file behavioral gates remain pending |
| [Resource cache](td2ega-resource-cache.md) | Descriptor ownership, moving operations and packed-loader stack convention |
| [Basename helper](td2ega-filename.md) | Bounded byte-scan C17 contract and comparison evidence |
| [Cache query](td2ega-cache-query.md) | Read-only name match, first-free abort and sentinel behavior |
| [Allocation prefix](td2ega-cache-allocate.md) | Metadata mutation, 16-bit arithmetic and partial failure state |
| [Discard prefix](td2ega-cache-discard.md) | Segment-only identity, free-row match and active-top trimming |
| [Moving cache](td2ega-moving-cache.md) | Word-copy direction, compaction/acquisition and distinct release/alias effects |
| [Main orchestration](td2ega-main-state.md) | Startup-through-exit paths, media retry difference, pool/platform and caller obligations |
| [Prefix byte stage](td2ega-prefix-stage.md) | Bounded code/bit/delta/count contract, extra65,536-byte edge and synthetic wrapper composition |
| [Run/block stage](td2ega-run-stage.md) | Bounded6B02/6B97/6C6E native contract and synthetic composition |
| [Mutable platform helper](td2ega-mutable-platform.md) | Loaded instruction boundaries, alias writes, query conditions and saved-near returns |
| [Timer callback metadata](td2ega-timer-callbacks.md) | Five-slot bounds, ordered publication/removal, interrupt-enable effects and fatal prefixes |
| [Raw loader](td2ega-raw-load.md) | Synthetic I/O ordering, partial error state, exact-block EOF and segment wrap |
| [File/header paragraphs](td2ega-file-paragraphs.md) | Ignored error flags, partial stack-header bytes and bounded size results |
| [Audio pointer/flag metadata](td2ega-audio-metadata.md) | Opaque source ownership, shared flags and IF effects without sequencer/audio acceptance |
| [Near simulation primitives](td2ega-sim-primitives.md) | Wrapped arithmetic, state fields, post-write aliases and conditional DS=SS |
| [Timer installation/cleanup](td2ega-timer-control.md) | Ordered port/vector effects, signed-division faults and callback list reset |
| [Ordinal search caller](td2ega-find-nth.md) | Signed ordinal, first-failure continuation and conditional stale-pointer writes |
| [DOS search/path state](td2ega-find-files.md) | Near path returns, global DTA/basename, bounded prefix and literal aliasing copies |
| [Pool setup/reset](td2ega-pool-setup.md) | Unchecked DOS resize chaining, retained descriptor state and remaining-word arithmetic |
| [Composed input update](td2ega-input-update.md) | Complete420A, thirteen actual callees, segment contrast and state/register ownership |
| [Signed-motion arithmetic](td2ega-signed-motion.md) | Explicit shifts/sign extension, wrapped damping, product/clamp order and callee-clean multiply |
| [Input-control state](td2ega-input-control.md) | BP effects, retained byte halves, post-write table aliases and arithmetic composition |
| [Near control operations](td2ega-control-ops.md) | Distinct ES scanner, conditional DF, subtraction/product composition and ordered state effects |
| [Input polling](td2ega-input-poll.md) | BIOS adapters, DS/SS consumption gate, direction masks and gameport repeat mapping |
| [Key dispatch](td2ega-key-dispatch.md) | Pushed-segment near-call far frame, argument/guard effects and explicit callback adapter |
| [Target/sample arithmetic](td2ega-sim-targets.md) | Signed smoothing/clamps, indexed post-write aliases and delta/countdown effects |
| [Gameport sampler](td2ega-gameport.md) | Polling, calibration signedness/overflow, timeout defaults and explicit port/IF effects |
| [Key callback bindings](td2ega-key-bindings.md) | Signed literal key domain, fixed extended-slot read and six constant installer calls |
| [Directory-list callers](td2ega-directory-batch.md) | Mutable selector argument, output/source aliases and required/optional composition |
| [Directory selector](td2ega-directory.md) | Optional/required lookup, selector publication, signed count and literal pointer arithmetic |
| [Packed loader](td2ega-packed-load.md) | Complete wrapper/helper composition, stack shift and count/far-pointer ABI |
| [Named raw loader](td2ega-named-raw.md) | Complete wrapper/helper composition, zero-segment branch and partial file/cache failures |
| [Session initialization](td2ega-session-init.md) | Four complete bounded entries, native helper composition and unchanged byte source |
| [Progress data](progress.json) | Task status, evidence, next work and remaining gates |

The [development roadmap](../planning/roadmap.md) and [backlog](../planning/backlog.json) retain the required phase order. Original media remains external. DOS audio is PC Speaker music/effects; Amiga audio and Northern Germany Challenge remain later requirements.

## Next work

P1-03 and the P1-04 discovery/disposition milestone are complete with bounded evidence. Continue P1-05 with every caller's moving-storage lifetime/exclusion, packed-loader orders/allocation bounds and SI/DI liveness, dynamic/embedded consumers and complete startup-to-exit transitions. The current graph has440 registered candidates and44 explicit indirect sites plus one reconstructed saved-near RET mechanism, with28 open bounds/writer obligations; it is not complete code-contract coverage. Eight unique call sites establish FN-EGA-000003 return use, including conditional and rejection-loop consumption from simulation callbacks. Shared state lifetime and interrupt interleaving still gate core integration. The anomalous read is physical086C with no timer-frequency assignment; the initial CLC state-tail writes physical0086, while the verified mutator can install RETF and return the sign-extended state instead. A declared low word0 in7C16 writes65,536 extra bytes while returning the declared count; native caller allocation safety remains a required proof.

CGA recovery remains behind EGA portable code-contract closure. Full resource decoding, Windows-host gameplay and Amiga recovery have not started. No DOS game session, renderer, audio output, complete state-machine validation or gameplay/fidelity acceptance is established by this checkpoint. Isolated loader and function emulation are recorded separately from those gates.

[Music callback75EA](td2ega-music-tick.md):13,346 synthetic comparisons exercise
all185 instruction locations; source/voice aliases, counters and port requests
are code evidence. Supplied VOICES bounds, IRQ/timebase and audio output remain open.

[Effect callback6269](td2ega-effect-tick.md):14,562 synthetic comparisons exercise
all140 instruction locations; queued/loop/source/port effects remain separate
from actualIRQ/audio/resource-fed acceptance.

[Timer handler/old-vector bridge](td2ega-timer-handler.md):3,586 serialized
comparisons exercise71/71 instruction locations with explicitoldINT08 andfar
callbackABImocks; actualIRQ/callbackbody/lifetime acceptance remainsopen.

[Six installedkeycallbacks](td2ega-key-actions.md):12,288 comparisons exercise
71/71 instruction locations withUIABImocks; exactguard/mode/returnedDS effects
areseparatefrom actualUI/IRQ/resource/fullstate acceptance.

[Keyboardvectors/handlers](td2ega-keyboard.md):38,400 comparisons exercise155/155
instructionlocations. AH1forcesIF1 viaRETF2; olderinputpollIF-preservingprofile
requires explicitreturnedflag repairbefore installedhandlercomposition.

Installedkeyboard compositions:2,876 poll/consume and9,984420A-root cases
executeactual69B7 plusnativekeyboard C, closingboundedIF-propagation assumptions;
actualIRQ/callbackbodies/fullstate/resource/game gatesremainopen.

[Recordpreparation/byte-source caller1E59](td2ega-prepare-records.md):6,240
comparisons include648DIVprefixes andexplicitSS/DS views; sampleconsumption
closure isbounded, withno actualreset/RNGmeaning/core/resource/IRQ acceptance.

[Stateorchestration1B2C](td2ega-state-loop.md):3,012 comparisons preserveknown
dispatch/farABI/reset/tail effects;120cases executeactualrecordcaller. Most
callees remainABImocks; fullstate/resource/IRQ/core/fidelity gatesremainopen.

[Ownedcounter/waitcontrol](td2ega-wait-control.md):2,912comparisons exercise
43/43locations; IF1 andmod32deadline/absolutecomparison/wrap retained.
Unitlesssyntheticcounterstreams aredistinctfromphysical086C andactualIRQ/timing.
