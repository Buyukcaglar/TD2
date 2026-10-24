# Kylofon address and symbol admission

Date:22 October2026. Pinned upstream commit `352b56824d8c91e938b8f0794a71afca9a276193`. This is bounded static reconciliation against the independently validated EGA image, not source-semantic or gameplay acceptance.

[Machine evidence](evidence/kylofon-address-admission-v1.json) contains input/maker hashes, all 50 unmatched-start dispositions, all 76 naming conflicts with original syntactic xrefs, all 460 function-symbol/source mappings, the complete 495-address union of local entries/upstream index starts/function symbols, complete C-definition comment claims and boundary/range qualifications. No original, clone file, accepted source, registry or old receipt was changed.

## Results

417 exact starts;27 upstream-only and23 local-only starts individually reconciled. All76 naming conflicts are keyed to stable localFN or neutral currentDS raw-view identities, with every upstream alias retained. 524 C definitions were parsed; 323 of460 function symbols bind by name to actual C definitions. Names and span hashes do not prove semantics.

The two most consequential upstream-index errors are06C9:AF54, which is a screen descriptor rather than an admitted code root, and06C9:1A37, an operand byte inside CALL1A33. The purported AF54→C030 call is not source of reachability proof: C030 is an interior shared graphics instruction. Real x86 alternate entries are possible, so rejection is scoped to these unmutated index claims; any independent alternate-entry witness would require new analysis.

Most other upstream-only starts are coherent uncalled library entries with distinct prologues, sometimes sharing tails with known routines. They are retained as candidates without assigning new accepted functionIDs. Their existence is useful discovery and does not establish a supported caller or complete contract. All13 local-only object callbacks4929..4A19 have explicit upstream C/symbol counterparts. Interrupt/callback roots and shared graphics entry splits explain the other local index omissions; the installed-handler raw contracts remain ours.

## All unmatched starts

| Direction | Address | Stable local identity | Disposition |
| --- | --- | --- | --- |
| Upstream only | `06C9:1A37` | retained candidate | operand_byte_not_admitted_entry: The byte at1A37 is the last segment byte of the five-byte far CALL beginning1A33. No selected direct-flow entry targets it. Upstream8F12's broad computed drawing traversal is not entry proof; retain only as a rejected index start pending any independent alternate-entry witness. |
| Upstream only | `06C9:5D9E` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:607A` | retained candidate | orphan_entry_with_shared_timer_tail: Independent prologue607A computes1:0 IDIV[BP+6], publishes countdown metadata and enters6099 timer-install tail also reached by6059's JMP6077. The selected graph has no607A root. Preserve the candidate and no-callers qualification; no new stableFN assigned. |
| Upstream only | `06C9:69F2` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:6F93` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:74D4` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:7501` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:75D9` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:799C` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:79D2` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:7A93` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:7D9C` | retained candidate | orphan_shared_blitter_prefix: Distinct prologue/configuration prefix7D9C..7DBB JMP91C1 selects AND/clipped raw tables. Local7D7C/7DBC and other blitters share later bodies; absence of this root is not absent library code or accepted caller reachability. |
| Upstream only | `06C9:A547` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:AC1C` | retained candidate | orphan_shared_grab_prefix: PrefixAC1C..AC3E subtracts member origin from supplied coordinates then JMPAC82, shared with admittedAC40. It is a separate uncalled entry candidate; AC40 evidence does not admit its different prefix. |
| Upstream only | `06C9:AC64` | retained candidate | orphan_shared_grab_prefix: PrefixAC64..AC81 reads stored member coordinates, masks x withFFF8 and falls intoAC82. Existing plane-gather context confirms13 prefix sites but leaves this entry open. Keep separate fromAC40's admitted76-site body. |
| Upstream only | `06C9:AF54` | retained candidate | data_misindexed_as_code: CS:AF54 is a26-byte screen descriptor, passed to7D5E by accepted5C98; upstream symbols marks it global gfx_screen_desc. Linear disassembly of descriptor bytes must not create a callable root or infer a real CALL toC030. |
| Upstream only | `06C9:BAE8` | retained candidate | orphan_shared_blitter_prefix: Distinct prologue/configuration prefixBAE8..BB07 JMP91C1 selects XOR/clipped raw tables. Adjacent admittedBAC8/BB08 prefixes and shared graphics paths do not establish a caller toBAE8. |
| Upstream only | `06C9:C030` | retained candidate | interior_shared_graphics_instruction: C030 is CMPBX,[BP-3C] inside the row loop reached linearly fromBFCF, with backward branchBFD2. Existing graphic ranges include it but no selected root/call does. Its upstream-only callerAF54 is data; reject new standalone entry inference. |
| Upstream only | `06C9:C65C` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:C6F0` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `06C9:C760` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `13A8:03EC` | retained candidate | orphan_near_runtime_helper: Twelve-byte near helper savesDS/ES, reads physical0012 throughDS0 and RETs. It lies after03D3's ordinary RET03EB; upstream's03D3 broad linear index lists it, but selected direct-flow has no caller. Keep code-candidate semantics and historical reachability separate. |
| Upstream only | `13A8:2CB4` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `13A8:2DA7` | retained candidate | orphan_nonstandard_runtime_entry: Prologue rewrites four stack words, adjustsBP and transfers through runtime dispatch path. It is not a normal epilogue-only function. No selected direct-flow caller or localFN exists; preserve candidate with exact stack effects pending full contract. |
| Upstream only | `16EB:008E` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `16EB:00D0` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Upstream only | `1748:016A` | retained candidate | orphan_library_code_candidate: A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted. |
| Local only | `06C9:4929` | `FN-EGA-000426` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:4947` | `FN-EGA-000427` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:494D` | `FN-EGA-000428` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:495D` | `FN-EGA-000429` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:499A` | `FN-EGA-000430` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:49C9` | `FN-EGA-000431` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:49CF` | `FN-EGA-000432` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:49D5` | `FN-EGA-000433` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:49DB` | `FN-EGA-000434` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:49E1` | `FN-EGA-000435` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:49E7` | `FN-EGA-000436` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:4A18` | `FN-EGA-000437` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:4A19` | `FN-EGA-000438` | indirect_object_entry_omitted_from_index: A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains. |
| Local only | `06C9:61BF` | `FN-EGA-000360` | installed_interrupt_root_omitted_from_index: Timer ISR has explicit upstream timer_isr C body while indexed function starts omit installed vector roots. OurFN360 keeps actual SS save/INT/IRET and alias/FLAGS evidence; upstream native body deliberately drops hardware frame details. |
| Local only | `06C9:6230` | `FN-EGA-000361` | interrupt_chain_shared_tail_omitted_from_index: LocalFN361 is saved-vector/BIOS-chain tail; upstream symbol timer_bios_chain exists but hardware chaining is replaced in host timer handling. Do not infer complete original body from the host timer ISR. |
| Local only | `06C9:6269` | `FN-EGA-000403` | published_callback_root_omitted_from_index: Effect callback sfx_tick is implemented explicitly in sound.c and invoked by native callback mapping; old index misses the callback root. Retain localFN403 and raw effect command/SS/port scopes. |
| Local only | `06C9:69B7` | `FN-EGA-000160` | installed_interrupt_root_omitted_from_index: Installed INT16 handler appears as kbd_int16_isr symbol and host keyboard behavior, not a standalone original ISR C implementation. LocalFN160 retains actual frames and AH branch coverage. |
| Local only | `06C9:8336` | `FN-EGA-000213` | shared_graphics_entry_split: Local mask/plane entry8336 is inside upstream82D0 range; upstream rect_set_plane implementation abstracts its screen/RAM paths. Exact instruction boundary is retained under localFN213. |
| Local only | `06C9:839C` | `FN-EGA-000214` | shared_graphics_entry_split: Local XOR plane entry839C has upstream rect_xor_plane symbol/implementation but is absent from index starts. Preserve localFN214 and raw alternate paths. |
| Local only | `06C9:AD8B` | `FN-EGA-000239` | shared_graphics_entry_split: LocalEGA plane-mask entryAD8B is represented by upstream rect_set_plane_ega family rather than a separately indexed root. KeepFN239's actual bus contract. |
| Local only | `06C9:ADF4` | `FN-EGA-000240` | shared_graphics_entry_split: LocalEGA XOR-mask entryADF4 is represented by upstream rect_xor_plane_ega family rather than a separately indexed root. KeepFN240's actual bus contract. |
| Local only | `13A8:049B` | `FN-EGA-000439` | installed_interrupt_root_inside_startup_index_span: Local divide interrupt entry049B is within upstream03F8..04BE aggregate index range but begins a distinct installed handler with current CS near hook04BA. PreserveFN439 and all context/termination gaps. |
| Local only | `13A8:0644` | `FN-EGA-000359` | shared_runtime_error_entry_inside_initializer_span: Local0644 candidate falls within upstream0620 initializer range. Actual0644 MOVAX,2 then0647 JMP04AA enters the common runtime error report path, rather than an independent ordinary C function. PreserveFN359 and its pending contract; no source signature invented. |

## All naming conflicts

The chosen identifier is deliberately neutral where original gameplay semantics or DS binding are unproved. Per-row xrefs and resource-span associations are in JSON. Resolve navigation names without rewriting existing accepted contracts or claiming global ownership/lifetime proof.

| Original address | Chosen identity | Upstream aliases retained | Role/evidence status |
| --- | --- | --- | --- |
| `06C9:412C` | `FN-EGA-000366` | `sound_tick`, `drive_sound_update` | passed |
| `06C9:7D5E` | `FN-EGA-000206` | `gfx_select_target`, `select_target` | passed |
| `06C9:843E` | `FN-EGA-000216` | `gfx_clear_clip`, `fill_clip` | passed |
| `06C9:89A2` | `FN-EGA-000218` | `gfx_fill_rect_clip`, `fill_rect_clip` | passed |
| `06C9:B0FE` | `FN-EGA-000242` | `gfx_create_buffer`, `create_buffer` | pending |
| `06C9:BA3C` | `FN-EGA-000243` | `gfx_plot`, `plot_pixel` | passed |
| `13A3:0038` | `FN-EGA-000254` | `tan_deg8`, `tan256_lookup` | passed |
| `13A8:002E` | `FN-EGA-000255` | `copy_protection_check`, `copyprot_check` | passed |
| `16FC:007C` | `FN-EGA-000422` | `exit_prompt`, `prompt_exit_to_dos` | pending |
| `16FC:0220` | `FN-EGA-000423` | `status_strip`, `message_box` | pending |
| `16FC:0358` | `FN-EGA-000424` | `pause_prompt`, `prompt_pause` | pending |
| `DS:09B2` | `CURRENT-DS-VIEW-09B2` | `drive_buf_desc`, `main_desc` | syntactic_xrefs_only |
| `DS:1352` | `CURRENT-DS-VIEW-1352` | `stream_engine`, `engine_sound_data` | address_alias_only |
| `DS:23A6` | `CURRENT-DS-VIEW-23A6` | `car`, `car_bin` | syntactic_xrefs_only |
| `DS:2E08` | `CURRENT-DS-VIEW-2E08` | `pal_normal`, `palette_normal` | address_alias_only |
| `DS:2E10` | `CURRENT-DS-VIEW-2E10` | `pal_flash`, `palette_flash` | address_alias_only |
| `DS:2F46` | `CURRENT-DS-VIEW-2F46` | `steer_angle`, `steer` | syntactic_xrefs_only |
| `DS:2F48` | `CURRENT-DS-VIEW-2F48` | `view_yaw`, `heading` | syntactic_xrefs_only |
| `DS:2F58` | `CURRENT-DS-VIEW-2F58` | `dash_toggle`, `gate_visible` | syntactic_xrefs_only |
| `DS:2F59` | `CURRENT-DS-VIEW-2F59` | `gate_close_delay`, `gearbox_timer` | syntactic_xrefs_only |
| `DS:2F5A` | `CURRENT-DS-VIEW-2F5A` | `redraw_gate`, `gearbox_dirty` | syntactic_xrefs_only |
| `DS:2F5B` | `CURRENT-DS-VIEW-2F5B` | `redraw_inst`, `gauges_dirty` | syntactic_xrefs_only |
| `DS:2F5C` | `CURRENT-DS-VIEW-2F5C` | `redraw_hud`, `clock_dirty` | syntactic_xrefs_only |
| `DS:30E8` | `CURRENT-DS-VIEW-30E8` | `ENGINE_NOTE`, `engine_div` | syntactic_xrefs_only |
| `DS:32AE` | `CURRENT-DS-VIEW-32AE` | `noise_div`, `RUMBLE` | syntactic_xrefs_only |
| `DS:331C` | `CURRENT-DS-VIEW-331C` | `opp_penalties`, `opp_crashes` | syntactic_xrefs_only |
| `DS:3379` | `CURRENT-DS-VIEW-3379` | `opponent_enabled`, `opp_enabled` | syntactic_xrefs_only |
| `DS:33CE` | `CURRENT-DS-VIEW-33CE` | `fall_scroll`, `fall_depth` | syntactic_xrefs_only |
| `DS:346A` | `CURRENT-DS-VIEW-346A` | `stage_dat`, `dat_image stage` | address_alias_only |
| `DS:347E` | `CURRENT-DS-VIEW-347E` | `road_records`, `dat_records` | syntactic_xrefs_only |
| `DS:368A` | `CURRENT-DS-VIEW-368A` | `dat_scenery_type`, `roadside_type` | syntactic_xrefs_only |
| `DS:370A` | `CURRENT-DS-VIEW-370A` | `dat_scenery_offset`, `roadside_side` | syntactic_xrefs_only |
| `DS:379E` | `CURRENT-DS-VIEW-379E` | `stage_score_k`, `stage_results_words` | syntactic_xrefs_only |
| `DS:37A6` | `CURRENT-DS-VIEW-37A6` | `right_zones`, `dat_band_table` | syntactic_xrefs_only |
| `DS:37F6` | `CURRENT-DS-VIEW-37F6` | `median`, `dat_wide_left` | syntactic_xrefs_only |
| `DS:37F7` | `CURRENT-DS-VIEW-37F7` | `toggle_37f7`, `dat_tunnel_style` | syntactic_xrefs_only |
| `DS:37F8` | `CURRENT-DS-VIEW-37F8` | `backdrop_off`, `dat_no_mountains` | syntactic_xrefs_only |
| `DS:380D` | `CURRENT-DS-VIEW-380D` | `dat_road_units`, `stage_len` | syntactic_xrefs_only |
| `DS:380F` | `CURRENT-DS-VIEW-380F` | `stage_length`, `dat_stage_length finish_unit` | syntactic_xrefs_only |
| `DS:3813` | `CURRENT-DS-VIEW-3813` | `oncoming`, `traffic_list_l` | syntactic_xrefs_only |
| `DS:39A3` | `CURRENT-DS-VIEW-39A3` | `same_dir`, `traffic_list_r` | syntactic_xrefs_only |
| `DS:3B51` | `CURRENT-DS-VIEW-3B51` | `road_bytes`, `road_stream` | address_alias_only |
| `DS:52C8` | `CURRENT-DS-VIEW-52C8` | `player_pos_lo`, `player_sub` | syntactic_xrefs_only |
| `DS:52CA` | `CURRENT-DS-VIEW-52CA` | `player_pos`, `player_pos_hi` | syntactic_xrefs_only |
| `DS:52CC` | `CURRENT-DS-VIEW-52CC` | `player_lateral`, `player_x` | syntactic_xrefs_only |
| `DS:52D0` | `CURRENT-DS-VIEW-52D0` | `opp_pos_lo`, `opp_sub` | syntactic_xrefs_only |
| `DS:52D2` | `CURRENT-DS-VIEW-52D2` | `opp_pos`, `opp_pos_hi` | syntactic_xrefs_only |
| `DS:52D4` | `CURRENT-DS-VIEW-52D4` | `opp_lateral`, `opp_x` | syntactic_xrefs_only |
| `DS:52D8` | `CURRENT-DS-VIEW-52D8` | `cop_pos_lo`, `cop_sub` | syntactic_xrefs_only |
| `DS:52DA` | `CURRENT-DS-VIEW-52DA` | `cop_pos`, `cop_pos_hi` | syntactic_xrefs_only |
| `DS:52DC` | `CURRENT-DS-VIEW-52DC` | `cop_lateral`, `cop_x` | syntactic_xrefs_only |
| `DS:5342` | `CURRENT-DS-VIEW-5342` | `distance_left`, `units_to_finish` | syntactic_xrefs_only |
| `DS:5344` | `CURRENT-DS-VIEW-5344` | `heading`, `mountain_scroll` | syntactic_xrefs_only |
| `DS:534A` | `CURRENT-DS-VIEW-534A` | `scene_words`, `col_left` | syntactic_xrefs_only |
| `DS:5374` | `CURRENT-DS-VIEW-5374` | `player_dist`, `result_dist_player` | syntactic_xrefs_only |
| `DS:5376` | `CURRENT-DS-VIEW-5376` | `opp_dist`, `result_dist_opp` | syntactic_xrefs_only |
| `DS:5490` | `CURRENT-DS-VIEW-5490` | `run_state`, `drive_result` | syntactic_xrefs_only |
| `DS:5491` | `CURRENT-DS-VIEW-5491` | `start_flags`, `region_flags` | syntactic_xrefs_only |
| `DS:5494` | `CURRENT-DS-VIEW-5494` | `stream_noise_short`, `SND_BUMP` | address_alias_only |
| `DS:549F` | `CURRENT-DS-VIEW-549F` | `stream_noise_long`, `SND_CRASH crash_sound_data` | address_alias_only |
| `DS:5560` | `CURRENT-DS-VIEW-5560` | `tan256`, `TAN_DEG` | syntactic_xrefs_only |
| `DS:5616` | `CURRENT-DS-VIEW-5616` | `opp_bin`, `opp_accel` | syntactic_xrefs_only |
| `DS:5656` | `CURRENT-DS-VIEW-5656` | `protect_sabotage`, `protection_failed` | syntactic_xrefs_only |
| `DS:629E` | `CURRENT-DS-VIEW-629E` | `joy_dir_map`, `DIR_FROM_BITS` | syntactic_xrefs_only |
| `DS:8432` | `CURRENT-DS-VIEW-8432` | `diff_c`, `traffic_speed` | syntactic_xrefs_only |
| `DS:843E` | `CURRENT-DS-VIEW-843E` | `game_mode`, `opponent_option` | syntactic_xrefs_only |
| `DS:8640` | `CURRENT-DS-VIEW-8640` | `songs`, `songs_ptr` | syntactic_xrefs_only |
| `DS:8658` | `CURRENT-DS-VIEW-8658` | `out_of_gas`, `out_of_gas_count` | syntactic_xrefs_only |
| `DS:8A9A` | `CURRENT-DS-VIEW-8A9A` | `demo_mode`, `attract` | syntactic_xrefs_only |
| `DS:8CA2` | `CURRENT-DS-VIEW-8CA2` | `page_buf_desc`, `page` | syntactic_xrefs_only |
| `DS:90A8` | `CURRENT-DS-VIEW-90A8` | `diff_easy`, `auto_trans` | syntactic_xrefs_only |
| `DS:920C` | `CURRENT-DS-VIEW-920C` | `diff_b`, `traffic_keep` | syntactic_xrefs_only |
| `DS:9258` | `CURRENT-DS-VIEW-9258` | `outran_police`, `escaped` | syntactic_xrefs_only |
| `DS:940C` | `CURRENT-DS-VIEW-940C` | `scn_signs`, `sgn_ptr stage_sgn` | syntactic_xrefs_only |
| `DS:942A` | `CURRENT-DS-VIEW-942A` | `voices`, `voices_ptr` | syntactic_xrefs_only |
| `DS:942E` | `CURRENT-DS-VIEW-942E` | `stage_time`, `clock_seconds time_seconds` | syntactic_xrefs_only |

## Source and range admission rules

Each original function symbol is linked to an actual C definition when its preferred name or retained alias matches. The JSON pins source files, line ranges, original upstream index span hash and existing local entry/range owners. Every C function's address comments are also retained with their line and prelude/body zone. A comment mentioning a callee does not make the surrounding function that callee. Source-name/comment mapping remains a candidate locator for the representative differential tests.

Original module offsets are segment*16+offset. No load-segment relocation is silently applied. Existing local ranges are shared and sometimes gapped; membership alone is not a complete execution proof. The selected direct-flow graph has no intra-state overlapping instruction bytes, but upstream indexed spans may include data, other entries or unreachable linear fallthrough. Marker/range differences therefore do not cause bulk function-status changes.

All naming conflicts now have an explicit address-based disposition. That closes the ambiguity of which bytes/view a label denotes, while semantic aliases/units and valid historical caller domains stay unpromoted until their own evidence exists. Upstream globalDS annotations are excluded; original xrefs are recorded only as currentDS syntactic displacements. No imported source may inherit our earlier bus/FLAGS/SS differential passes without an explicit checked adapter.

## Remaining gates

P1-R02 address/navigation reconciliation is complete at this bounded scope. Independent candidate input/unpacker identity, per-site deviation/embedded-data classification and the memory/caller profile are owned by the accompanying admission work. P1-R03 still needs its representative candidate build/comparisons. The uncalled library entries, installed handler adaptations, shared/mutable graphics domains, all writers/lifetimes and entire reachableEGA semantics remain obligations forP1-05..11. NoCGA/resource/gameplay/visual/audio/fidelity acceptance is established here.
