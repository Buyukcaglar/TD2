# EGA state and platform body composition

2026-10-14. A separate
[864-case comparison](evidence/td2ega-state-platform-composition-v1.json)
executes1B2C with the reviewed message/sequence/shared-helper bodies and their
recovered platform callees. The private instruction fence contains24 entries:
1B2C;3532/3643; eleven message/shared entries;7A10/7A27/79C8/7A55/6A6A;
69FE/6A03/6A3B; installed69B7; andABFA. This is not a claim that every path or
instruction in the combined fence executes in this particular suite.

Original instructions and eight compiled native libraries agree on ordered
calls, live argument vectors, full bus effects outside live SS frame scratch,
modeled registers/CF/IF/DF, dispatch target and root call count. The suite
executes486,768 original instructions,10,360 synthetic counter boundaries,
5,232 installed69B7 handler calls and768 mocked BIOS10 requests.

Fixtures cover reviewed positive states1..9, raw8424 values0/1/2, independent
and equal DS/SS, returned DS changes, zero-state polling, reinitialization,
reset and cleanup paths, optional message gates, input drain and extended
pending words. A counter boundary can inject a synthetic pending word before
6A6A to exercise its early-input path. The CLC and RETF mutable tails use
separate CPU instances; this does not prove their transition reachability.

69FE uses the observed6A03 target in this suite. Arbitrary far targets and all
setters/lifetimes remain open. Installed69B7 executes with synthetic interrupt
frames; no BIOS/device/IRQ delivery occurs. Counter boundaries update the bus
without delivering interrupts or asserting a clock rate or tick history.
BIOS10, graphics, formatting and other root leaves remain explicit ABI mocks.

Native arguments needed by recovered SS-reading callees are materialized
inside the excluded live frame scratch. Data, code and control frames are
separate in this profile. This does not admit arbitrary frame/data aliases
or actual caller stack allocation bounds. Individual helper suites retain
their own broader arithmetic/alias probes and separate native diagnostics.

These864 cases are separate from the48 helper-suite total. The comparison
strengthens reviewed caller interfaces without closing the actual state
writer/dispatch domain, remaining root/graphics/resource/BIOS10 bodies,
asynchronous lifetimes or complete state machine. P1-05 remains in progress;
remaining EGA code contracts and EGA-before-CGA order still govern P1-GATE.
No DOS game session, renderer/audio output, Windows gameplay, full resource
decoding, Amiga recovery or gameplay/fidelity acceptance is established.
