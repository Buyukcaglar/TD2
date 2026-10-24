"""Index raw EGA resource interfaces and filename-argument candidates.

No file payload decoding or game execution. Lexical matches remain candidates.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'analysis/tools/python'))
from capstone import Cs,CS_ARCH_X86,CS_MODE_16
from capstone.x86 import X86_OP_IMM,X86_OP_REG


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--flow',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'docs/recovery/evidence'):raise ValueError('Fresh evidence output required')
    g=json.loads(a.flow.read_text());data=(ROOT/g['image']).read_bytes()
    if hashlib.sha256(data).hexdigest()!=g['image_sha256']:raise ValueError('Image mismatch')
    records=json.loads((ROOT/'docs/recovery/functions.json').read_text())['records']
    ids={f"{r['entries'][0]['segment']:04X}:{r['entries'][0]['segment_offset']:04X}":r['id'] for r in records}
    md=Cs(CS_ARCH_X86,CS_MODE_16);md.detail=True
    literals=[];names={}
    for m in re.finditer(rb'[A-Za-z0-9_%?\\:.-]{1,32}\.(?:bin|pes|pcs|dat|fnt|sgn|ss|exe)\x00',data,re.I):
        if m.start()<0x178f0:continue
        offset=m.start()-0x178f0;name=m.group()[:-1].decode('ascii')
        names[offset]=name;literals.append({'name_or_suffix':name,'group_offset':offset,'module_offset':m.start(),
                                          'length_with_null':len(m.group()),'interpretation':'Filename/suffix lexical candidate, not proof of a consumer'})
    selected={
        '0000:0297':'Near filename/media-selection wrapper; returns status, not an inferred FILE pointer',
        '13A8:0A6E':'Near filename + near mode string to runtime stream-open path; AX near stream handle/pointer',
        '06C9:5E1C':'Near filename; DOSopen/seekend/seekstart/close; AX ceil(filebytecount/16) low16bit paragraphs',
        '06C9:5E8A':'Near filename; reads exactly4 headerbytes; takes24bit bytes1..3 length and rounds toparagraphs',
        '06C9:5EF4':'DOS1A/4E FindFirst path/DTA helper; successAXnear5D88, failure0. CHattribute retained,87byteprefix/13bytefound-name copy andglobal5DEC lifetime; notpurebooleanopen/close existence',
        '06C9:5F4E':'DOS1A/4F FindNext usesexisting5DEC andDTA5DEE, returnsnear5D88or0. Literal13byteforwardcopy aliases/wrap; actualglobal search/caller lifetime pending',
        '16B8:0000':'Signedordinal search: alwaysFindFirst, canFindNext afterfirstfailure forordinal>1; returnslastnear5D88or0. Nativecomposition preservesstaleDTA/basename aliases; actualDOS/history pending',
        '06C9:6AA2':'Near filename + offset/segment destination; DOS read chunks4000h and segment+=0400h; returns originalAXoffset:DXsegment',
        '06C9:6D18':'Near filename; cache lookup then paragraphallocation and rawread; returns AXoffset:DXsegment',
        '06C9:6D50':'Near filename; cache or rawread/guarded stage dispatch. Synthetic final6B02 paths return farstorage; intermediate7C16 returns count. Arbitrary order/caller bounds pending; uncached SI/DI popshift preserved',
        '06C9:6E4E':'Optional four-byte directory selector, null-tail space publication, literal signed-count scan and far result; missing returns0:0. Source-offset omitted from result base as original; archive bounds/schema pending',
        '06C9:6E59':'Required variant of6E4E; missing enters fatal651A. Actual caller/source/lifetime bounds remain open; bounded native comparison does not admit a supplied archive',
        '16EB:000A':'Required directory-selector list; mutable caller selector argument and output-to-selector/source alias effects preserved by native composition. Actual principalDS/list/source/output bounds pending',
        '16EB:004C':'Optional directory-selector list, stores0:0 for absent selectors; same mutable argument/shared view effects as000A. Empty list preservesAX/DX/DF',
        '1748:000E':'Near graphic filename; dotless .PES/.ESH lookup, cache/raw/packed dispatch; .PES conversion throughC838 and temporary allocation release7490',
        '06C9:6B02':'Bounded C17 run/block stage plusnearframehelpers: DS=SS,markers1..11,far0:destination return,originalcounter/REPwrap effects. Larger-stack-marker/corpus/callerallocation domains pending',
        '06C9:7C16':'Bounded C17 prefix byte-stage, declared24bit count return; lowword0 writesextra65536, optionaldelta and16bit tableeffects. Fullformat/corpus/caller scratch bounds pending',
        '06C9:71B4':'Named cache search/transfer over18byte descriptors; writes descriptor ownership metadata',
        '06C9:70A3':'Named allocation bookkeeping over18byte descriptors; returns normalized far storage',
        '06C9:7273':'Readonly name query, AXboolean; DXpreserved onsuccess or0onfailure. Firstfree abort/sentinel inclusion; nofarstorage pointer returned',
        '06C9:72C6':'Release bysegment; conditionally cache withstatus1 and returnAXoriginaloffset:DXnewcachedsegment, orDX0',
        '06C9:736B':'Release bysegment; can compact/cache payload butreturnsAXoriginaloffset:DX0; distinct from72C6',
        '06C9:7490':'Discard active allocation bysegment; status0 andactive-top trim; no cachepayload move',
        '06C9:7147':'Backward cache-descriptor compaction andpayload movement; updates6C6A',
        '06C9:7083':'Near basename pointer afterlastcolon/backslash; no case folding',
        '06C9:6FE8':'Ascending paragraph wordcopy,1000h-paragraph chunks,DSrestore/ESclobber/DF0; bounded C17 externalpool contract',
        '06C9:7030':'Descending paragraph wordcopy,STD thenCLD,DSrestore/ESclobber; bounded C17 externalpool contract',
        '06C9:6F1E':'Rawpool setup/reset: DOS48 allocation andtwo4A resizes withoutlocalcarrybranches; establishesboundaries, resetsindices/interiorstatuses; platformsuccess/errors pending',
        '06C9:6FD6':'AX unsigned16 end-sentinel segment minusactive-top segment/paragraphs; notgap-beforecache oradmittedhost allocation size',
        '06C9:75C8':'Far voices pointer setter; raw consumer contract reviewed separately',
        '06C9:758A':'Far songs pointer plus index setter; raw consumer contract reviewed separately',
        '06C9:79C8':'OwnedDS5E8C/E rawcounter snapshotCLI/STI/IF1, distinctfromphysical086C; actualIRQ/rate/profile pending',
        '06C9:7A55':'Raw32distancewait:moddeadline thenabsoluteunsignedownedcountercompare; wrapcanexitimmediately, unitless/counterstreamonly',
        '06C9:6A6A':'69FEinput-or-rawcounterwait, SSdeadline/returnedDS andearlyinputIFDF retained; actualcallback/IRQ/lifetime pending',
        '06C9:1B2C':'Stateorchestration/rootrawfields/resetfarpairs/callargumentlifetimes andmutableCLC/RETFtail; typedcalleeABIservices, mostbodies/statewriter/IRQ/resource domains pending',
        '06C9:1E59':'SS3813/39A3 rawrecord preparation, DSglobal/DSforwarddelete/byte-source consumption/scaling/DIVprefix; conditionalrouteDATcopy withSS=DS, actualresource/IRQ/reset pending',
        '06C9:6860':'Keyboardvector installer:offsetonly6907guard, savedIVT09/16,90keyflagclear/pendingwordretained; syntheticPICprofile only',
        '06C9:68C4':'Actual16A7reportparent/68C4cleanup/actual642E-840A-610A-29F6-message-exitbodies/fullSS-latefivewordPUSHreads/returnedBPaliases/PICrestoreAH-orderedIVT-BDAwrites/callerADDSP0A/wholeRAM-GPR-BP-CFIFDF-definedFLAGS/orderedBIOS-device-port-DOS/independentCPUwrites.4906cases/4404970instructions/all13admittedparentof15-and22cleanup/269of342union/51native; separate432lowmemoryrootaliases/192changedfarwordpairs.358syntheticRETFs separate. Formatter0B00 typedretiredABIprofilenotbodyproof; preparedDOSexitnotexecuted/no inventedparentepilogue. Fullformatter/caller-DS-SS/allwriters-lifetime-IRQ/core-B0FEarenaqualification/P1-GATE unproved.',
        '06C9:6907':'IRQ09 scan/latch/modifier/keytable consumer, makebeforemodifierread andpendingword publication; actualIRQ pending',
        '06C9:69B7':'AdditionalactualSSINT16body/PUSHBX-PUSHDS-beforeprincipalDSread/orderedpendingclear-savedDS-BX-IP-FLAGS aliases/AH1STI-ORAX-RETF2 versusotherAH-IRET/CFZFIFDF/actualrawrootcoordinates. RS293pendingword-RS29490keyflags/knownproducerprofiles; oldtypedAPI/compositions frozen. Actualinstallerownership-INT-IRQhistory/allwriters-capacity-lifetime/full420A-403B-core open',
        '06C9:646F':'Keycallback6CFC0 then16FC0220 withneartext603C/8/0 caller-clean; UIbody/resourcebounds pending',
        '06C9:6488':'Effectsbit toggle OR1/AND2 withsharedactiveclear,neartext6029/6032 UIABI; fullUI/IRQ lifetime pending',
        '06C9:64C7':'Musicbit toggle OR2/AND1 withsharedactiveclear,neartext6016/601F UIABI; fullUI/IRQ lifetime pending',
        '06C9:61BF':'Additional independent timer_handler_bus_flags entry preserves the same61BF/6230 fullSS body while accepting F72B incoming/retired child flags. Arithmetic CF/IF/DF and named system-bit profile remain known; PF/AF/ZF/SF/OF may be unexposed. Prefixes retain partial masks/actual child coordinates; normalADDDI4 and laterCMP regain defined arithmetic flags. Frozen original handler interface unchanged. Actualfull403B/nestedIRQ-writers-reset-lifetime-core/P1-GATE remain open.',
        '06C9:6230':'Additional independent timer_handler_bus_flags entry preserves the same61BF/6230 fullSS body while accepting F72B incoming/retired child flags. Arithmetic CF/IF/DF and named system-bit profile remain known; PF/AF/ZF/SF/OF may be unexposed. Prefixes retain partial masks/actual child coordinates; normalADDDI4 and laterCMP regain defined arithmetic flags. Frozen original handler interface unchanged. Actualfull403B/nestedIRQ-writers-reset-lifetime-core/P1-GATE remain open.',
        '06C9:6269':'Additional6269 actualSS/currentDS/literalCS6334word dispatch/actualfarRET/whole1MiBRAM-GPR-BP-CFIFDF-definedFLAGS/independentCPUwrites/byteport profiles. Known altered words dispatch by target offset; unsupported words native6 beforeJMP. Source loop/port budgets and preRET qualification are diagnostic prefixes. Actual6269-first403B composition/IRQ-writers-reset-storage-lifetime-exclusion/core remain open. RS298256byteinitializedword-envelope/transitivehardware units unassigned.',
        '06C9:75EA':'Serialized music callback:3byte songrecords/2byte events, FD28bytevoicecopy, counter/pitch andtypedport effects; sourcebounds/VOICESexception/IRQ/timebase pending'
    }
    selected.update({
        '06C9:403B': 'Whole 06C9:403B far/no-arguments controller: 80 root instruction sites and 11 near CALL sites, actual SS frames, relocated principal DS/ES, frozen C callee composition and actual nonlocal near unwind. Caller/IRQ ownership, shared-source writers/reset/lifetime and whole-core admission remain open. Transitive raw resources only; counter words have no assigned clock units.',

        '06C9:420A':'Whole420AadditionalactualSS/37root-sites-8CALLs/15actualbodies-663sites/eightimmutablebranchforms/actual69B7-6528-gameport-fields-motion-multiply-scanner. RealnearrootRET/4219argumentPUSH-421FPOPBX/actualmotionpreclampfullFLAGS->6601INTFLAGS/CPU-modedINTwrites/CFZFIFDF/retiredchildcontrol. RawSSviewRS271-291..297/transitiveconsumeronly; no allwriters-capacity-lifetime-IRQ/callbackbody/whole403B-core/P1-GATE closure.',

        '06C9:65C5':'AdditionalactualSS65C5/fullrawFLAGS-validity/explicitundefinedAF0-1/modeledINTFLAGS-CS-IP/actual69B7AH1-AH0/actual6528retiredcallback-or6686port/ADDSP2fullflags/16word6254lookup-6274repeat/actualfarRET. RS293-295-296-297/actualvector-caller-allwriters-lifetime-IRQ/whole420A-403B-core open.',
        '06C9:6601':'AdditionalactualSS6601/fullrawFLAGS-validity/modeledINT16actual69B7/SS-DSconsume gate/actual6528-keycaller-clean-ADDSP2/actualfarRET. InputentryFLAGS survivesMOVAH1; whole420A4261motionfullFLAGS before4266stillrequiresproof. RS293-296-297/allwriters-callbacks-vectorownership-lifetime-IRQ-core open.',
        '06C9:6620':'AdditionalactualSS6620/tenkeyflagbytes-ORAL/ORAX/fullFLAGSvalidity/explicitundefinedAFchoice/actual6686fallbackandfarRET. RS294-295 andconditionalSSframewriterRS297; actualcaller-validhistory-allwriters-capacity-lifetime-IRQ/full420A-403B-core open.',

        '06C9:6528':'AdditionalactualSS6528/oneSSkeyword/PUSHBP-beforeguard/SSargumentrewrite/live261nearwordlookup/capturedBX/PUSHCS-nearCALLBX/retiredfarcallbackresponse-CSIPSPchecked/actualsavedSI-DI-BP/rootplainRETF/returnedDSguardclear/definedCFZF. RS296522byte rawnearwordview/conditionalSSframewriters/6585potential32640even-offsetwriterdomain; knownsixcallbackbodies and6559target-domain-allwriters-lifetime-IRQ/fullinputpoll-420A-403B-core remainopen, complete=false.',

        '06C9:6686':'AdditionalactualSS6686/currentDS/orderedbyte201-portstates-GPR-CFZFIFDF/CLItrigger-STIcalibration/signedX-unsignedY-minthreshold/raw16bitDIV-SHR/actualchangedfarwords/plainRETF. RS295627C50byte rawcount-calibration-translationview/serialized4003INbound nottimebase; wholeinputpoll-420A-403B/allwriters-capacity-lifetime-IRQ-core open.',
        '06C9:680A':'AdditionalactualSS680A/MOV-onlyinitializer/explicitincomingCFZF-IFDF-preserved/fiveDSwritescanoverwriteactualfarreturnwords/plainRETF. RS295conditionalDSwriter; wholecaller/input-allwriters-capacity-lifetime-IRQ-core open.',
        '06C9:6828':'AdditionalactualSS6828/oneSSword/rawwordmaskF/actualPUSHBP-before-liveDS629Elookup/CF0ZF1evennonzeroAL/plainRETF-caller-clean. 420AusesPOPBXtoconsumeoriginalargument, notsavedBXrestore. RS295conditionalSSsavedBP-aliaswriter; full420A/allwriters-capacity-lifetime-IRQ-core open.',

        '06B3:0008':'Additional06B3:0008far/plainRETF/fullSS/actual2EE8-RETF8/orderedlocals-globals. FullmotionFLAGS fromterminalSUBAXAX orCMP2F46,F180 beforelowerclamp; normalOF0/upperCMPcanOF1/afterclampRAMlosesflags. Before0114CALL NEGDXfullydefined; 420A4261->6601incomingINTFLAGSrequiresfullword. Sameentrycountedonce/no newspan. Whole420A-403B/caller-allwriters-capacity-lifetime-IRQ-core open.',
        '13A8:2EE8':'Additional13A8:2EE8far/fourSSwords/actualsavedBP-RETF8/frozenpuremultiply/fastCXpreserved-ZFundefined/generalwrappedcross-termCX-finalADD-DX-CFZF. SP>FFFCpreRETFprefix only/backendprofile; actualcaller-domain-storage-lifetime-core open.',
        '06C9:44A6':'Additional06C9:44A6near/fullSS/currentDS-ES/AX0DFshortcut/backwardfivebyteESscan-CLD/DSfivenearwords/threeactiontargets-plus-known44BE-RETtail/unknownrawwordbeforeJMPprefix4. RS271conditionalESbinding/alltablewriters-validdomain-lifetime-IRQ/whole420A-403B-core open.',

        '06C9:4281':'Additional actualSS near4281/currentDS/BPclobber/immutable42AD-JA-JNE/ordered byte-state and overlapping339x/240x views/byte-selector23C6-23C8 targetpairs/actual4612-4441 frames. RS291boundwords-RS2921024byte target footprint; no new unique entry. Whole420A-403B/writers-capacity-lifetime-IRQ-core open.',
        '06C9:43C3':'Additional actualSS near43C3/signed wrapped pair approach6/postwrite rereads/BH publication and MOVBL retainsBH/variable23B8 lookup any even currentDSword/actual4612-4441 frames. RS292fixed23C8 only, not variablelookup bound. Whole420A-403B/BHdomain-allwriters-capacity-lifetime-IRQ-core open.',
        '06C9:4441':'Additional actualSS near4441/signed branch then unsigned wrapped thresholds/AH-only subtraction5/ALborrow clamp/BYTE-MUL/definedCFZF/actual rootRET. Whole420A-403B/writers-capacity-lifetime-IRQ-core open.',
        '06C9:448A':'Additional actualSS near448A/eight signedCBWbytes335D-3364/ordered30E4 then30E6 stores/CF0-ZF1 from finalCMPBL8 independentof finalAX/actual rootRET. Whole420A-403B/writers-capacity-lifetime-IRQ-core open.',

        '06C9:4674':'Whole06C9:4674near/noargs/241root-sites/25actualbodies-687sites/fullSS-currentDS/arithmetic/sourceorderedring-and-state/13recognized491Dnearcallbacktargets/frozenCcalleecomposition. Unknownrawtargetnative6prefixbeforeCALL; validdomain-allwriters-IRQ-lifetime-core remainopen. RS289masked128x4record/RS290initialized48nearwordview/raw256selector-envelope; actual499Asource37DD..38DCcontainedRS288. Primaryrowcounter366notfullcycles/supplement2actualwraps. Whole403B/420A/validdomain-allwriters-lifetime-IRQ-coreopen.',

        '06C9:412C':'AdditionalfullSSbusview/existingnearbody/CFZF/actualSSnearRET/post332Astore-before-indexed30E8read/RS287masked32word64byteview-andRS2881024word2048byteoverlapview. Actual403B/writers-capacity-lifetime-IRQ-coreopen.',
        '06C9:4639':'AdditionalfullSSbusview/existingnearbody/unsignedorderedbounds/signedDEC80-JLoverflow-retainsCF/actualSSnearRET/statepublication/RS288overlapped332Cfield. Actual403B/writers-capacity-lifetime-IRQ-coreopen.',

        '06C9:4929':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',
        '06C9:4947':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',
        '06C9:494D':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',
        '06C9:495D':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',
        '06C9:499A':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',
        '06C9:49C9':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',
        '06C9:49CF':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',
        '06C9:49D5':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',
        '06C9:49DB':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',
        '06C9:49E1':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',
        '06C9:4A18':'AdditionalfullSSbusview/existingnearbody/CFZF-inputZF/actualSSnearRET/noownframe. 499AoutputsdefaultSS/DSsourcepostwritealias; otherstatewritescurrentDS. Actual491Dtargetbounds-allwriters/full4674-lifetime-IRQ-coreopen.',

        '06C9:4C85':'Actual06C9:4C85 near/noargs/currentDS/fullSS/maskedtoken/inline-or-ESnear-width/BYTE-DIV5-keepsAHlookup/BYTEsignedIMUL50/actual4D26/near4A2E/cachedprechildunsignedBP20-postchildstate2/nearRET. RS284-285128bytezero-views/RS286318byte-stridedword-footprint/knownDATcopy-first2/actualallwriters-objectcapacities-storage-lifetime-sharedsource-IRQ-fullcaller-coreopen.',
        '06C9:4AFA':'Actual06C9:4AFA near/noargs/currentDS/orderedwrappedwindowwrites/signedCL-JG-JL/markedbranch-originalAX-after52CCclamp/state1-4-9/actualnearRET-requiredZF. No newspan/RS271window-writers-andconditionalinheritedRS250-270-271-272-273/actualcaller-sharedsource-allwriters-validindices-storage-lifetime-IRQ-coreopen.',
        '06C9:4B5D':'Actual06C9:4B5D near/noargs/ALload-AHretained/DEC-TEST0Fgate/actual4D26fullSS-requiredZF/negative500-or900thenpositive500-or900/actualnear4A2Eframe/fullSS-frozenfamily/nearRET. No newspan/RS271window-writers-andconditionalinheritedRS250-270-271-272-273/actualcaller-sharedsource-allwriters-validindices-storage-lifetime-IRQ-coreopen.',

        '06C9:4B9A':'Actual06C9:4B9A near/noargs/currentDS/fullSS/signedthresholds/sourceorderedstatewrites/8byterawrowSIwrap/signedIMUL-IDIV/actual45FC-4612/nearRET-requiredZF. RS283minimalzerohead/RS271orderedstatewrites/knownDATcopy/allwriters-validrows-capacity-storage-lifetime-IRQ-fullcaller-coreopen.',
        '06C9:49E7':'Actual06C9:49E7 near/noargs/negative400-or800thenpositive400-or800/radius5/actual4D26requiredZF/conditionalfrozen4A2EfullSS-tail/actualnearRET. No newspan/conditionalinheritedRS270-271-272-273writers/actual491Dvalidselector-allwriters-full4674-sharedsource-IRQ-lifetime-coreopen.',
        '06C9:4A19':'Actual06C9:4A19 near/noargs/incomingBLbit2/positive-or-negative200/radius7/actual4D26requiredZF/MOVAH6F/conditionalfrozen4A2EfullSS-tail/actualnearRET. No newspan/conditionalinheritedRS270-271-272-273writers/actual491Dvalidselector-allwriters-full4674-sharedsource-IRQ-lifetime-coreopen.',

        '06C9:4A2E':'Actual06C9:4A2E near/noargs/fullSS/actual45FC-4612/7977CLI-pointer-store-STI/780Ebyte-ring/IF1sample/sourceorderedwrappedstate-arithmetic/raw256selectorwriters/actualnear-farRET. No newspan/conditionalRS271-272-273-270writers/validselector-allwriters-indirecttargets-sharedsource-lifetime-IRQ-coreopen.',
        '06C9:843E':'Actual06C9:843E far/oneSScolorword/fullSS/currentCSgeometry/DFretained/threefillpaths/softwarepackedwordIMUL-lowword-DLshift/softwareSScolorword-mutatingrows/hardwareBYTE-MUL-heightLow8-or-liveSSrows/globalwork/actualfarRET. No newspan/liveCSviewgeometry/allwriters-DF-caller-capacities-storage-lifetime-exclusion-device-coreopen/fullresourcecodecnotadmitted.',
        '06C9:AE62':'Actual06C9:AE62 far/eightSSwords/fullSS/DS-ESA000CLD/unsignedxSHR3/firstREPshift-do-oncewideDECJG/optionalmembertwoBYTE-MULs/zero-nibblewholeexit/secondLODS-ReadAH-WriteAL-LOOPwidth0wrap/liveSSlocals/globalwork/actualfarRET. No newspan/rawmemberfields/allwriters-format-capacities-storage-lifetime-exclusion-device-coreopen/fullresourcecodecnotadmitted.',
        '06C9:AC40':'Actual06C9:AC40 far/SSmemberoffset-segment-x-y/fullSS/orderedheaderwrites/liveSSwidth-height-start-stride-gap-counter-configptr/CSnonzero-nibbleselector/DSA000-CLD/packedbyteCOPY/DEC-JGwide/actualfarRET. RS282nibbleview/AC64alternateentry-dispositionopen/allwriters-memberbounds-storage-lifetime-exclusion-device-coreopen/fullresourcecodecnotadmitted.',
        '06C9:3A91':'Actual06C9:3A91 near/currentDS52CA-52D2-52DA liveinputs/BX0-2-4/DX0C-09-0E/threeactual3AB8nearframes-BA3Cfarframes/fullSS/globalouterCALL-pixelCALL-devicebudgets/lastactualchildCF-ZF/nearRET. RS281indirectcache-reader-writer/RS279indirectmask/live52CA-52D2-52DA/allwriters-storage-coordinatebounds-lifetime-exclusion-device-coreopen/fullresourcecodecnotadmitted.',
        '06C9:3AB8':'Actual06C9:3AB8 near/registerSI-BX-DX/signedSUB-JGE-SAR5/currentDS2F50+BX/cachewrite-before-old-newSSpixelframes/actualBA3C/globalCALL-deviceeventbudgets/nearRET-CF-ZF. RS281minimalcachewordview/RS279conditionalmask/allwriters-coordinatebounds-storage-lifetime-exclusion-device-coreopen/fullresourcecodecnotadmitted.',
        '13A8:18B0':'Actual13A8:18B0 PUSHCS+nearCALL farframe/fullSS/currentDS83EErawcounter-83F2nearstream/DECSFguard/cursorINC-before-bytefetch/actual0B42fullallocator-reader/globalDOSbudget/plainfarRET. BSS83EE/83F2/RS266-RS262conditionalindirect/allwriters-storage-capacity-lifetime-exclusion-coreopen/fullresourcecodecnotadmitted.',
        '13A8:0B42':'Actual13A8:0B42 far/SSnearstreamword/fullSS/rawflagZF/signedchannel-times6/actual0BE8heap and247C-094Areader/globalDOSbudget/currentreturnedDS-SI-BP/countstore-before-JG/cursorINC-before-bytefetch/plainfarRET. RS266directside/RS262conditionalmapper/allwriters-storage-capacity-lifetime-exclusion-coreopen/fullresourcecodecnotadmitted.',
        '13A8:247C':'Actual13A8:247C far/SS-handle-nearDSbuffer-count/fullSS/currentDSflags/DOS3Ffullstate/binary-or-firstLF-CR-1Aloop/defaultDSwrites-currentDFLODS/4400-3F-4201lookahead/currentDSnear-vs-SSlocal/returnedAH-CX-BP-DS-DI-SI/full094A-nearRET/sharedfarRET/budgets-qualification. RS262conditionalvia094A/actualDOS-callerDS-SS-buffer-writers-storage-lifetime-exclusion-coreopen/fullresourcecodecnotadmitted.',
        '06C9:C784':'Actual06C9:C784 far/sixSSwords/fullSSlocals/in-placeSAR3source-destX/SAR3widthlocal/currentCSrow-plane-strides/DSA000-CLD/fourplanes-zero-skip/byteOUT-rawCOPY/livewidth-stride-heightreads/do-onceDECJGwide/globalrow-port-copywork/actualSSFNs-farRET-or-preRETqualification. CurrentCSrow-plane-stridebindings/allwriters-coordinatebounds-storage-lifetime-exclusion/devicehardware-coreopen.',
        '06C9:5FBC':'Actual06C9:5FBC far/noargs/PUSHDI-beforecurrentDS5E6Ebranch:zeroactual642E-840A-fullSS-currentDF/twoBIOSfullstate; nonzeroBDA0410OR30/27byteOUTs-currentDS12tablebytes/CLD16384B800wordeffects/BIOS10AX7fullstate/actualPOPDI-rootRET/globalCALL-eventbudgets. RS28012rawportvalues/currentDS-allwriters-controllerunits-hardware-callerBP-storage-lifetime-exclusion-coreopen/noCGAedition.',
        '06C9:BA3C':'Actual06C9:BA3C far/SSx-y-colorlowbyte/fullSS/unsignedxSHR3-xAND7/wrappedCSrowlookup/currentDS8maskbytes/currentCSfirstA000fivewordOUT-byteReadWrite orfourliveplanezero-skip-readANDwrite-atomicOR/actualSSFNs-farRET-or-preRETqualification. RS2798rawmaskbytes/sourcex&7bound/currentDSallwriters-CSrowplane-storage-lifetime-exclusion-devicehardware-coreopen.',
        '06C9:0083':'Actual0083/38D4 far/noargs/currentDSfar-descriptorpointerwords/actual782C-7490-fullSS/entry1firstargsretainedduringsecondCALL-ADDSP8/globalCALL-search-trimbudgets/actualchildRETchecks/fatal-budget-preRETqualificationprefixes. CurrentDS09B2-09B4mutablefar-descriptorviews/pointerwriters-storage-lifetime-exclusion-coreopen.',
        '06C9:38D4':'Actual0083/38D4 far/noargs/currentDSfar-descriptorpointerwords/actual782C-7490-fullSS/entry1firstargsretainedduringsecondCALL-ADDSP8/globalCALL-search-trimbudgets/actualchildRETchecks/fatal-budget-preRETqualificationprefixes. CurrentDS2F60-2F62and2F68-2F6Amutablefar-descriptorviews/pointerwriters-storage-lifetime-exclusion-coreopen.',
        '06C9:782C':'Actual06C9:782C far/twoSSwords-fardescriptor/actualSSBP-DS-SI-DIsaves/DSobjectword+13-lowworddouble-CSB269subtract/store-beforeDSrestore/actual7490raw18bytecache-search-ignorestatus/toptrim/fullCPU-SS/boundedrootRET-rawchild-fatalpreCALL-budget-preRETqualification. Counterunits/allwriters/actualdescriptorbounds-objectstorage-lifetime/cacheexclusion/fatalcleanup-coreopen.',
        '06C9:642E':'Actual06C9:642E far/noargs/XORAX-PUSHzero/actual840A-fullSS-currentDF/sharedbudget/childRETcheck-ADDSP2/BDAphysical0410mask/BIOS10AX0003fullstate thenAH0B-retainreturnedAL-BX0/fullstate/boundedrootRET-or-preRETqualification. CurrentBIOSreturnedAL-DS-ES-BP preservedintosecondrequest; actualROM-devicehardware/callerprofiles-storage-exclusion-coreopen.',
        '06C9:90E8':'Actual06C9:90E8 far/noargs/eightOUTs/actual840Aarg0-fullSS-currentDF/sharedbudget/childRETcheck-ADDSP2/BDAphysical0410mask/BIOS10AX000D-fullstate/AX1002-ESactualreturnedDS-DX6848-17bytepayload/fullstate/boundedrootRET-or-preRETqualification. RS27817rawpaletteparameterbytes/modeBIOSreturnedDS/allwriters-devicehardware-callerprofile-storage-exclusion-core open.',
        '06C9:5F64':'ActualEGAexe06C9:5F64 far/noargs/initialDSflag-BDAphysical0410mask/BIOS10AX0004fullreturnedstate/27byteOUTs-currentDS12tablebytes/CLD-REP16384B800wordeffects/fullSS/boundedRET-or-unqualifiedfarframeprefix. RS277raw12portvalues/postBIOSDS/actualBIOS-device-callerBP-profile-storage-writers-exclusion-core open/noCGAedition.',
        '06C9:840A':'Actual06C9:840A far/oneSSwordfill/sixbyteOUTs/REP8000devicebytes/incomingDF/SSargumentafterports/fullSS/boundedfarRET ornative5unqualifiedfourbyteframeprefixat843D. RawA000-devicewrites/sixports/SSfillword/CPU-frame-device-model-callerDF-IF-storage-exclusion-core open/noembeddedspan.',
        '0000:0651':'Actual0000:0651 far/noargs/fullSS/twoqueries/stride30/signedwordIMUL-DXAX-CF/mutablecount/lastmatches/primary0-secondarycount>1fallback/actual2B40-2956/incomingDF/fourargcleanups/farRET. RawBSS8D24-8428-90B0-9266-8CFE-8A7A-8A82-9264/noinitializedembeddedspan/writers-schema-capacity-lifetime-core open.',
        '0000:0730':'Actual0000:0730 far/noargs/fullSS/signedmutablecount/stride32casecompare2B40/lastmatch/fallbackrecord0/actual2956incomingDF/finaluncleanedargs-MOVSPBP/tailindexword-shift-wrap/read26/store8A80. RawcurrentDS/BSS865C-8CFA-90AA-9212-8A80/noinitializedembeddedspan/writers-name-count-indexschema-capacity-lifetime-core open.',
        '13A8:2600':'Actual13A8:2600 near/inheritedBP-DX-DI/fullSS/typedDOS40/actualcountupdate/normalnearRET orADDSP8carry-replacesDOSCF/rawflags-1A/shared2558nonlocalfarRET/actual094A mapper-nearframe. RawDOSwritebuffer/SSparentcount-savedSP/currentDSflags-errorglobals/whole2558-fatalcallbacks-writers-capacity-profile-lifetime-core open.',
        '13A8:21D6':'Actual13A8:21D6 far/twoSSwords-value-streamnearoffset/rawflags-FFFFguard/actual0BE8-fullSS/cursor-countboundary/inc-dec-backwardbyte/sourceorderedaliases/signedmetadata/plainfarRET. RS266nominalsidecandidate/unboundedrawsignedindex/RS274-275-276indirectconsumer/wholecallers-writers-capacity-profile-lifetime-core open.',
        '13A8:0BE8':'Actual13A8:0BE8 near/oneSSnearoffsetstreamargument/fixedcount200/actual26A8-fullSS/AX-onlystreamoffset/currentDS/signedbyte-times-sixmetadata/sourceorderedrereads/actualnearRET. RS266nominalsidecandidateunboundedrawsignedindex/RS274-275-276indirectconsumption/wholecallers-writers-capacity-profile-lifetime-core open.',
        '13A8:26A8':'Actual13A8:26A8 far/onecaller-ownedSSwordcount/actual2830requiredZF-init/currentDSglobalstores/currentBPargument/actual26F1-fullSS-DS-ES/AXoffset-DXsegmentorzero/actualSSepilogue/plainfarRET. RS274-275-276rawmetadata/wholepubliccallers-writers-capacity-profile-lifetime-core open.',
        '13A8:26F1':'Actual13A8:26F1 near/inheritedBX-CX/currentDS-ES/fullSS/actual280E-27D4-requiredZF/rawwordheaders/byteupdates/CLD-thenactualreturnedDF-LODSW/DSswitches/AXoffset-DXsegment-or-zero/nearRET. RS276controlcontainsRS275/RS274indirectconsumer/whole26A8-writers-capacity-profile-lifetime-core open.',
        '13A8:27D4':'Actual13A8:27D4 near/inheritedcontext/actual280ErequiredZF/fullSS/explicitES6F36/rawheaderword/mask-overflow/retryusingactualreturnedDX/actualsavedCX-nearRET. RS275explicitESword/RS274indirectconsumer/whole26F1-writers-capacity-profile-lifetime-core open.',
        '13A8:280E':'Actual13A8:280E near/inheritedregistercontext/actual2830ZF/fullSS-nearfarframes/orderedDSmetadata/SUB-DECcarry-zero/actualPOPAXsavedDI-CX-DX/nearRET. RS274indirectconsumer/requiredZF27B0-2802/wholehighercallers-writers-capacity-profile-lifetime-core open.',
        '13A8:2830':'Actual13A8:2830 near/noSSargs/AXrawsize-DSkey-ESmetadataDS, actual2852mode1/fullSSfar-nearframes/fiveargs/DSswitch/savedAX-to-DX/DS-BXrestores/requirednormalZF. RequiredZF26BDJNE/2813JE/RS274indirectconsumer/wholecaller-writers-capacity-lifetime-core open.',
        '13A8:2852':'Actual13A8:2852 far/fiveavailableSSwords/fullSS/actual28C0inheritedBP-nearCALL/twoCFconsumers/secondactualPUSHSI-POPSI/fallbackDOS48/fullreturnedstate/orderedmetadata/farRET. RS274knownwriters/raw48-4A/higher2830-allwriters-capacity-lifetime-core open.',
        '13A8:28C0':'Actual13A8:28C0 near/inheritedBP-SSarg0E/rawDI-DX/table4bytes/sizecarry/17bitparagraphrounding/DOS4Afullreturnedstate/metadataXCHG/actualSSnearRET. RS274rawtable/actual2852CFconsumers/wholecaller-allwriters-lifetime-core open.',
        '0432:0006':'Actual0432:0006 far/twoSSnearoffsetargs/actual2956copy-fullSSfarframe/incomingDF, signedSSlocal17downwardtrimthenforwardspace-to-underscore/actualsavedSI-BP-farreturn. Actualfourwholecallers/NUL-capacity-DF/writers/lifetime/core open.',
        '06C9:0201':'Actual06C9:0201 far/noargs/currentDS/17wordREPSTOSW-CLD-ESDS/twodo-once8byterecordloops/livecountandrecordrereads/partial6byteoutput/cachedbaseSUB-SBB/actualBPclobber/fullSSfarreturn. Actual1B2C/3532caller/capacity/liveboundwriters/lifetime/core open.',
        '06C9:53A6':'Actualnear53A6/noSSargs/fullSS/actual56ED-4612/5446tail, mutable5514-55A1rawnearwordtargets/known13blocks/unknown6, child57A7/known3, explicitPOPAX-RETnonlocalparentexit. RS272/273initializedparentwords/allwriters-domains/whole403B/IRQ/core open.',
        '13A8:20F0':'Actual13A8:20F0 far/twoSSnearoffsetarguments, rawstarDS8404cursor, optionalSSsign/worddecimalwrap/signedbyteguards/IMULCF/outputword/actualSSrestores-RETF4. Actual192Ccaller/bounds/starcursorwriters/lifetime/core open.',
        '06C9:56ED':'Actualnear56ED/noSSargs/actualmath-ratio-scalarCchildren/fullSS, mutableDS57A7near-dispatch operand/knownactualtargets andunknownprefix6, rawcurve/partialwordstores, ordinaryRET2 orliteralPOPAX+RET2 two-SS-word unwind/actualdiscardedAX. RS2695636viewoverlapsRS253/RS270initialized3460candidate; actual53A6/twowordunwind/allindirectwriters/units/lifetime/core open.',
        '06C9:50A1':'Actualnear50A1/noSSargs, disable/DECearlypaths/rawSUB-SBBsignedguards, tenpossibleactualmath-arithmetic-scalarCALLs, dynamicDI4*3318highbyte/zeroDIVprefix, raw5616-324Atables/orderedbyte52D0-word52D2commit/final52D4signedstep535E/fullSS/RET2. RS2685616wordviewoverlapsRS253, RS267byteviewshared; actual403B/3318producer/writer/units/lifetime/core open.',
        '06C9:5A6F':'Actualnear5A6F/noSSargs, clears2F56-33B2 thenactual4588/44D8/fullSS, raw33D4branches/52CCsignedstep25/33CEincrement3or33D2/unsigned100-280guards/orderedstores/rootRET2. Actual403B/statusFLAGS/writers/units/lifetime/core open.',
        '06C9:44EA':'Actualnear44EA/noSSargs, rawbyte/indexedguards/fixedDXtailJMPs/ordinary4588-45BFcalls, index2419clamp80/byteMULDH/fiveSHR/45BFthenJMP4612, fullSS/CFIFDF andactualrootRET2. Actual403B/statusFLAGS/writers/units/lifetime/core open.',

        '06C9:4588':'AdditionalfullSS/GPR/BP/CFIFDFnear4588 raw332C/signed336C/sub200-clamp800-oradd600 effects; actual5A6F/44EAstatussetters reviewed, wholecaller/writers/lifetime/core open.',
        '06C9:44D8':'DX1600/JMP45FC, fullSS actual460EnearCALL4612 andrawRET; flag/fieldframealiases retained, actualcaller/writer/lifetime/core open.',
        '06C9:45FC':'Raw52CEsaturatingsubtraction, optionalactual460EnearCALL4612/fullSS, rawCF/RET; actualcaller/writer/lifetime/core open.',
        '06C9:45BF':'RawDX/scaledDS324Abyteview indexAH>>2 0..63 RS267, FFshortcutretainsDX, actualSS/CFIFDF/4612nestedframe; values/units/writers/lifetime/core open.',
        '06C9:4612':'Raw3328*52CE unsignedproduct/clamphigh800/332Cstore, actualSSnearRET/CFIFDF; ownframecanchangeguard2F56 orbeoverwritten. Actualcaller/writers/lifetime/core open.',

        '13A8:2AD8':'Actual13A8:2AD8/oneSSword, oneorthreeactualfar225E calls withliteralpools/SSlocals/saves, bothFFFFearlysentinel, secondresultsaved/thirdresultignored, fullreturnedBP-SI-DS-CFIFDF, callerADDSP8 andactualPOP SI/MOVSPBP/POPBP/plainfarRET4. Actual043204F1/handlewriters/ownership/lifetime/core/DOS remainopen.',
        '13A8:225E':'Actual13A8:225E/fourSSwords rawhandle-offsetlow-high-mode, unsignedlimit/negativepreflight, syntheticDOS42query-end-restore-finalseek withactualreturnedstate/SSlocals/ignoredCF paths, returnedDS-BXbitclear, actual094A/shared0937tail/MOVSPreturnedBP/POPBP/plainfarRET4. Actual0C4E-2AD8/handlewriters/ownership/lifetime/core/DOS remainopen.',
        '13A8:223E':'Actual13A8:223E/oneSSword rawhandle, unsigned6DA2guard/AX0900error, syntheticDOS3E fullreturnedGPR/BP/DS/CFIFDF, successbyteclearatreturnedDS:BX+6DA4, actualnear094A/shared0924-0939tail/MOVSPreturnedBP/POPBP/plainfarRET4. Actual0978/handlewriters/ownership/lifetime/core/DOS remainopen.',
        '06C9:5880':'Actualnear5880/noSSargs, sixnearCALLsites composeactual5299/5C5A/52FD twice/optional5334/535B, rawtable/field/threshold effects, orderedrereads/byte336Cguard andsignedwrapped52CCstep44/clamp/store, actualSSframes/RET2. Actual403B/44EA/writer/bounds/lifetime/core open.',
        '06C9:595F':'Actualnear595F/noSSargs, threeconditionalactualnear5A25 pairupdate calls, fullreturnedGPR/BP/CFIFDF, returnedCXstores334A/C/E, CF-JB andsignedBX/CXbranches, orderedpair/flag/counterwrites andsevennearRET2sites. Actual403B/IFDF/writer/lifetime/core open.',
        '06C9:4D3F':'Actualnear4D3F/noSSargs, two do-once8byte DSrecord loops, ten actualnear4F92/5022/5446 C calls, literalSSPUSHF/POPFword withsource-definedflags/explicitundefinedAF input, actualZF consumers androotRET2. Actual403B/CPUprofilebinding/writer/lifetime/core open.',
        '13A8:2E42':'FourSSoperandwords rewritten tomagnitudes, signedquotient via two wordDIVs orSHR-RCR normalize/actual2EE8 C multiply withSSABI/productcorrection; signxor/rawINT_MIN/-1wrap, actualSSsaves andliteralRETF8 consumingfourargs+farframe. 17directarithFLAGSedges reviewed; wholecaller/storage/lifetime/exception/core open.',
        '13A8:2F1C':'FourSSoperandwords rewritten tomagnitudes, signedremainder via two wordDIVs orSHR-RCR normalize/actual2EE8 C multiply withSSABI/correctedproduct-minus-numerator/signprocedure; numerator-sign only, actualSSsaves/literalRETF8. 17directarithFLAGSedges reviewed; wholecaller/storage/lifetime/exception/core open.',
        '13A8:184A':'OneSSword rawindex/FFFFguard/DS[BX+6F57]bit4, actualPUSHCS+nearCALL190E/RETF, sourceORAXBoolean0/1, CF0 andactualSSBP/plainfarRET4; callerowns2argbytes. Wholecaller/type/bounds/writer/lifetime/core open.',
        '13A8:0DF0':'OneSSnearrecord, byte+6mask83/8 guards, actualfar2696 withword+4, sourceflagF7/AX0/orderedrecordbase,+4,+2 zero stores. Guardskip preservesincomingAX, actualSSSI/BP/plainfarRET4/caller2argbytes. Wholecaller/type/bounds/writer/lifetime/core open.',
        '019E:0004':'019E0004 far/noargs, actual780E byte-ring C transformation with sourceSSABI adapter/actualframes, one sample then mask7/wordCWD/eight instruction-immediate SSword selections, actualSSBP restoration/plainfarRET4. Two actualcaller farframes includingPUSHCS+nearCALL reviewed. Sharedringwriter/reset/reentry/lifetime/wholeconsumption/core open.',
        '06C9:C838':'FourSSwords headerOff/Seg,scratchOff/Seg; actualC701 normalizedfar member, explicit DS header/principal/member/scratch transitions, raw shapes/nibblemask/fourplanes/orderedcolumn transpose andcopyback with incomingDF, realSSlocals/saves/farframes/plainfarRET4/caller8argbytes. Actual1748scratchnormaloffset0/1F6paragraphs; final6D50pass/format/capacity/writer/lifetime/core open.',
        '06C9:5ADA':'NoSSargs far5ADA, actualPUSHSI/DI/BP, two actualnear5B5A calls overDS39A3/3813, two or fouractual5C30 calls with source-order count/position rereads and selectedSI-base stores330E/330C/3312/3310; actualnearframes/POPBP-DI-SI/plainfarRET4. Actual1B2C/writer/capacity/lifetime/core open.',
        '13A8:29D0':'ThreeSSwords value16/destNear/radix; decimal-only wordCWD/sign prefix, actualshared2BBC rawlongdivision/digitbytewrap/CLD/do-once reversal/actualSSsaves/plainfarRET4; callerowns6argbytes. Actualcaller/capacity/writer/lifetime/core open.',
        '13A8:29EC':'FourSSwords valueLow/valueHigh/destNear/radix; signprefixdisabled includingdecimal, actualshared2BBC rawlongdivision/digitbytewrap/CLD/do-once reversal/actualSSsaves/plainfarRET4; callerowns8argbytes. Actualcaller/capacity/writer/lifetime/core open.',
        '06C9:5299':'Four ten-stride DS record bytes, signed first-byte stores3340/42, 7F mask/wordCBW/twoSHL/strided table347F and alwaysNEG AL from retained SHL flags, unsigned byte max then byteabs/wordtable32EE/AL*DI.low; POPBX=savedfirstAX, DS3344=product, CF=MUL highbyte. Caller/writer/units/capacity/lifetime/core open.',
        '06C9:5022':'Backward -8 DS39A5/7 records, origin/end5356 and signed lowSUB/highSBB branches, modulo/angular guards, ordered updates, BP wrapping count and raw fallbackSI. NearRET2. Caller/writer/units/capacity/lifetime/core open.',
        '06C9:5446':'Loads raw AX/DX/BP/DI fields, initializes334C/33B8/334E, two -8 DS39A5/3815 ring walks with signed SBB/26 guards, stores3316/3314 and52D8..DE/33BA. NearRET2. Caller/writer/units/capacity/lifetime/core open.',
        '06C9:4F92':'Explicit DS:[BP+SI] records, initial signedSBB<=0 vs subsequent<0 correction, angular/reject guards, ordered forward-ring updates, actualSS SIsave/restore updating path, skip increments; nearRET2. Caller/writer/units/capacity/lifetime/core open. AdditionaldefinedreturnFLAGS/mask/ret-site viewproved; undefinedAF excluded. RawPUSHF/POPF callercontract stillopen.',
        '06C9:5B5A':'Explicit DS:[BP+SI] records, raw initial unsigned60 and subsequent signed forward/backward SBB guards, ordered updates/modulo corrections and ring ends. AX/DX reloaded before backward pass; nearRET2. Caller/writer/units/capacity/lifetime/core open.',
        '06C9:C6C5':'Two SS words raw low/high offset; actual C692 CLI/read DS5E90/92/STI/RETF, ordered ADD/ADC SS-local target, high AND low unsigned guards, actual SS frames/saves and plain far RETF consuming4/caller owns4 argument bytes. TransitiveDS/writer/IRQ lifetime/core remain open; raw units unassigned.',
        '06C9:C701':'ThreeSSwords headerOffset/headerSegment/index: ES:SI+4headerword, ESabsolute wordtable4*N+4*index+6, wordbase8*N+6 truncation, two separatelywrappedtablewords/raw32bitadd/4SHR-RCR ->AXnibble/DXnormalizedsegment/CFlinearbit3. ActualSSBP-SIsaves/plainfarRETF4/caller6bytescleanup. C838actualfarconsumer reviewed; producer/header/table/bounds/writer/lifetime/core open',
        '06C9:08CB':'08CB twoflagmasks88/C0 atcurrentDS133C, signedAX/SI/fieldcomparisons, rawAXclamps andunsignedlastcomparisonCF. Negative/signedboundaries andflags interactions retained; nofieldunits inferred. NearRET2/noargs. Actualcaller/FLAGS/fieldunits/bounds/writer/lifetime/core open',
        '06C9:52FD':'52FDsignedSUB/JLE usesOFcorrectly beforewrappedCXcompares. AdjacentJLE/JG arecomplementarywithoutflagsetter,5303unreachablefromthisentry (notglobaldead). RawAX-BX/AX+5wordwrap, bytequotientguard, finalXORAHclearsCF; nearRET2. Actualcaller/FLAGS/fieldunits/bounds/writer/lifetime/core open',
        '0432:0061':'0432:0061 SSlocalcounter/nearargument: underscore->space whileunboundedscan, thenSIGNEDcounter<18 padding. ReadSScounter andargument again aftereachwrite; aliases maychange count/pointer/returnframe. Long>=18nottruncated; negativecounterwrap retainsrawpadding. AXunchanged, BXfinalcounter, actualSI/BPsaves/farRET4/callerclean. Actualcaller/FLAGS/fieldunits/bounds/writer/lifetime/core open',

        '13A8:0F16':'0F16incrementsDS6DF2 afterSSnearptrread. Special6DFC/6E04/6E14flagguards, signedbyteatrecord+7 signextends/word*6intoDI, sideflag6E94 andword6E96; orderednear8440/count200/flags setup. SecondfamilyguardDS6E00!=8440 andstores signedflagsword83D4. AX1/0CF0, SI/DI/BPactualSSrestored/plainfarRET4. Actualcaller/index/handle/writer/lifetime/core open',
        '13A8:2170':'2170 loadsCLfromSSargumentlowbyte, CHpreserved, SI6F1E andexplicitINCSI independentofDF. NULcheck precedescomparison, requestedzero returnsAX0. MatchAX1/nonmatchAX0, plainfarRET4/callerclean; rawmissingNUL/missingbyte maycycle. Actualcaller/index/handle/writer/lifetime/core open',
        '13A8:219A':'219A SI6DF4/CXcurrentDS6F0C; TESTbyte+6 mask83 choosesfirstfree. Orderedcount+2zero/flag+6zero/base+4zero/basezero/index+7FF reset, AXnearoffset. UsedrecordcopiesoldSIintoAX, advancesSI8, thenCMPoldSIend; inclusiveold-SItest, unalignedend maycycle. AX0ifusedend reached, CF0/plainfarRET4. Actualcaller/index/handle/writer/lifetime/core open',

        '13A8:0599':'0599actualtwoempty060Dnearwalks/066EfullAXguard/SSexitword00FFconditional, rawCX15/BX5flaggedDOS3Eloop withreturnedcountereffects, actualnear05E0cleanup, thenpreparedINT21/AH4Cboundary. Noactualprocess exit ornormalrootRET invented. Actualcaller/source/target/writer/lifetime/core/realDOS acceptance open',
        '13A8:05E0':'Near05E0 optionalDS7076:7078farservice/BX2, PUSHDS/LDS6D89/AX2500syntheticDOS, actualSSPOPDS/guard6DC6 thenoptionalAL6DC7/LDS6DC8/AH25service/POPDS/nearRET2. Orderedpost-PUSHaliases/savedDSmutations/fullreturnedGPR/BP/CFIFDF retained. Actualcaller/vectorwriters/callback/lifetime/IRQ/core open',
        '13A8:0620':'0620actual08B7messageFC/RETF2, then currentDS6DCEsegment-onlyguard and optionalfar[6DCC], thenactualmessageFF/RETF2. Callbackoffsetzero remainsvalid ifsegmentnonzero. RootMOVSPreturnedBP/POPBP/plainfarRETF4; noargumentcleanup. Actualsource/callback/writer/catalog/lifetime/core open',
        '13A8:066E':'066EPUSHSI/XORSI/CX42/CLD, XOR66currentDSbytesintoAH, thenAH^55. AHzero branchretainslastbyteinAL, soAX00last notBoolean. OnAHnonzero actual0620farcall thenactualmessage1 andMOVAX1. POPSI/plainfarRETF4. Actualsource/callback/writer/catalog/lifetime/core open',

        '13A8:088C':'088C capturescurrentDSintoES, scansrawwordID/string sequence at82C4 with incomingDF, CMPmatch precedes INCFFFFendtest. XCHGreturnsrawpostLODSoffset orzero; SI/DI/BP restoredfromactualSS. LiteralRETF2callee cleanup. RS264prefix only, catalogend/key/NUL/DF/writer/lifetime/core open',
        '13A8:08B7':'08B7 materializesargument/far08C3frame andexecutes088C, testsAX, scansES:DI unchangedDF up toFFFF, NOTCX/DECCX length, BX2/AH40 syntheticDOSwrite. ReturnedBPfeedsMOVSP, actualSSDI/BP/rootwords andliteralRETF2. RS264prefix only, catalogend/key/NUL/DF/writer/lifetime/core open',

        '13A8:060D':'Near reversecallbacklist: unsignedSI<DI, DI-=4, separatecurrentDSwordORskip, actualfar[DS:DI]CALL/CS-061Dframe, fullreturnedcallbackGPR/BP/CFIFDF/DS/positions feedrepeat; rootnearRET2. SyntheticcallbackABI, notoriginalcallee/targetdomain proof. Sixfixedcaller contexts/initialtarget0A3A/allwriters/lifetime/core open',
        '13A8:2E20':'One SS near filename/currentDS, DOS41 thenshared0924success AX0/CF0 or actualnear094Aerror mapper/0939tail AXFFFF/DXFFFF/mapperCF; returnedBP MOVSP/actualSSsaved/rootwords andplainfarRETF4/caller-clean. Rawoverwrittenchildnearreturn exposednotfollowed. Actualcaller filenamebounds/FLAGS/writer/lifetime/core open',
        '06C9:5C30':'5C30 shifts incomingCX right3 then do-once scans eight-byte records at currentDS:SI. LowwordSUB feeds highwordSBB; signednegative correction usesDS380D, unsigned <=best selects latest tie. SI+8 sets finalCF, LOOPzero=65536, SI=DI, BP clobbered. Nearreturn. Actualcaller/writer/FLAGS/lifetime/core open',
        '0143:019E':'0143:019E incrementsDS02DE and83C8, signedclamps02DEat200 thenwordCWD/IDIV20 andaddquotientto02E0. SecondwordIDIVby83CA mayfaultzero/overflow; remainderzero increments/clamps83CCagainst83CE. Farreturn; subsequentdefinedADD/OR/CMP establishesCF, undefinedIDIVflags unadmitted. Actualcaller/writer/FLAGS/lifetime/core open',
        '06C9:5A25':'5A25 tests bothpairhighwords nonzero, lowSUB/highSBB thenDEC/XORsigngate, rawDX+180/-360 signedguards. Selects sourcehigh+1 or-1 bysignedBX, writesdestinationhigh before rereading sourcelow andwritingdestinationlow. CF1success/0reject, nearreturn. Actualcaller/writer/FLAGS/lifetime/core open',
        '06C9:5C5A':'5C5A rawBX comparedwithDS380F+3B42; SI*SI unsignedwordMUL, highwordtripled asDX:AX, DIVDI mayfaultzero/overflow, quotientSHR1 thenremainingdistancecompare. RejectwritesDS3344zero andAL1 preservingAH; acceptAX0. Nearreturn. Actualcaller/writer/FLAGS/lifetime/core open',

        '13A8:094A':'094A stores incomingAL atDS6DA0. AHnonzero becomes signedAX directly; otherwise versionbyte6D9D changes raw error-code clamp/remap then XLAT6DDA, word CBW andstore6D95. Near return. Actualcaller/writer/FLAGS/lifetime/core open',
        '13A8:2D57':'ActualSS2D57-2C1C-29F6/currentCSsixkeylookup-literalnearworddispatch/currentDS7058handlers-distinctDS7076guard-SS707Efallback/liveSSpointerrereads-beforeCALL/retiredhandlercontrol/actualmessage-exitbodies/RETF2-vsplainfarcleanup/fullRAM-GPR-BP-CFIFDF-definedFLAGS.4990cases/445916instructions/93executedfamilyof97/208of228union/35native; prepared2C31-05DEand3postterminalwrapper-sites qualified.1458genericcallbackRETFs separate/notbodyproof. Actualcaller-allwriters-validtargets-lifetime-IRQexclusion/fullfatalcaller-B0FEarena/core/P1-GATE unproved.',
        '13A3:0012':'13A3:0012 unprefixed98 signextendsAL; absolute value then signed BL compare5A, raw foldB4-BL onlyifBLsigned>5A. AL80 keepsindex128. ReadsDS54AA+2index, conditionalwordNEG, preservesBX/DXviaactualSSsaves/farreturn. Actualcaller/writer/FLAGS/lifetime/core open',
        '06C9:5334':'5334 signedBX<-400 or>800 skipsupdate; signedranges[-400,-1]/[0,399]/[400,800] selectDS333E/3340/3342, updateonlysignedAX<word. Nearreturn. Actualcaller/writer/FLAGS/lifetime/core open',
        '06C9:535B':'535B signedmaxof333E/3340 choosesCXFF38/C8; bit80of33BE and3342comparisonmaychooseCX258 withoutDXupdate. SignedAX<-40,[-40,40],[41,359],[360,440],>440 selectDX333E/100/100/3340/3342. Nearreturn. Actualcaller/writer/FLAGS/lifetime/core open',

        '13A8:2916':'Two SS near offsets/currentDS; scan destination and source CXFFFF/incomingDF, raw tail/source computation, reread destination, source-parity peel/word/residual-byte copy; plain far RET4/caller-clean. Actual caller bounds/NUL/DF/FLAGS/lifetime/core open',
        '13A8:2956':'Two SS near offsets/currentDS; scan source CXFFFF/incomingDF then read destination, destination-parity peel/word/residual-byte copy; plain far RET4/caller-clean. Actual caller bounds/NUL/DF/FLAGS/lifetime/core open',
        '13A8:2988':'Two SS near offsets/currentDS; scan second string CXFFFF/incomingDF then DI-count regardless ofDF, counted REPECMPSB; AX0/CF0 equal, AX1/FFFF andCF1 mismatch; plain far RET4/caller-clean. Actual caller bounds/NUL/DF/FLAGS/lifetime/core open',
        '13A8:2B40':'Two SS near offsets/currentDS; BX+1 versus LODSB SI followsDF, differing byte ASCII41..5A folds, CL first-byte mask, unprefixed98 signextendsAL; plain far RET4/caller-clean. Actual caller bounds/NUL/DF/FLAGS/lifetime/core open',
        '13A8:2B82':'Three SS words nearDestination/lowByte/count in currentDS; incomingDF byte/word fill, AXdestination/DIrestoredviaDX, zero count incomingCF andBXincomingDS, nonzeroCF0/BXrepeatedByte; plain far RET4/caller-clean. Actual caller bounds/NUL/DF/FLAGS/lifetime/core open',

        '13A8:29B4':'Current DS near string REPNE SCASB FFFF/incoming DF/word wrap, AX count and last comparison CF; caller bounds/NUL/DF/lifetime open',
        '16AA:0002':'SSargumentlowbyteASCIIcase/inplacesubtract/AXsignextension with16bit98; highargbyte/upperEAX preserved, originalCtype/callerFLAGS open',
        '13A8:2A18':'SSsignedindex/currentDS6DA2limit/nonnegative thennearbyte6DA4bit40 ->AX0/1; tableformat/bounds/lifetime open',
        '13A8:190E':'CurrentDS83E4flag/signedpositive83DAcounter decrement ->AX0/1, rawunits/writers/lifetime open',
        '0432:1D25':'RawcurrentDS8A22indexedzero/8A22-8A8Czero then8C9Eread->8A1C, SHLcarry/postwritealiases; actualbounds/writers/lifetime open',

        '13A8:2FD0':'SSnearPointer/countWord/currentDS32bitwordpair, actual2FC4CL-byte shift/reread/stores, literalRETFimm4 callee-clean; 155CcallerDS-SS/bounds/FLAGS/lifetime open',
        '06C9:6A30':'Actual69FEuntilfullAXnonzero/AH-onlyaccepted, materializedfarframes; actualinputtarget/writers/lifetime open',
        '06C9:6A4A':'Actualinput69FE/79C8ownedpair thenDS6818/1Aunsignedlexbound; writer/lifetime/IRQ/units open',
        '06C9:7A3B':'Singleactual79C8/DS6818/1AunsignedlexpredicateAX0/1; rawcounterwriter/lifetime/units open',
        '06C9:C63E':'Actualinput69FE/C692pair thenDS68D8highAND68D6low, distinctfromlex; actualwriter/lifetime/IRQ/units open',

        '06C9:7866':'FiveSSword nearfilename/farbuffer/32bitlength writer; lengthdecrement-beforeDOS40/segmentadvance/16A7:0002 rawerrorcallboundary, FN348/producer/lifetime open',
        '06C9:7874':'Optionalrawcreate/write/close wrapper, staleSShandlecloseafterCREATEerror/ignoredcloseCF/shortcount, callerlengthmutations; actualDOS/capacity/lifetime open',
        '06C9:5DFB':'FourSSwords orderedread/write ->CSAF46/48/4A/4C rawbounds, DFpreserved/SS-CS aliases; allactualwriters/bounds/lifetimes open',
        '06C9:78F8':'OneSSnear-destination/currentDS <-26forwardCSAF3Awords, ES capturesDS/CLD/rawreturnaliases; outputcapacity/writer/lifetime open',
        '06C9:3EFC':'CurrentDS9B4/9B2 orderedfar-sourcepool ->actual7D5E/CScopy, fullnestedSSframes/ADDSP4/RETF4; rawchildreturnaliases explicit, producer/capacity/writer/lifetime open',
        '06C9:5D01':'FiveSSwords bytefarcopy, CLD/REP0zero/forwardaliasorder, actualsource/destcapacity/lifetime open',
        '06C9:7D5E':'TwoSSword far-source ->13words currentCSAF3A configuration inclplane/clip/offset/stride;61directsites/actualproducer/writers/lifetime open',
        '06C9:7918':'OneSSnear-source/currentDS ->26words currentCSAF3A configuration;6directsites/actualproducer/writers/lifetime open',

        '06C9:5D4E':'RawDOS19/0E servicepair AL->DL/AH0; actualdrive/service/caller domains open',
        '06C9:5D74':'RawBIOS11 responseALhighbits/CL6 ->AX2..4; actualhardware/caller domains open',
        '13A8:2E2E':'RawDOS19 ->incrementAL word atreturnedDS/SSnearoffset viareturnedBP, AX0; actualservice/ownership open',
        '06C9:5D5B':'RawDOS4301/CX2 nearpathDS:DX, CF->AX1/0; actualfile/path/service domains open',
        '06C9:5D2E':'RawBIOS1A responseCX/DX masks ->currentDS52C2/52C4, nearoffset52C2; DATalias/writers/units open',

        '06C9:5D83':'LiteralES0040:046C physical086C rawread; nofrequency/sourcewriter/unitsassignment',
        '06C9:5D8D':'OneSSword rawsubtractfromliteralphysical086C, currentES0040; units/writers/callers open',
        '06C9:C692':'CurrentDS5E90/92 rawpair read underCLI/STI/IF1; noactualIRQexclusion',
        '06C9:C69C':'ActualC692 plusSSdelta ADD/ADC ->currentDS68D6/68D8; ownership/units/exclusion open',
        '06C9:7A82':'TwoSSwords orderedpairedstate6822then6820; actualbyteconsumers excludeautomaticfarptrtyping',
        '13A8:246B':'CurrentDS6D97 complement/ANDCX andALbit7 ->CX0/1, nearRET2',
        '13A8:2696':'SSnearoffsetBX, conditionalORbytecurrentDS[BX-2],1; writer/lifetime domains open',
        '0267:0004':'SSargument1 choosesAXnearoffset7738 otherwise7739; sourceCtype/actualDS/resource meaning open',
        '13A8:2682':'RawcurrentDS6DD4 versuspostpopSP; preservespoppedfarreturnIP/CS inCX/DX',
        '06C9:7AA4':'22opaque currentDS6820 bytes ->SS-suppliednear destination by11forwardwords; source/capacity/lifetime open',
        '06C9:7ABD':'SS-suppliednear source ->22opaque currentDS6820 bytes by11forwardwords; aliases/writers/lifetime open',

        '06C9:7DBC':'TwoSSword farptr/headercoords, AND RAM logic/explicit hardwaremode8/sharedcopykernels/near masks; actualcaller/writers/device/core open',
        '06C9:A718':'TwoSSword farptr/headercoords, OR RAM logic/explicit hardwaremode10/sharedcopykernels/near masks; actualcaller/writers/device/core open',
        '06C9:BB08':'Verified explicit XOR root/twoSSword farptr/headercoords, XORRAM/distincthardware kernels/near masks; actualcaller-reachability/writers/device/core open',
        '06C9:916C':'FourSSwords sourcefarptr/xyminusheaderorigin, DSsource/SSframevectors/CSnibblemaps-copytables, actualnear-maskhelpers/explicitbytebus; allwriter/capacity/device/renderer gatesopen',
        '06C9:91A4':'FourSSwords sourcefarptr/directxy, sharedsprite-copybody/materializedframe andrawunsupportedtarget transport; source/header/table bounds andotherfamilies pending',
        '06C9:91D6':'TwoSSwords sourcefarptr/header+8-Acoords, sharedcopybody/near-maskcalls/farRETF4; nofour-argassumption, actualcaller/resource/device/core gatesopen',
        '06C9:82D0':'RAMAND implicitmaskhelper/rawBX-CSmask/byteDLoverflow/LOOP-REP-DEC/DFdistinctions, exactregister-bytebus effects; actualspritecaller/writers/bounds/device/renderer pending',
        '06C9:8336':'RAMOR implicitmaskhelper/rawBX-CSmask/byteDLoverflow/LOOP-REP-DEC/DFdistinctions, exactregister-bytebus effects; actualspritecaller/writers/bounds/device/renderer pending',
        '06C9:839C':'RAMXOR implicitmaskhelper/rawBX-CSmask/byteDLoverflow/LOOP-REP-DEC/DFdistinctions, exactregister-bytebus effects; actualspritecaller/writers/bounds/device/renderer pending',
        '06C9:AD22':'deviceAND implicitmaskhelper/rawBX-CSmask/byteDLoverflow/LOOP-REP-DEC/DFdistinctions, exactregister-bytebus effects; actualspritecaller/writers/bounds/device/renderer pending',
        '06C9:AD8B':'deviceOR implicitmaskhelper/rawBX-CSmask/byteDLoverflow/LOOP-REP-DEC/DFdistinctions, exactregister-bytebus effects; actualspritecaller/writers/bounds/device/renderer pending',
        '06C9:ADF4':'deviceXOR implicitmaskhelper/rawBX-CSmask/byteDLoverflow/LOOP-REP-DEC/DFdistinctions, exactregister-bytebus effects; actualspritecaller/writers/bounds/device/renderer pending',
        '06C9:89A2':'ClippedSSfivewordrectangleargs mutatedinplace, shared8A0Cbody/DSedge masks/currentCSplane-offset-stride/explicitsyntheticbus; actualcaller/device/resourcebounds pending',
        '06C9:8A0C':'RawSSrectangleargs/sharedCLD/signedextentchecks, DS6838/6840masks index&7, wideRAMcallercolorbyteSHR/highbytepreserved, orderedRAM/OUT/MMIO traces; noactualrenderer/device acceptance',
        '06C9:8582':'SSfivewordlineargs/locals, bodyDS=CS/CSclip-plane-offsetdata and8externalCS857Amaskbytes, twofar8A0CABI leaves; rawRAMplanes orsyntheticOUT/MMIO events, noactualdevice/renderer/resourcecapacity acceptance',
        '06C9:0C17':'CurrentDS four16byte palettes withBX&15, maskSS[BP+5468], currentDS plane words/orderedbytewrites, rawDS0702nearcontinuation; actualview/allwriter/capacity/IRQ proofopen',
        '06C9:284F':'CurrentDS rawrowfields, initialCSlookup/ESload/CLD, actualC17SSmask/plane writes and28BDdiscarded-returncontinuations; rawSI!=34 loop, producer/resourcebounds open',
        '06C9:28F9':'TemporarilySHL sharedDS2C30, signedrowloop withcurrentDS fields andD01ABImocks, rereadSHR; actualproducer/leaf/outputbounds pending',
        '06C9:26D8':'Rawflag/owner/extent orchestration, fiveword89A2 andfourprepared4word916C pools; actualresource/source/leaf/bounds pending',
        '06C9:34DC':'CurrentDSwrappedSI height/width/endpoints, unsignedhalfwidth, raw2C2A-5 override, twoorthreeprepared5word8582 pools; actualcaller/leaf/bounds pending',
        '06C9:06C3':'NearRET6 consumes3wordargs, DS5348/ESwordoutput plusorderedCS071F-0735 INC-DECpatches; boundednativebody/orderedpatchprefixes compared, actualcallerbounds/IRQtransition domain pending',
        '06C9:2477':'SIcurrentDS vsBPpreviousSS fields, ESDS/outputarrays and15wordargumentstack consumedbyfive06C3RET6calls; bounded2477+06C3nativecompositionpassed, actualDS-SS/caller bounds pending',
        '06C9:21C3':'25backwardrawbytes/128maskeddescriptor records/currentDS weight-lookup-list consumers, signedADD-JGE/IMUL-IDIVfaultprefixes; raw2C2A writer, actualcaller/schema/units/rendering pending',
        '13A3:0038':'SignedALabsindex0..128 intoDS5560wordtable, wrappednegativeoutput; tablevalues/physicalfunctionmeaning/writers pending',
        '06C9:088E':'SignedDSwordclamp orderedfivepasses, BX5348captured, LOOPzero65536 andnearRET. Actual1F71AX2C2A/BP17/precedingwriters/SSframeexclusion pending; no renderer/resourceacceptance',
        '06C9:1F60':'DS2A20/22 farpair consumer782C/caller-cleanargs, actualsource/lifetime pending',
        '06C9:1F71':'Near21C3/2477/2542/088E orchestration, raw5348/2C2A fields andsavedSI-DS-BP; actualnear/graphics bodies pending',
        '06C9:1F99':'CurrentCSAF3C..42 graphicsfields/currentDSgates/pairs andpaired5+5word drawingcalls, near/farframes retained; actualbodies/writers/resourcebounds pending',
        '06C9:2089':'CurrentDSrecord/filter/output preparation;1E59usesSS, actualsamerecordcaller relation pending. NEG-JGE8000/unsignedfilter/do-once extentloops anduncheckedindexedaliases retained; resourcebounds/units/graphics pending',
        '06C9:7A10':'Rawcounter snapshot thenSSdistance ADDADC/CF andorderedDS6818/A deadlinepublication; argumentaliases retained, no unit/rate/IRQ admission',
        '06C9:7A27':'Repeatedrawcounter snapshot versuscurrentDS6818/A globaldeadline unsignedcompare; writerchanges retained, no fixedlocaldeadline/clockhistory admission',
        '06C9:ABFA':'Raw BIOS10AX1002 ESincomingDS/DXnearSSargument wrapper, BP restored; blockextent/meaning/device pending.3532near2E08/2E10 are notestablishedtext',
        '06C9:3532':'SSindexedcount/point source versusDSglobals, retainedAHsecondpoint, bytezero256iterations, seveniterations/pairedfarargs; actualgraphics/resources/caller bounds pending',
        '06C9:3643':'Ten rawcounteriterations, DItable/resourcepairs, paired80CA-AA12args, nestedactual5C98 andsavedSI; actualgraphics/resources/units/caller bounds pending',
        '06C9:69FE':'CurrentDS64DC/DE dynamicfarcall; arbitrary setters prevent complete target admission, serializedbodyonly',
        '06C9:6A03':'BIOS16 query/consume, ASCIIlowbyte clearsAH andextendedzeroAL retainsAH; explicitZF/CFIFDF, 3450actualinstalled69B7compositions separate; actualdevice/targetlifetime pending',
        '06C9:6A17':'Ordered offset/segment setter, firstwritebeforesecondSSargumentread, noCLI/atomicity; caller/IRQlifetime pending',
        '06C9:6A28':'CurrentDSfarinputpair getterAXoffset/DXsegment; noCLI/atomicity',
        '06C9:6A3B':'BIOS16 drainuntilqueryZFempty, continuousinputmaynotreturn; actualdevice/inputsession pending',
        '06C9:375F':'Near caption2F13/2F27 andformatter destination2F20/format2F24/counter8424; overlapping span/output bounds andrealformatterDS-SS remainopen',
        '16AB:000C':'Near currentDS text argument passed to13A8:29B4 length candidate; actual glyph/layout/body contract pending',
        '13A8:2A3C':'Near destination/format/variadic wrapper with BP-defaultSS andDI-defaultDS frame accesses; DS=SS orprovedcorrespondingviews/output extent pending'
    })
    selected.update({
        '06C9:601C':'AdditionalactualSS601C-6059-610A/currentDS/fullGPR-BP-CFIFDF-definedFLAGS; literalSSargument reread afterquotientpublications, separateIVTguards, actualsavedBP/farRET, orderedports andwholeRAM/CPUwrites. F72ApostIDIVprefix doesnotexposeCF. Nativebudget-portfailure-preIDIV-preRET boundaries distinctfromsourceerrors. No timeunits/physical086Csemantics/realIRQ-allwriters-reset-lifetime-nativeproducer/core/P1-GATE acceptance.',
        '06C9:6059':'AdditionalactualSS601C-6059-610A/currentDS/fullGPR-BP-CFIFDF-definedFLAGS; literalSSargument reread afterquotientpublications, separateIVTguards, actualsavedBP/farRET, orderedports andwholeRAM/CPUwrites. F72ApostIDIVprefix doesnotexposeCF. Nativebudget-portfailure-preIDIV-preRET boundaries distinctfromsourceerrors. No timeunits/physical086Csemantics/realIRQ-allwriters-reset-lifetime-nativeproducer/core/P1-GATE acceptance.',
        '06C9:610A':'AdditionalactualSS601C-6059-610A/currentDS/fullGPR-BP-CFIFDF-definedFLAGS; literalSSargument reread afterquotientpublications, separateIVTguards, actualsavedBP/farRET, orderedports andwholeRAM/CPUwrites. F72ApostIDIVprefix doesnotexposeCF. Nativebudget-portfailure-preIDIV-preRET boundaries distinctfromsourceerrors. No timeunits/physical086Csemantics/realIRQ-allwriters-reset-lifetime-nativeproducer/core/P1-GATE acceptance.',
    })
    selected.update({
        '06C9:614C':'AdditionalactualSS614C-6180/wholeRAM-GPR-BP-CFIFDF-definedFLAGS/liveargumentrereads/orderedmetadatawrites/actualfarRET. Addunmaskedpublication6176-before6179retained;60IF1stalesentinelprefixwitnesses are serialized/notactualIRQfeasibility. MatchedremoveCLI-STI/unmatchedIF preserved.46executedsites/6164preCALLfatalboundarywithPUSHAX/relocatedtarget; actualfatalcallee/allwriters-reset-lifetime-exclusion-nativeproducer-core/P1-GATE remainopen.',
        '06C9:6180':'AdditionalactualSS614C-6180/wholeRAM-GPR-BP-CFIFDF-definedFLAGS/liveargumentrereads/orderedmetadatawrites/actualfarRET. Addunmaskedpublication6176-before6179retained;60IF1stalesentinelprefixwitnesses are serialized/notactualIRQfeasibility. MatchedremoveCLI-STI/unmatchedIF preserved.46executedsites/6164preCALLfatalboundarywithPUSHAX/relocatedtarget; actualfatalcallee/allwriters-reset-lifetime-exclusion-nativeproducer-core/P1-GATE remainopen.',
    })
    selected.update({'06C9:3F40':'Additionalwhole3F40-3FF9-38F2-1E31-near5427 actualSS/fullGPR-BP-CFIFDF-definedFLAGS/orderedprefixwrites-liveSSCALLframes/partialREP-fold-prefixes/current3811wrap/live23C6-C8bounds/frozennative601C-614CtailwithoutextraCALL.10546cases/3194962instructions/187admittedsites+6164fatalpreCALL/34nativechecks.168conditionalSSringwrites arenotintentionalreset-seeding/RNGpurpose oractualstackdomainproof; caller-allwriters-reset-lifetime-IRQexclusion/startup-to-exit-core/P1-GATE remainopen.'})
    selected.update({
        '06C9:3FF9':'Additionalwhole3F40-3FF9-38F2-1E31-near5427 actualSS/fullGPR-BP-CFIFDF-definedFLAGS/orderedprefixwrites-liveSSCALLframes/partialREP-fold-prefixes/current3811wrap/live23C6-C8bounds/frozennative601C-614CtailwithoutextraCALL.10546cases/3194962instructions/187admittedsites+6164fatalpreCALL/34nativechecks.168conditionalSSringwrites arenotintentionalreset-seeding/RNGpurpose oractualstackdomainproof; caller-allwriters-reset-lifetime-IRQexclusion/startup-to-exit-core/P1-GATE remainopen.',
        '06C9:38F2':'Additionalwhole3F40-3FF9-38F2-1E31-near5427 actualSS/fullGPR-BP-CFIFDF-definedFLAGS/orderedprefixwrites-liveSSCALLframes/partialREP-fold-prefixes/current3811wrap/live23C6-C8bounds/frozennative601C-614CtailwithoutextraCALL.10546cases/3194962instructions/187admittedsites+6164fatalpreCALL/34nativechecks.168conditionalSSringwrites arenotintentionalreset-seeding/RNGpurpose oractualstackdomainproof; caller-allwriters-reset-lifetime-IRQexclusion/startup-to-exit-core/P1-GATE remainopen.',
        '06C9:1E31':'Additionalwhole3F40-3FF9-38F2-1E31-near5427 actualSS/fullGPR-BP-CFIFDF-definedFLAGS/orderedprefixwrites-liveSSCALLframes/partialREP-fold-prefixes/current3811wrap/live23C6-C8bounds/frozennative601C-614CtailwithoutextraCALL.10546cases/3194962instructions/187admittedsites+6164fatalpreCALL/34nativechecks.168conditionalSSringwrites arenotintentionalreset-seeding/RNGpurpose oractualstackdomainproof; caller-allwriters-reset-lifetime-IRQexclusion/startup-to-exit-core/P1-GATE remainopen.',
        '06C9:5427':'Additionalwhole3F40-3FF9-38F2-1E31-near5427 actualSS/fullGPR-BP-CFIFDF-definedFLAGS/orderedprefixwrites-liveSSCALLframes/partialREP-fold-prefixes/current3811wrap/live23C6-C8bounds/frozennative601C-614CtailwithoutextraCALL.10546cases/3194962instructions/187admittedsites+6164fatalpreCALL/34nativechecks.168conditionalSSringwrites arenotintentionalreset-seeding/RNGpurpose oractualstackdomainproof; caller-allwriters-reset-lifetime-IRQexclusion/startup-to-exit-core/P1-GATE remainopen.',
    })
    selected.update({
        '13A8:2C1C':'ActualSS2D57-2C1C-29F6/currentCSsixkeylookup-literalnearworddispatch/currentDS7058handlers-distinctDS7076guard-SS707Efallback/liveSSpointerrereads-beforeCALL/retiredhandlercontrol/actualmessage-exitbodies/RETF2-vsplainfarcleanup/fullRAM-GPR-BP-CFIFDF-definedFLAGS.4990cases/445916instructions/93executedfamilyof97/208of228union/35native; prepared2C31-05DEand3postterminalwrapper-sites qualified.1458genericcallbackRETFs separate/notbodyproof. Actualcaller-allwriters-validtargets-lifetime-IRQexclusion/fullfatalcaller-B0FEarena/core/P1-GATE unproved.',
        '13A8:29F6':'ActualSS2D57-2C1C-29F6/currentCSsixkeylookup-literalnearworddispatch/currentDS7058handlers-distinctDS7076guard-SS707Efallback/liveSSpointerrereads-beforeCALL/retiredhandlercontrol/actualmessage-exitbodies/RETF2-vsplainfarcleanup/fullRAM-GPR-BP-CFIFDF-definedFLAGS.4990cases/445916instructions/93executedfamilyof97/208of228union/35native; prepared2C31-05DEand3postterminalwrapper-sites qualified.1458genericcallbackRETFs separate/notbodyproof. Actualcaller-allwriters-validtargets-lifetime-IRQexclusion/fullfatalcaller-B0FEarena/core/P1-GATE unproved.',
    })
    selected.update({'16A7:0002':'Actual16A7reportparent/68C4cleanup/actual642E-840A-610A-29F6-message-exitbodies/fullSS-latefivewordPUSHreads/returnedBPaliases/PICrestoreAH-orderedIVT-BDAwrites/callerADDSP0A/wholeRAM-GPR-BP-CFIFDF-definedFLAGS/orderedBIOS-device-port-DOS/independentCPUwrites.4906cases/4404970instructions/all13admittedparentof15-and22cleanup/269of342union/51native; separate432lowmemoryrootaliases/192changedfarwordpairs.358syntheticRETFs separate. Formatter0B00 typedretiredABIprofilenotbodyproof; preparedDOSexitnotexecuted/no inventedparentepilogue. Fullformatter/caller-DS-SS/allwriters-lifetime-IRQ/core-B0FEarenaqualification/P1-GATE unproved.'})
    interfaces={entry:{'entry':entry,'function_id':ids[entry],'contract_observation':description,'call_sites':[]} for entry,description in selected.items()}
    candidates=[]
    for f in g['functions']:
        s=int(f['entry'].split(':')[0],16)
        calls={c['site']:c for c in f['calls']}
        for c in f['calls']:
            if c['target'] in interfaces:interfaces[c['target']]['call_sites'].append({'owner':ids[f['entry']],**c})
        for c in f['indirect']:
            if c['kind'] not in ('call','lcall'):continue
            for target in c.get('review',{}).get('targets',[]):
                if target in interfaces:
                    interfaces[target]['call_sites'].append({'owner':ids[f['entry']],'site':c['site'],'kind':c['kind'],
                        'target':target,'resolution':'Reviewed indirect mechanism; surrounding semantics/caller domains separate',
                        'target_set_complete':c['review']['complete']})
        ins={ip:next(md.disasm(data[s*16+ip:s*16+ip+15],ip,count=1)) for ip in f['instructions']}
        for ip,i in ins.items():
            if i.mnemonic!='mov' or len(i.operands)!=2 or i.operands[0].type!=X86_OP_REG or i.operands[1].type!=X86_OP_IMM:continue
            offset=i.operands[1].imm;reg=i.reg_name(i.operands[0].reg)
            if offset not in names or reg not in ('ax','bx','si','di','dx'):continue
            cur=ip+i.size;pushed=False;callee=None;callsite=None
            for step in range(7):
                n=ins.get(cur)
                if n is None:break
                if n.mnemonic=='push' and n.op_str==reg:pushed=True
                key=f'{s:04X}:{cur:04X}'
                if key in calls:
                    if pushed:callee=calls[key]['target'];callsite=key
                    break
                if n.mnemonic.startswith('j') or n.mnemonic in ('ret','retf','iret'):break
                cur+=n.size
            if callee:
                candidates.append({'owner':ids[f['entry']],'literal_load_site':f'{s:04X}:{ip:04X}',
                                   'name_or_suffix':names[offset],'group_offset':offset,'call_site':callsite,'callee':callee,
                                   'status':'Literal argument candidate; requires segment/argument/consumer review'})
    manifest=json.loads((ROOT/'docs/planning/evidence/reference-manifest.json').read_text())
    resources=[]
    for row in sorted((r for r in manifest['files'] if r['path'].startswith('reference/dos/')),key=lambda r:r['path'].casefold()):
        filename=Path(row['path']).name
        matched=[c for c in candidates if c['name_or_suffix'].casefold()==filename.casefold()]
        resources.append({'logical_path':row['path'],'sha256':row['sha256'],'bytes':row['bytes'],
                          'literal_argument_candidates':matched,
                          'consumer_disposition':'Literal candidate(s), consumer review required' if matched else 'Dynamic-name/catalog/table/embedded consumer unresolved',
                          'format_decode_gate':'not_started_phase2','publication':'External original; no payload in this map'})
    result={'schema':1,'image_sha256':g['image_sha256'],'flow_ledger_sha256':hashlib.sha256(a.flow.read_bytes()).hexdigest(),
            'function_registry_sha256':hashlib.sha256((ROOT/'docs/recovery/functions.json').read_bytes()).hexdigest(),
            'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'interfaces':list(interfaces.values()),'filename_literals':literals,'literal_argument_candidates':candidates,
            'dos_file_count':len(resources),'resources':resources,
            'embedded_resource_candidates':[{'id':r['id'],'logical_path':r['logical_path'],'locations':r['locations'],'consumers':r['consumers'],'writers':r['writers'],'scope':r['claim']} for r in json.loads((ROOT/'docs/recovery/resources.json').read_text())['records'] if any(l['coordinate']=='unpacked_module' for l in r['locations'])],
            'scope':'Raw interface and lexical/call-site inventory; no resource format decode or complete consumer acceptance.',
            'limits':['Literal matching does not prove DS, source-level pointer type, liveness, family coverage or format.',
                      'Dynamic car/route/graphics names, catalogs, embedded media, writes and alias lifetimes need manual recovery.',
                      'No DOS, native game, renderer or audio output exercised.']}
    out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'interfaces':len(interfaces),'filename_literals':len(literals),'literal_argument_candidates':len(candidates),'dos_files':len(resources)},indent=2))


if __name__=='__main__':main()
