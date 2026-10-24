"""Compile frozen isolated Kylofon baseline/candidate C directly with MSVC.

Uses absolute tools and explicit MSVC/SDK/SDL paths instead of vcvars or CMake.
No reference or accepted recovered source is mutated. Fresh outputs only.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
TASK = ROOT / "analysis/candidates/kylofon-r03-v1"
BUILD = TASK / "native-build-v1"
OUT = ROOT / "docs/recovery/evidence/kylofon-candidate-build-v1.json"
VC = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207")
SDK = Path(r"C:\Program Files (x86)\Windows Kits\10")
VERSION = "10.0.26100.0"
SDL = ROOT / "analysis/external/sdl3-3.4.18/sdk/SDL3-3.4.18"
CL = VC / "bin/Hostx64/x64/cl.exe"
LINK = VC / "bin/Hostx64/x64/link.exe"


def pin(path):
    p = Path(path)
    try: name = p.relative_to(ROOT).as_posix()
    except ValueError: name = str(p)
    return {"path": name, "bytes": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}


def write_json(path, obj):
    path.write_bytes((json.dumps(obj, indent=2) + "\n").encode())


def main():
    if OUT.exists() or BUILD.exists():
        raise FileExistsError("Use a fresh build version; this maker cannot overwrite attempts")
    for path in (CL, LINK, VC/"include", VC/"lib/x64", SDK/"Include"/VERSION,
                 SDK/"Lib"/VERSION/"um/x64", SDL/"include/SDL3/SDL.h", SDL/"lib/x64/SDL3.lib", SDL/"lib/x64/SDL3.dll", TASK/"probe.c", TASK/"candidate-fixes-v2.json"):
        if not path.exists(): raise FileNotFoundError(path)
    BUILD.mkdir()
    started = time.perf_counter()
    include = [VC/"include", *[SDK/"Include"/VERSION/k for k in ("ucrt", "shared", "um", "winrt")], SDL/"include"]
    libs = [VC/"lib/x64", SDK/"Lib"/VERSION/"um/x64", SDK/"Lib"/VERSION/"ucrt/x64", SDL/"lib/x64"]
    env = dict(os.environ)
    for key in ("CL", "_CL_", "LINK", "_LINK_"):
        env.pop(key, None)
    env["INCLUDE"] = ";".join(str(p) for p in include)
    env["LIB"] = ";".join(str(p) for p in libs)
    env["LIBPATH"] = ""
    env["VSLANG"] = "1033"
    env["PATH"] = str(CL.parent) + os.pathsep + str(SDK/"bin"/VERSION/"x64") + os.pathsep + env.get("PATH", "")
    sources = {}
    for variant in ("baseline", "candidate"):
        src = TASK/variant/"td2port/src"
        sources[variant] = [pin(p) for p in sorted(src.rglob("*")) if p.suffix in (".c", ".h")]
    probe_pin = pin(TASK/"probe.c")
    frozen = {"source_authority": "Parent SOURCE FROZEN confirmation for candidate-fixes-v2 and final probe.c", "variants": sources,
              "probe": probe_pin, "fix_manifest": pin(TASK/"candidate-fixes-v2.json"),
              "fix_patch": pin(TASK/"candidate-fixes-v2.patch")}
    write_json(BUILD/"source-freeze.json", frozen)
    calls = []
    def compile_one(variant, source, obj, log, is_probe=False):
        srcroot = TASK/variant/"td2port/src"
        args = [str(CL), "/nologo", "/c", "/TC", "/std:c17", "/W3", "/O2", "/utf-8", "/MD", "/D_CRT_SECURE_NO_WARNINGS"]
        if is_probe and variant == "candidate": args.append("/DTD2R03_QUALIFIED=1")
        args += ["/I"+str(p) for p in [srcroot, *include]]
        args += ["/Fo"+str(obj), str(source)]
        begin=time.perf_counter()
        result=subprocess.run(args, cwd=ROOT, env=env, capture_output=True, timeout=240)
        data=result.stdout+result.stderr
        log.write_bytes(data)
        record={"kind":"compile_probe" if is_probe else "compile_source", "variant":variant,
                "source":pin(source), "argv":args, "exit_code":result.returncode,
                "elapsed_seconds":round(time.perf_counter()-begin,3),"log":pin(log)}
        if obj.exists(): record["object"]=pin(obj)
        print(f"{variant} {source.name}: exit {result.returncode}",flush=True)
        return record
    jobs=[]
    for variant in ("baseline", "candidate"):
        folder=BUILD/variant
        (folder/"obj").mkdir(parents=True)
        (folder/"logs").mkdir()
        srcroot=TASK/variant/"td2port/src"
        for source in sorted(srcroot.rglob("*.c")):
            stem="__".join(source.relative_to(srcroot).with_suffix("").parts)
            jobs.append((variant,source,folder/"obj"/(stem+".obj"),folder/"logs"/(stem+".log"),False))
        jobs.append((variant,TASK/"probe.c",folder/"obj/probe.obj",folder/"logs/probe.log",True))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures=[pool.submit(compile_one,*job) for job in jobs]
        for future in concurrent.futures.as_completed(futures): calls.append(future.result())
    failed=[q for q in calls if q["exit_code"]]
    links=[]
    if not failed:
        for variant in ("baseline", "candidate"):
            folder=BUILD/variant
            source_calls=[q for q in calls if q["variant"]==variant and q["kind"]=="compile_source"]
            full_objects=[str(ROOT/q["object"]["path"]) for q in source_calls]
            probe_objects=[str(ROOT/q["object"]["path"]) for q in source_calls if Path(q["source"]["path"]).name not in ("host.c","main.c")]
            probe_objects.append(str(folder/"obj/probe.obj"))
            for target,objects in (("full",full_objects),("probe",probe_objects)):
                binary=folder/("td2r03_full.exe" if target=="full" else "td2r03_probe.dll")
                args=[str(LINK),"/NOLOGO","/MACHINE:X64","/INCREMENTAL:NO","/OUT:"+str(binary)]
                if target=="probe": args += ["/DLL","/IMPLIB:"+str(folder/"td2r03_probe.lib")]
                else: args.append("/SUBSYSTEM:CONSOLE")
                args += ["/LIBPATH:"+str(p) for p in libs]
                args += objects + ["SDL3.lib","bcrypt.lib","kernel32.lib","user32.lib","gdi32.lib","shell32.lib","ole32.lib","oleaut32.lib","uuid.lib","comdlg32.lib","advapi32.lib","winmm.lib","setupapi.lib","imm32.lib","version.lib"]
                begin=time.perf_counter()
                result=subprocess.run(args,cwd=ROOT,env=env,capture_output=True,timeout=240)
                log=folder/"logs"/("link-"+target+".log")
                log.write_bytes(result.stdout+result.stderr)
                record={"variant":variant,"target":target,"argv":args,"exit_code":result.returncode,
                        "elapsed_seconds":round(time.perf_counter()-begin,3),"log":pin(log)}
                if binary.exists(): record["binary"]=pin(binary)
                links.append(record)
                print(f"{variant} {target} link: exit {result.returncode}",flush=True)
            shutil.copyfile(SDL/"lib/x64/SDL3.dll",folder/"SDL3.dll")
    source_changes=[]
    for variant,rows in sources.items():
        for row in rows:
            if pin(ROOT/row["path"])!=row: source_changes.append(row["path"])
    if pin(TASK/"probe.c")!=probe_pin: source_changes.append(probe_pin["path"])
    recipe={"schema":1,"date":"2026-10-22","method":"Absolute MSVC compiler/linker, explicit include/library paths; no vcvars/CMake invocation", "compiler":pin(CL),"linker":pin(LINK),
            "maker":pin(Path(__file__).resolve()),"language":"C17","compile_flags":["/TC","/std:c17","/W3","/O2","/utf-8","/MD","/D_CRT_SECURE_NO_WARNINGS"],
            "warning_policy":"Upstream-equivalent W3 without WX; warnings retained verbatim in per-object logs. This is not the recovered-helper W4/WX qualification.",
            "source_freeze":frozen,"source_freeze_record":pin(BUILD/"source-freeze.json"),
            "sdl":{"version":"3.4.18","sdk_git_hash":(SDL/".git-hash").read_text().strip(),
                   "archive":pin(ROOT/"analysis/external/sdl3-3.4.18/SDL3-devel-3.4.18-VC.zip"),
                   "import_library":pin(SDL/"lib/x64/SDL3.lib"),"runtime_library":pin(SDL/"lib/x64/SDL3.dll"),"license":pin(SDL/"LICENSE.txt"),
                   "headers":[pin(p) for p in sorted((SDL/"include").rglob("*.h"))]},
            "compiler_support_files":[pin(p) for p in sorted(CL.parent.glob("*.dll"))],
            "msvc_headers":[pin(p) for p in sorted((VC/"include").rglob("*.h"))],
            "sdk_version":VERSION,"include_paths":[str(p) for p in include],"library_paths":[str(p) for p in libs],
            "compilations":sorted(calls,key=lambda q:(q["variant"],q["source"]["path"])),"links":links,
            "frozen_sources_unchanged":not source_changes,"source_changes":source_changes,
            "elapsed_seconds":round(time.perf_counter()-started,3),
            "scope":"Compilation/link compatibility only. No game, original EXE, probe, window, audio device or original instructions executed by this maker; differential acceptance recorded separately."}
    recipe["result"]="pass" if not failed and all(q["exit_code"]==0 for q in links) and len(links)==4 and not source_changes else "fail"
    recipe["failed_compiles"]=[q["log"]["path"] for q in failed]
    recipe["failed_links"]=[q["log"]["path"] for q in links if q["exit_code"]]
    recipe["build_artifacts"]=[pin(p) for p in sorted(BUILD.rglob("*")) if p.is_file()]
    write_json(OUT,recipe)
    print(json.dumps({k:recipe[k] for k in ("result","elapsed_seconds","failed_compiles","failed_links","frozen_sources_unchanged")},indent=2),flush=True)
    return 0 if recipe["result"]=="pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
