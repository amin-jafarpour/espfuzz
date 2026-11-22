#!/usr/bin/env python3
"""Static dependency census of Espressif's precompiled Wi-Fi libraries.

For each chip directory, parse the static archives with `readelf` and report:
  - object count, executable-section bytes, data/bss bytes
  - defined global functions
  - undefined external symbols, classified as
      (a) resolved by another radio library in the same set,
      (b) provided by the chip's mask ROM (PROVIDE entries in ROM linker scripts),
      (c) external: ESP-IDF glue, libc, FreeRTOS, etc.
  - whether the OS-adapter table pointer is referenced.

Usage: radio_symbols.py <wifi_lib_root> <esp_idf_root> <chip> [<chip> ...]
"""
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

CORE_LIBS = ["libcore.a", "libnet80211.a", "libpp.a"]
OPTIONAL_LIBS = ["libespnow.a", "libmesh.a", "libsmartconfig.a", "libwapi.a"]

SYM_RE = re.compile(
    r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s*$"
)
SEC_RE = re.compile(
    r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(\S*)\s"
)
ROM_RE = [
    re.compile(r"PROVIDE\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+)?"),
    re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+)\s*;"),
]


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def parse_symbols(lib):
    defined, undefined = set(), set()
    funcs = 0
    for line in run(["readelf", "-sW", str(lib)]).splitlines():
        m = SYM_RE.match(line)
        if not m:
            continue
        _val, _size, typ, bind, _vis, ndx, name = m.groups()
        if bind not in ("GLOBAL", "WEAK"):
            continue
        if ndx == "UND":
            undefined.add(name)
        else:
            defined.add(name)
            if typ == "FUNC":
                funcs += 1
    return defined, undefined, funcs


def parse_sections(lib):
    code = data = 0
    objs = 0
    for line in run(["readelf", "-SW", str(lib)]).splitlines():
        if line.startswith("File: "):
            objs += 1
            continue
        m = SEC_RE.match(line)
        if not m:
            continue
        name, typ, size_hex, flags = m.groups()
        size = int(size_hex, 16)
        if "A" not in flags:
            continue  # not allocated at run time
        if "X" in flags:
            code += size
        elif "W" in flags or typ == "NOBITS":
            data += size
    return objs, code, data


def rom_symbols(idf_root, chip):
    names = {}
    ld_dir = Path(idf_root) / "components" / "esp_rom" / chip / "ld"
    for ld in sorted(ld_dir.glob("*.ld")):
        for line in ld.read_text(errors="replace").splitlines():
            for rx in ROM_RE:
                m = rx.search(line)
                if m:
                    addr = int(m.group(2), 16) if m.group(2) else None
                    names.setdefault(m.group(1), addr)
    return names


def census(wifi_root, idf_root, chip, libs):
    rom = rom_symbols(idf_root, chip)
    per_lib, all_def, all_und = {}, set(), set()
    tot_objs = tot_code = tot_data = tot_funcs = 0
    for lib in libs:
        path = Path(wifi_root) / chip / lib
        if not path.exists():
            continue
        d, u, f = parse_symbols(path)
        o, c, dt = parse_sections(path)
        per_lib[lib] = {"objects": o, "code_bytes": c, "data_bytes": dt,
                        "defined_funcs": f, "undefined": len(u)}
        all_def |= d
        all_und |= u
        tot_objs += o; tot_code += c; tot_data += dt; tot_funcs += f
    external = all_und - all_def
    in_rom = {s for s in external if s in rom}
    other = external - in_rom
    adapter_refs = sorted(s for s in all_und if "osi_funcs" in s)
    prefixes = Counter(re.split(r"_", s.lstrip("_"))[0] for s in other)
    return {
        "chip": chip,
        "libs": per_lib,
        "objects": tot_objs,
        "code_bytes": tot_code,
        "data_bytes": tot_data,
        "defined_funcs": tot_funcs,
        "undefined_total": len(all_und),
        "resolved_within_set": len(all_und & all_def),
        "external_total": len(external),
        "external_rom": len(in_rom),
        "external_other": len(other),
        "adapter_symbols_referenced": adapter_refs,
        "rom_symbols_available": len(rom),
        "top_other_prefixes": prefixes.most_common(15),
        "sample_other": sorted(other)[:400],
        "rom_resolved": sorted(in_rom),
        "rom_resolved_addr": {s: rom[s] for s in sorted(in_rom)},
    }


def main():
    wifi_root, idf_root, chips = sys.argv[1], sys.argv[2], sys.argv[3:]
    out = {"core": [], "all": []}
    for chip in chips:
        out["core"].append(census(wifi_root, idf_root, chip, CORE_LIBS))
        out["all"].append(census(wifi_root, idf_root, chip, CORE_LIBS + OPTIONAL_LIBS))
    json.dump(out, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
