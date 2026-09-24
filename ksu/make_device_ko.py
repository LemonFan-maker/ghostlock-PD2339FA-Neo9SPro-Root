import argparse
import shutil
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile

SHN_ABS = 0xFFF1
SHN_UNDEF = 0

LINK_BASE_FALLBACK = 0xFFFFFFC008000000


def parse_kallsyms(path):
    syms = {}
    for line in open(path, errors="replace"):
        p = line.split()
        if len(p) >= 3:
            try:
                a = int(p[0], 16)
            except ValueError:
                continue
            if a != 0 and p[2] not in syms:
                syms[p[2]] = (a, p[1])
    return syms


def read_sections(f):
    elf = ELFFile(f)
    hdr = elf.header
    shoff, shnum, shentsize = hdr["e_shoff"], hdr["e_shnum"], hdr["e_shentsize"]
    f.seek(shoff + hdr["e_shstrndx"] * shentsize)
    sh = f.read(shentsize)
    stroff = struct.unpack("<Q", sh[0x18:0x20])[0]
    strsize = struct.unpack("<Q", sh[0x20:0x28])[0]
    f.seek(stroff)
    st_data = f.read(strsize)

    def sec(idx):
        f.seek(shoff + idx * shentsize)
        return f.read(shentsize)

    def name_of(idx):
        sh = sec(idx)
        nmoff = struct.unpack("<I", sh[0:4])[0]
        return st_data[nmoff : st_data.find(b"\x00", nmoff)].decode(errors="replace")

    return hdr, shoff, shnum, shentsize, sec, name_of


def find_sec_by_name(f, want):
    hdr, shoff, shnum, shentsize, sec, name_of = read_sections(f)
    for idx in range(shnum):
        if name_of(idx) == want:
            sh = sec(idx)
            off = struct.unpack("<Q", sh[0x18:0x20])[0]
            size = struct.unpack("<Q", sh[0x20:0x28])[0]
            return idx, off, size
    return None, None, None


def ko_undef_syms(path):
    """Undefined (SHN_UNDEF) non-empty symbol names of the ko."""
    out = []
    with open(path, "rb") as f:
        symtab_off, _, symtab_size = find_sec_by_name(f, ".symtab")[0], None, None
        idx, off, size = find_sec_by_name(f, ".symtab")
        if idx is None:
            raise RuntimeError(".symtab not found")
        f.seek(off)
        entsize = 24
        raw = f.read(size)
        stridx, stroff, strsize = find_sec_by_name(f, ".strtab")
        f.seek(stroff)
        strdata = f.read(strsize)
        for i in range(len(raw) // entsize):
            e = raw[i * entsize : (i + 1) * entsize]
            st_name = struct.unpack("<I", e[0:4])[0]
            st_shndx = struct.unpack("<H", e[6:8])[0]
            if st_shndx != SHN_UNDEF:
                continue
            nm = strdata[st_name : strdata.find(b"\x00", st_name)].decode(errors="replace")
            if nm:
                out.append(nm)
    return out


def patch(src, dst, kallsyms_path, text_runtime, release, flags, strip=True):
    syms = parse_kallsyms(kallsyms_path)
    link_text, _ = syms.get("_text", (None, None))
    if link_text is None:
        raise RuntimeError("_text not found in kallsyms dump")
    slide = text_runtime - link_text
    print(f"[*] link _text = 0x{link_text:016x}")
    print(f"[*] runtime _text= 0x{text_runtime:016x}")
    print(f"[*] slide = 0x{slide:016x} ({'+' if slide >= 0 else '-'}0x{abs(slide):x})")

    undef = ko_undef_syms(src)
    missing = [s for s in undef if s not in syms]
    print(f"[*] undefined symbols in ko: {len(undef)}; missing in kallsyms: {len(missing)}")
    for s in missing:
        print(f"    MISSING {s}")
    if missing:
        print("[!] coverage incomplete - refusing to patch (relocations would embed garbage)")
        return 1
    shutil.copy(src, dst)
    with open(dst, "r+b") as f:
        hdr, shoff, shnum, shentsize, sec, name_of = read_sections(f)
        symtab = elf_tab = None
        for idx in range(shnum):
            if name_of(idx) == ".symtab":
                elf_tab = sec(idx)
                break
        sym_off = struct.unpack("<Q", elf_tab[0x18:0x20])[0]
        sym_size = struct.unpack("<Q", elf_tab[0x20:0x28])[0]
        link_idx = struct.unpack("<I", elf_tab[0x28:0x2C])[0]
        strsh = sec(link_idx)
        stroff = struct.unpack("<Q", strsh[0x18:0x20])[0]
        strsize = struct.unpack("<Q", strsh[0x20:0x28])[0]
        f.seek(stroff)
        strdata = f.read(strsize)

        entsize = 24
        n = sym_size // entsize
        patched = 0
        runtime_lo = runtime_hi = None
        for i in range(n):
            f.seek(sym_off + i * entsize)
            e = f.read(entsize)
            st_shndx = struct.unpack("<H", e[6:8])[0]
            if st_shndx != SHN_UNDEF:
                continue
            st_name = struct.unpack("<I", e[0:4])[0]
            nm = strdata[st_name : strdata.find(b"\x00", st_name)].decode(errors="replace")
            if not nm or nm not in syms:
                continue
            a, _t = syms[nm]
            rt = a + slide
            runtime_lo = rt if runtime_lo is None else min(runtime_lo, rt)
            runtime_hi = rt if runtime_hi is None else max(runtime_hi, rt)
            f.seek(sym_off + i * entsize + 8)
            f.write(struct.pack("<Q", rt))
            f.seek(sym_off + i * entsize + 6)
            f.write(struct.pack("<H", SHN_ABS))
            patched += 1

        vers_stripped = False
        for idx in range(shnum):
            if name_of(idx) == "__versions":
                f.seek(shoff + idx * shentsize + 0x20)
                f.write(struct.pack("<Q", 0))
                vers_stripped = True
                break

        midx = moff = msize = None
        for idx in range(shnum):
            if name_of(idx) == ".modinfo":
                midx = idx
                msh = sec(idx)
                moff = struct.unpack("<Q", msh[0x18:0x20])[0]
                msize = struct.unpack("<Q", msh[0x20:0x28])[0]
                break
        f.seek(moff)
        mi = bytearray(f.read(msize))
        pos = bytes(mi).find(b"vermagic=")
        if pos < 0:
            raise RuntimeError("vermagic= not found in .modinfo")
        end = bytes(mi).find(b"\x00", pos)
        cur = bytes(mi[pos + 9 : end]).decode(errors="replace")
        new = (release + flags).encode()
        space = msize - (pos + 9)
        if len(new) > space - 1:
            raise RuntimeError(f"new vermagic {len(new)}B > .modinfo space {space}B")
        mi[pos + 9 : end] = new + b"\x00"
        f.seek(moff)
        f.write(bytes(mi))
        print(f"[*] vermagic: '{cur}' -> '{new.decode()}'")

    if strip:
        subprocess.run(["llvm-strip", "-d", dst], check=True)

    print(f"[*] patched SHN_ABS symbols: {patched}")
    if runtime_lo is not None:
        print(f"[*] runtime addr range: 0x{runtime_lo:016x} .. 0x{runtime_hi:016x}")
    print(f"[*] __versions: {'zeroed (sh_size=0)' if vers_stripped else 'NOT FOUND'}")

    n_abs = n_undef = 0
    with open(dst, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        for s in symtab.iter_symbols():
            idx = s.entry["st_shndx"]
            if idx == SHN_ABS or idx == "SHN_ABS":
                n_abs += 1
            elif idx == SHN_UNDEF or idx == "SHN_UNDEF":
                n_undef += 1
        modinfo = elf.get_section_by_name(".modinfo")
        vm = [kv for kv in modinfo.data().split(b"\x00") if kv.startswith(b"vermagic=")]
        vsize = None
        for sec2 in elf.iter_sections():
            if sec2.name == "__versions":
                vsize = sec2["sh_size"]
        spot = ["_printk", "memcpy", "prepare_creds", "commit_creds",
                "override_creds", "module_layout", "param_ops_bool"]
        for s in symtab.iter_symbols():
            if s.name in spot:
                print(f"    {s.name:16s} = 0x{s.entry['st_value']:016x}")
    print(f"[verify] SHN_ABS symbols: {n_abs}, remaining SHN_UNDEF: {n_undef}, "
          f"__versions size: {vsize}, vermagic: {vm[0].decode() if vm else '??'}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="PD2339FA device-ready LKM pipeline")
    ap.add_argument("--ko", required=True)
    ap.add_argument("--kallsyms", required=True)
    ap.add_argument("--text", required=True, type=lambda s: int(s, 0),
                    help="runtime _text of the boot (psl2 measurement), hex")
    ap.add_argument("--out", default="kernelsu-device-ready.ko")
    ap.add_argument("--release", default="6.1.145-android14-11-maybe-dirty")
    ap.add_argument("--flags", default=" SMP preempt mod_unload modversions vivo aarch64")
    ap.add_argument("--dry-run", action="store_true",
                    help="coverage check only: report resolvability of every undefined symbol")
    ap.add_argument("--no-strip", action="store_true")
    args = ap.parse_args()

    syms = parse_kallsyms(args.kallsyms)
    undef = ko_undef_syms(args.ko)
    missing = [(s, syms[s][1] if s in syms else "-") for s in undef if s not in syms]
    have = [s for s in undef if s in syms]
    print(f"[coverage] ko undefined: {len(undef)}  resolvable: {len(have)}  missing: {len(missing)}")
    for s, _ in missing:
        print(f"    MISSING {s}")
    if args.dry_run:
        return 0 if not missing else 2

    return patch(args.ko, args.out, args.kallsyms, args.text, args.release,
                 args.flags, strip=not args.no_strip)


if __name__ == "__main__":
    sys.exit(main())
