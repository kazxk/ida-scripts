import hashlib
import json
import sys

try:
    import ida_idaapi
    HEADLESS = False
except ImportError:
    import idapro
    HEADLESS = True

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name
import ida_segment
import ida_ua
import idautils

MIN_LEN = 16
MAX_LEN = 4096
WILD = (ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem)


def fields(insn):
    ops = sorted((o.offb, o) for o in insn.ops if o.type != ida_ua.o_void and o.offb)
    for i, (offb, o) in enumerate(ops):
        end = ops[i + 1][0] if i + 1 < len(ops) else insn.size
        addr = o.addr if o.type == ida_ua.o_displ else o.value
        if o.type in WILD or (end - offb >= 4 and ida_segment.get_segment_info(None, addr)):
            yield offb, end


def key(ea):
    fi = ida_funcs.func_entry_info_t()
    if not ida_funcs.get_func_entry_info(fi, ea):
        return None, 0
    body, mask, cur = bytearray(), bytearray(), fi.start_ea
    while cur < fi.end_ea and len(body) < MAX_LEN:
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, cur):
            break
        raw = ida_bytes.get_bytes(cur, insn.size)
        m = bytearray(b"\xff") * insn.size
        for offb, stop in fields(insn):
            m[offb:stop] = b"\x00" * (stop - offb)
        body += bytes(a & b for a, b in zip(raw, m))
        mask += m
        cur += insn.size
    if len(body) < MIN_LEN:
        return None, len(body)
    return hashlib.blake2b(bytes(body) + bytes(mask), digest_size=16).digest(), len(body)


def groups():
    seen = {}
    for f in idautils.Functions():
        k, size = key(f)
        if k:
            seen.setdefault(k, (size, []))[1].append(f)
    return sorted((v for v in seen.values() if len(v[1]) > 1), key=lambda v: (-len(v[1]), -v[0]))


def label(ea):
    name = ida_name.get_name(ea)
    return "%#x %s" % (ea, name) if not ida_bytes.has_dummy_name(ida_bytes.get_flags(ea)) else "%#x" % ea


def rename(members):
    named = [f for f in members if not ida_bytes.has_dummy_name(ida_bytes.get_flags(f))]
    if len(named) != 1:
        return 0
    base = ida_name.get_name(named[0])
    rest = [f for f in members if f != named[0]]
    return sum(ida_name.set_name(f, "%s_dup%d" % (base, i), ida_name.SN_NOWARN) for i, f in enumerate(rest))


def report(size, members, do_rename=False):
    more = ", +%d more" % (len(members) - 8) if len(members) > 8 else ""
    print("[+] %d x %d bytes: %s%s" % (len(members), size, ", ".join(label(f) for f in members[:8]), more))
    if do_rename:
        n = rename(members)
        if n:
            print("    renamed %d" % n)


def gui():
    import ida_kernwin
    k, size = key(ida_kernwin.get_screen_ea())
    if not k:
        print("[-] not in a function, or shorter than %d bytes" % MIN_LEN)
        return
    twins = [f for f in idautils.Functions() if key(f)[0] == k]
    if len(twins) > 1:
        report(size, twins)
    else:
        print("[-] no duplicates")


def cli():
    import argparse
    global MIN_LEN
    ap = argparse.ArgumentParser(description="group functions that are identical apart from relocations (IDA 9.4)")
    ap.add_argument("binary", help="file or .i64/.idb to open")
    ap.add_argument("--ea", type=lambda s: int(s, 0), help="only the group containing this address")
    ap.add_argument("--min", type=int, default=MIN_LEN, help="skip functions shorter than this many bytes")
    ap.add_argument("--rename", action="store_true", help="name sub_ members after the one named member of their group")
    ap.add_argument("--json", action="store_true", help="print groups as json")
    args = ap.parse_args()
    MIN_LEN = args.min
    if idapro.open_database(args.binary, True):
        sys.exit("could not open " + args.binary)
    ida_auto.auto_wait()
    found = groups()
    if args.ea is not None:
        fi = ida_funcs.func_entry_info_t()
        start = fi.start_ea if ida_funcs.get_func_entry_info(fi, args.ea) else args.ea
        found = [g for g in found if start in g[1]]
    if args.json:
        print(json.dumps([{"size": size, "functions": ["%#x" % f for f in members]} for size, members in found], indent=2))
    else:
        for size, members in found:
            report(size, members, args.rename)
        print("[*] %d groups, %d functions" % (len(found), sum(len(m) for _, m in found)))
    idapro.close_database(True)


if __name__ == "__main__":
    cli() if HEADLESS else gui()
