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
import ida_ida
import ida_idaapi
import ida_name
import ida_segment
import ida_ua
import idautils

MAX_LEN = 512
WILD = (ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem)


def fields(insn):
    ops = sorted((o.offb, o) for o in insn.ops if o.type != ida_ua.o_void and o.offb)
    for i, (offb, o) in enumerate(ops):
        end = ops[i + 1][0] if i + 1 < len(ops) else insn.size
        addr = o.addr if o.type == ida_ua.o_displ else o.value
        if o.type in WILD or (end - offb >= 4 and ida_segment.get_segment_info(None, addr)):
            yield offb, end


def matches(sig):
    lo, hi = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
    hits = []
    ea = ida_bytes.find_bytes(sig, lo, range_end=hi)
    while ea != ida_idaapi.BADADDR and len(hits) < 2:
        hits.append(ea)
        ea = ida_bytes.find_bytes(sig, ea + 1, range_end=hi)
    return hits


def make(ea):
    pat, cur, first = [], ea, None
    while cur - ea < MAX_LEN:
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, cur):
            break
        raw = ida_bytes.get_bytes(cur, insn.size)
        wild = set()
        for offb, stop in fields(insn):
            wild.update(range(offb, stop))
            if first is None:
                first = (cur - ea + offb, stop - offb)
        pat += [None if i in wild else b for i, b in enumerate(raw)]
        cur += insn.size
        if len(matches(fmt(pat)[0])) == 1:
            while pat[-1] is None:
                pat.pop()
            return pat, first
    return None, first


def fmt(pat):
    ida = " ".join("?" if b is None else "%02X" % b for b in pat)
    code = "".join("\\x00" if b is None else "\\x%02X" % b for b in pat)
    mask = "".join("?" if b is None else "x" for b in pat)
    x64dbg = ida.replace("?", "??")
    return ida, code + " " + mask, x64dbg


def report(ea, xref=False):
    starts = [x.frm for x in idautils.XrefsTo(ea) if ida_bytes.is_code(ida_bytes.get_flags(x.frm))] if xref else [ea]
    for start in starts:
        pat, first = make(start)
        if pat:
            ida, code, x64dbg = fmt(pat)
            where = " field at +%d size %d" % first if xref and first else ""
            print("[+] %#x%s\n    %s\n    %s\n    %s" % (start, where, ida, code, x64dbg))
            return ida
        print("[-] %#x: no unique signature within %d bytes" % (start, MAX_LEN))
    if not starts:
        print("[-] %#x: no code references" % ea)
    return None


def gui():
    import ida_kernwin
    sig = report(ida_kernwin.get_screen_ea())
    if sig:
        try:
            from PyQt5.QtWidgets import QApplication
            QApplication.clipboard().setText(sig)
        except ImportError:
            pass


def cli():
    import argparse
    ap = argparse.ArgumentParser(description="make and resolve byte signatures (IDA 9.4)")
    ap.add_argument("binary", help="file or .i64/.idb to open")
    ap.add_argument("--ea", type=lambda s: int(s, 0), help="address to sign")
    ap.add_argument("--xref", action="store_true", help="sign the first code reference to --ea instead")
    ap.add_argument("--make", metavar="JSON", help="{name: address or symbol} in, {name: signature} out")
    ap.add_argument("--scan", metavar="JSON", help="{name: signature} in, resolve each in this binary")
    ap.add_argument("--save", action="store_true", help="save the database")
    args = ap.parse_args()
    if args.ea is None and not args.make and not args.scan:
        ap.error("need --ea, --make or --scan")
    if idapro.open_database(args.binary, True):
        sys.exit("could not open " + args.binary)
    ida_auto.auto_wait()
    failed = 0
    if args.ea is not None:
        failed += report(args.ea, args.xref) is None
    if args.make:
        out = {}
        for name, loc in json.load(open(args.make)).items():
            ea = int(loc, 0) if isinstance(loc, str) and loc[:2] == "0x" else ida_name.get_name_ea(ida_idaapi.BADADDR, str(loc))
            pat, _ = make(ea) if ea != ida_idaapi.BADADDR else (None, None)
            out[name] = fmt(pat)[0] if pat else None
            failed += pat is None
        print(json.dumps(out, indent=2))
    if args.scan:
        for name, sig in json.load(open(args.scan)).items():
            hits = matches(sig) if sig else []
            if len(hits) == 1:
                print("[+] %s %#x" % (name, hits[0]))
            else:
                print("[-] %s: %d matches" % (name, len(hits)))
                failed += 1
    idapro.close_database(args.save)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    cli() if HEADLESS else gui()
