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
import ida_ida
import ida_name
import ida_segment
import ida_xref
import idautils

MIN_SLOTS = 2


def code_ref(ea):
    return any(x.type == ida_xref.dr_O and ida_bytes.is_code(ida_bytes.get_flags(x.frm)) for x in idautils.XrefsTo(ea))


def scan(min_slots=MIN_SLOTS):
    ps = 8 if ida_ida.inf_is_64bit() else 4
    found = []
    seg = ida_segment.segment_info_t()
    n = 0
    while ida_segment.get_segment_info_by_num(seg, n):
        n += 1
        if seg.get_perm() & ida_segment.SEGPERM_EXEC or not ida_bytes.is_loaded(seg.start_ea):
            continue
        data = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea) or b""
        start = None

        def flush(ea):
            if start is not None and ea - start >= min_slots * ps and code_ref(start):
                found.append((start, (ea - start) // ps))

        for off in range(0, len(data) - ps + 1, ps):
            ea = seg.start_ea + off
            target = int.from_bytes(data[off:off + ps], "little")
            if ida_funcs.get_func_start(target) == target:
                if start is None or code_ref(ea):
                    flush(ea)
                    start = ea
            elif start is not None:
                flush(ea)
                start = None
        flush(seg.end_ea)
    return found


def name(ea):
    return "" if ida_bytes.has_dummy_name(ida_bytes.get_flags(ea)) else ida_name.get_name(ea)


def report(found, unnamed=False):
    for ea, slots in found:
        if unnamed and name(ea):
            continue
        print("[+] %#x %d slots %s" % (ea, slots, name(ea)))
    print("[*] %d vtables" % len(found))


def gui():
    report(scan())


def cli():
    import argparse
    ap = argparse.ArgumentParser(description="find vtables by scanning data for runs of function pointers with a code reference (IDA 9.4)")
    ap.add_argument("binary", help="file or .i64/.idb to open")
    ap.add_argument("--min", type=int, default=MIN_SLOTS, help="minimum slots")
    ap.add_argument("--unnamed", action="store_true", help="only vtables without a name")
    ap.add_argument("--json", action="store_true", help="print as json")
    args = ap.parse_args()
    if idapro.open_database(args.binary, True):
        sys.exit("could not open " + args.binary)
    ida_auto.auto_wait()
    found = scan(args.min)
    if args.json:
        rows = [{"ea": "%#x" % ea, "slots": slots, "name": name(ea)} for ea, slots in found]
        print(json.dumps([r for r in rows if not (args.unnamed and r["name"])], indent=2))
    else:
        report(found, args.unnamed)
    idapro.close_database(True)


if __name__ == "__main__":
    cli() if HEADLESS else gui()
