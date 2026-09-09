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
import ida_nalt
import idautils

DEPTH = 2


def strings(ea, depth=DEPTH, seen=None):
    seen = seen if seen is not None else set()
    start = ida_funcs.get_func_start(ea)
    if start == ida_idaapi.BADADDR or start in seen:
        return []
    seen.add(start)
    out, callees = [], []
    for item in idautils.FuncItems(start):
        for ref in idautils.DataRefsFrom(item):
            if ida_bytes.is_strlit(ida_bytes.get_flags(ref)):
                text = ida_bytes.get_strlit_contents(ref, -1, ida_nalt.get_str_type(ref))
                out.append((item, ref, text.decode("utf-8", "replace") if text else "", start))
        for ref in idautils.CodeRefsFrom(item, 0):
            if ida_funcs.get_func_start(ref) == ref and ref != start:
                callees.append(ref)
    if depth > 0:
        for callee in callees:
            out += strings(callee, depth - 1, seen)
    return out


def report(ea, depth=DEPTH):
    start = ida_funcs.get_func_start(ea)
    if start == ida_idaapi.BADADDR:
        print("[-] %#x: not in a function" % ea)
        return None
    found = strings(start, depth)
    print("[+] %#x %s: %d strings" % (start, ida_name.get_name(start), len(found)))
    for item, ref, text, func in found:
        via = "" if func == start else "  via %s" % ida_name.get_name(func)
        print("    %#x %r%s" % (item, text, via))
    return found


def gui():
    import ida_kernwin
    report(ida_kernwin.get_screen_ea())


def cli():
    import argparse
    ap = argparse.ArgumentParser(description="list strings reachable from a function through its callees (IDA 9.4)")
    ap.add_argument("binary", help="file or .i64/.idb to open")
    ap.add_argument("--ea", type=lambda s: int(s, 0), nargs="+", required=True, help="function addresses")
    ap.add_argument("--depth", type=int, default=DEPTH, help="how many calls deep to follow")
    ap.add_argument("--json", action="store_true", help="print as json")
    args = ap.parse_args()
    if idapro.open_database(args.binary, True):
        sys.exit("could not open " + args.binary)
    ida_auto.auto_wait()
    if args.json:
        out = {}
        for ea in args.ea:
            start = ida_funcs.get_func_start(ea)
            found = strings(start, args.depth) if start != ida_idaapi.BADADDR else []
            out["%#x" % ea] = [{"at": "%#x" % item, "string": text, "in": ida_name.get_name(func)} for item, _, text, func in found]
        print(json.dumps(out, indent=2))
    else:
        for ea in args.ea:
            report(ea, args.depth)
    idapro.close_database(True)


if __name__ == "__main__":
    cli() if HEADLESS else gui()
