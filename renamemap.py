import json
import re
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
import ida_idaapi
import ida_name

SIG = re.compile(r"^([0-9A-Fa-f]{2}|\?\??)( ([0-9A-Fa-f]{2}|\?\??))*$")


def resolve(loc):
    if isinstance(loc, int):
        return loc, ""
    if loc[:2].lower() == "0x":
        return int(loc, 16), ""
    if SIG.match(loc):
        lo, hi = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
        ea = ida_bytes.find_bytes(loc, lo, range_end=hi)
        if ea == ida_idaapi.BADADDR:
            return ida_idaapi.BADADDR, "no match"
        if ida_bytes.find_bytes(loc, ea + 1, range_end=hi) != ida_idaapi.BADADDR:
            return ida_idaapi.BADADDR, "several matches"
        return ea, ""
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, loc)
    return ea, "" if ea != ida_idaapi.BADADDR else "no such symbol"


def apply(names, func=False, dry=False):
    done = 0
    for name, loc in names.items():
        ea, why = resolve(loc)
        if ea == ida_idaapi.BADADDR:
            print("[-] %s: %s" % (name, why))
            continue
        if func:
            ea = ida_funcs.get_func_start(ea)
            if ea == ida_idaapi.BADADDR:
                print("[-] %s: %s is not in a function" % (name, loc))
                continue
        other = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        if other != ida_idaapi.BADADDR and other != ea:
            print("[-] %s: already used at %#x" % (name, other))
            continue
        old = ida_name.get_name(ea)
        was = " (was %s)" % old if old and old != name and not ida_bytes.has_dummy_name(ida_bytes.get_flags(ea)) else ""
        if dry or ida_name.set_name(ea, name, ida_name.SN_NOWARN):
            print("[+] %s %#x%s" % (name, ea, was))
            done += 1
        else:
            print("[-] %s: rename failed at %#x" % (name, ea))
    print("[*] %d of %d %s" % (done, len(names), "resolved" if dry else "renamed"))
    return done


def gui():
    import ida_kernwin
    path = ida_kernwin.ask_file(0, "*.json", "name map")
    if path:
        apply(json.load(open(path)))


def cli():
    import argparse
    ap = argparse.ArgumentParser(description="apply names from json keyed by address, signature or symbol (IDA 9.4)")
    ap.add_argument("binary", help="file or .i64/.idb to open")
    ap.add_argument("map", help="json of {name: 0x address | signature | symbol}")
    ap.add_argument("--func", action="store_true", help="name the function containing the address instead of the address")
    ap.add_argument("--dry", action="store_true", help="resolve and report, change nothing")
    args = ap.parse_args()
    if idapro.open_database(args.binary, True):
        sys.exit("could not open " + args.binary)
    ida_auto.auto_wait()
    names = json.load(open(args.map))
    done = apply(names, args.func, args.dry)
    idapro.close_database(True)
    sys.exit(0 if done == len(names) else 1)


if __name__ == "__main__":
    cli() if HEADLESS else gui()
