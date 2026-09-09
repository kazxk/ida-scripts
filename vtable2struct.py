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
import ida_nalt
import ida_segment
import ida_typeinf
import ida_xref
import idautils

MAX_SLOTS = 2048
OPERATORS = {"==": "eq", "!=": "ne", "<": "lt", ">": "gt", "<=": "le", ">=": "ge"}


def psize():
    return 8 if ida_ida.inf_is_64bit() else 4


def demangled(ea):
    return ida_name.demangle_name(ida_name.get_name(ea), ida_name.MNG_SHORT_FORM) or ""


def sanitize(s):
    s = re.sub(r"[^0-9A-Za-z_]+", "_", s).strip("_")
    return "_" + s if s[:1].isdigit() else s


def slots(ea):
    ps = psize()
    read = ida_bytes.get_qword if ps == 8 else ida_bytes.get_dword
    seg = ida_segment.segment_info_t()
    if not ida_segment.get_segment_info(seg, ea):
        return []
    out = []
    while len(out) < MAX_SLOTS and ea + ps <= seg.end_ea:
        if out and (ida_name.get_name(ea) or ida_xref.get_first_dref_to(ea) != ida_idaapi.BADADDR):
            break
        t = read(ea)
        if ida_funcs.get_func_start(t) != t:
            break
        out.append(t)
        ea += ps
    return out


def rtti_base(ea):
    ps = psize()
    col = (ida_bytes.get_qword if ps == 8 else ida_bytes.get_dword)(ea - ps)
    if not ida_segment.get_segment_info(None, col):
        return None
    offset = ida_bytes.get_dword(col + 4)
    base = ida_nalt.get_imagebase() if ps == 8 else 0
    chd = base + ida_bytes.get_dword(col + 16)
    bca = base + ida_bytes.get_dword(chd + 12)
    for i in range(ida_bytes.get_dword(chd + 8)):
        bcd = base + ida_bytes.get_dword(bca + 4 * i)
        m = re.match(r"(.+?)::`RTTI Base Class Descriptor", demangled(bcd))
        if offset and ida_bytes.get_dword(bcd + 8) == offset and m:
            return sanitize(m.group(1))
    return None


def class_name(ea):
    m = re.match(r"(?:const )?(.+?)::`vftable'(?:\{for `(.+?)'\})?$", demangled(ea))
    if m:
        base = sanitize(m.group(2)) if m.group(2) else rtti_base(ea)
        suffix = re.search(r"@_(\d+)$", ida_name.get_name(ea))
        return sanitize(m.group(1)) + ("_for_" + base if base else "_" + suffix.group(1) if suffix else "")
    m = re.match(r"`vtable for'(.+)$", demangled(ea))
    return sanitize(m.group(1)) if m else "vtbl_%X" % ea


def method_name(t, i):
    name = ida_name.get_name(t)
    if ida_bytes.has_dummy_name(ida_bytes.get_flags(t)):
        return "vfn%d" % i
    if "purecall" in name:
        return "purecall"
    dem = demangled(t).split("(")[0].rsplit("::", 1)[-1].strip()
    if dem.startswith("~"):
        return "dtor"
    if "deleting destructor" in dem:
        return ("" if dem.startswith("`scalar") else "vector_") + "deleting_dtor"
    if dem.startswith("operator"):
        op = dem[8:].strip()
        return "operator_" + OPERATORS.get(op, sanitize(op))
    return sanitize(dem or name) or "vfn%d" % i


def func_type(t):
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, t) and ida_typeinf.guess_tinfo(tif, t) != ida_typeinf.GUESS_FUNC_OK:
        tif.clear()
    if not tif.is_func():
        msvc = ida_ida.inf_get_cc_id() & ida_typeinf.COMP_MASK == ida_typeinf.COMP_MS
        cc = "__fastcall" if psize() == 8 else "__thiscall" if msvc else "__cdecl"
        ida_typeinf.parse_decl(tif, None, "void %s f(void *);" % cc, ida_typeinf.PT_SIL)
    ptr = ida_typeinf.tinfo_t()
    ptr.create_ptr(tif)
    return ptr


def make_vtable_struct(ea, cls=None, class_struct=False, rename=False):
    cls = cls or class_name(ea)
    targets = slots(ea)
    if not targets:
        print("[-] %#x: no function slots found" % ea)
        return None
    ps = psize()
    udt = ida_typeinf.udt_type_data_t()
    names = set()
    for i, t in enumerate(targets):
        name = method_name(t, i)
        name = "%s_%d" % (name, i) if name in names else name
        names.add(name)
        udt.push_back(ida_typeinf.udm_t(name, func_type(t), i * ps * 8))
    udt.taudt_bits |= ida_typeinf.TAUDT_VFTABLE
    tif = ida_typeinf.tinfo_t()
    tif.create_udt(udt)
    if tif.set_named_type(None, cls + "_vtbl", ida_typeinf.NTF_REPLACE) != ida_typeinf.TERR_OK:
        print("[-] %#x: could not create %s_vtbl" % (ea, cls))
        return None
    tif.get_named_type(None, cls + "_vtbl")
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(targets) * ps)
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
    ida_typeinf.set_vftable_ea(tif.get_ordinal(), ea)
    if not ida_name.get_name(ea):
        ida_name.set_name(ea, cls + "_vtbl", ida_name.SN_NOWARN)
    if class_struct and not ida_typeinf.tinfo_t().get_named_type(None, cls):
        ida_typeinf.idc_parse_types("struct __cppobj %s { %s_vtbl *vtbl; };" % (cls, cls), 0)
    if rename:
        for i, t in enumerate(targets):
            if ida_bytes.has_dummy_name(ida_bytes.get_flags(t)):
                ida_name.set_name(t, "%s__vfn%d" % (cls, i), ida_name.SN_NOWARN)
    print("[+] %#x: %s_vtbl, %d slots" % (ea, cls, len(targets)))
    return cls + "_vtbl", len(targets)


def gui():
    import ida_kernwin
    ea = ida_kernwin.ask_addr(ida_kernwin.get_screen_ea(), "Vtable start address")
    cls = ea is not None and ida_kernwin.ask_str(class_name(ea), ida_kernwin.HIST_IDENT, "Class name")
    if cls:
        make_vtable_struct(ea, cls, class_struct=True)


def cli():
    import argparse
    ap = argparse.ArgumentParser(description="build a struct from a vtable and apply it at its address (IDA 9.4)")
    ap.add_argument("binary", help="file or .i64/.idb to open")
    ap.add_argument("--ea", type=lambda s: int(s, 0), help="vtable start address")
    ap.add_argument("--name", help="class name, default is taken from the vtable symbol")
    ap.add_argument("--all", action="store_true", help="every RTTI named vtable (??_7 and _ZTV)")
    ap.add_argument("--class-struct", action="store_true", help="also create <class> with a vtbl pointer")
    ap.add_argument("--rename-funcs", action="store_true", help="rename sub_ targets to <class>__vfn<n>")
    ap.add_argument("--save", action="store_true", help="save the database")
    args = ap.parse_args()
    if args.ea is None and not args.all:
        ap.error("need --ea or --all")
    if idapro.open_database(args.binary, True):
        sys.exit("could not open " + args.binary)
    ida_auto.auto_wait()
    if args.all:
        skip = 2 * psize()
        eas = [ea + (skip if n.startswith("_ZTV") else 0) for ea, n in idautils.Names() if n.startswith(("??_7", "_ZTV"))]
    else:
        eas = [args.ea]
    failed = [ea for ea in eas if not make_vtable_struct(ea, None if args.all else args.name, args.class_struct, args.rename_funcs)]
    idapro.close_database(args.save)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    cli() if HEADLESS else gui()
