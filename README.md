# ida-scripts

idapython scripts for ida 9.4. each one runs from file > script file on the cursor address, or headless from a terminal with the idalib python module installed.

## vtable2struct.py

builds a struct from a vtable and applies it at the vtable address. member names come from demangled symbols, types from the stored or guessed prototype.

```
python vtable2struct.py <binary> --ea 0x140001000 [--name cls] [--class-struct] [--rename-funcs]
python vtable2struct.py <binary> --all [--class-struct] [--rename-funcs]
```

`--all` runs over every rtti named vtable, msvc and itanium. `--class-struct` adds `<cls>` with a vtbl pointer. `--rename-funcs` renames `sub_` targets to `<cls>__vfn<n>`.

## sigmaker.py

makes and resolves byte signatures. it wildcards relative branches, rip-relative operands and address-sized immediates, and prints the pattern in ida, code + mask and x64dbg style.

```
python sigmaker.py <binary> --ea 0x140001000 [--xref]
python sigmaker.py <binary> --make list.json
python sigmaker.py <binary> --scan sigs.json
```

`--xref` signs the first code reference to the address and reports the operand offset, for globals and strings. `--make` takes `{name: address or symbol}` and prints `{name: signature}`. `--scan` takes `{name: signature}` and prints the address of each, or the match count if it broke.

mit license.
