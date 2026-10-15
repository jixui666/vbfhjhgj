import struct, os, sys

def loads(path):
    d = open(path, 'rb').read()
    magic = struct.unpack_from('<I', d, 0)[0]
    off = 0
    if magic == 0xBEBAFECA and len(d) > 8:  # FAT (LE view)
        nfat = struct.unpack_from('>I', d, 4)[0]
        for i in range(nfat):
            cputype, cpusub, foff, fsize, align = struct.unpack_from('>5I', d, 8 + 8*i)
            if cputype == 0x0100000C:
                off = foff
                break
    hdr = struct.unpack_from('<7I', d, off)
    if hdr[0] != 0xFEEDFACF:
        return None
    ncmds = hdr[4]
    o = off + 32
    deps = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<2I', d, o)
        if cmd == 0xC:  # LC_LOAD_DYLIB
            name = d[o+24:o+size].split(b'\0')[0].decode(errors='replace')
            deps.append(name)
        elif cmd == 0x80000018:  # LC_LOAD_WEAK_DYLIB
            name = d[o+24:o+size].split(b'\0')[0].decode(errors='replace')
            deps.append(name + ' (weak)')
        elif cmd == 0x1F:  # LC_REEXPORT_DYLIB
            name = d[o+24:o+size].split(b'\0')[0].decode(errors='replace')
            deps.append(name + ' (reexport)')
        o += size
    return deps

bins = []
for root, dirs, files in os.walk('Frameworks'):
    for f in files:
        p = os.path.join(root, f)
        if os.path.isfile(p):
            bins.append(p)
for f in os.listdir('lara/lib'):
    p = os.path.join('lara/lib', f)
    if os.path.isfile(p):
        bins.append(p)
for p in sorted(bins):
    deps = loads(p)
    print('%s\n    deps: %s' % (p, deps if deps else '(none)'))

