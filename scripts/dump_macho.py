import struct
d = open(r'Frameworks/libuiopsersvc.framework/libuiopsersvc', 'rb').read()
hdr = struct.unpack_from('<7I', d, 0)
ncmds, sz = hdr[4], hdr[5]
o = 32
for i in range(ncmds):
    cmd, size = struct.unpack_from('<2I', d, o)
    if cmd == 0x19:
        seg = d[o+8:o+24].split(b'\0')[0].decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<4Q', d, o+24)
        nsects = struct.unpack_from('<I', d, o+64)[0]
        print('SEG %-16s vm 0x%x size 0x%x off 0x%x fsz 0x%x nsects=%d' % (seg, vmaddr, vmsize, fileoff, filesize, nsects))
        so = o + 72
        for j in range(nsects):
            sname = d[so:so+16].split(b'\0')[0].decode()
            addr, size2 = struct.unpack_from('<2Q', d, so+32)
            foff = struct.unpack_from('<I', d, so+48)[0]
            flags = struct.unpack_from('<I', d, so+64)[0]
            print('    %-24s vm 0x%x size 0x%x off 0x%x flags 0x%x' % (sname, addr, size2, foff, flags))
            so += 80
    elif cmd == 0x2:
        symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', d, o+8)
        print('LC_SYMTAB nsyms=%d strsize=%d' % (nsyms, strsize))
    elif cmd == 0x26:
        foff, fsize = struct.unpack_from('<2I', d, o+8)
        print('LC_FUNCTION_STARTS off 0x%x size 0x%x' % (foff, fsize))
    elif cmd == 0xB:
        print('LC_DYSYMTAB')
    o += size

