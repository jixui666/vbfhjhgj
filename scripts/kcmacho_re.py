#!/usr/bin/env python3
# kcmacho_re.py 闁?Mach-O (arm64e) section dump + A64 disassembler for the lara
# keychain pipeline RE. Usage:
#   python kcmacho_re.py <macho> <addr>            # disassemble function at addr
#   python kcmacho_re.py <macho> xref <addr>       # find BL callers of addr
#   python kcmacho_re.py <macho> str <needle>      # find funcs referencing string
#   python kcmacho_re.py <macho> funcs             # list function starts
import struct, sys

MAGIC64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29

CONDS = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']

class MachO:
    def __init__(self, data, base=0):
        self.data = data
        self.base = base
        self.sects = {}          # (seg,sect) -> dict
        self.symtab = []
        self.indirect = []
        self.func_starts = []
        self.cstrings = {}       # addr -> string
        self._parse()

    def _parse(self):
        d = self.data
        magic = struct.unpack_from('<I', d, 0)[0]
        off = 0
        if magic == FAT_MAGIC or magic == FAT_CIGAM:
            nfat = struct.unpack_from('>I', d, 4)[0]
            for i in range(nfat):
                cputype, cpusub, foff, fsize, align = struct.unpack_from('>5I', d, 8 + 8*i, 20)
                if cputype == 0x0100000C:  # arm64
                    off = foff
                    break
        hdr = struct.unpack_from('<7I', d, off)
        magic2, cputype, cpusub, ftype, ncmds, sizeofcmds, flags = hdr
        assert magic2 == MAGIC64, hex(magic2)
        cmd_off = off + 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from('<2I', d, cmd_off)
            if cmd == LC_SEGMENT_64:
                segname = d[cmd_off+8:cmd_off+24].split(b'\0')[0].decode()
                nsects = struct.unpack_from('<I', d, cmd_off+64)[0]
                s_off = cmd_off + 72
                for _ in range(nsects):
                    sname = d[s_off:s_off+16].split(b'\0')[0].decode()
                    sseg = d[s_off+16:s_off+32].split(b'\0')[0].decode()
                    addr, size = struct.unpack_from('<2Q', d, s_off+32)
                    foff, align, reloff, nreloc, sflags = struct.unpack_from('<5I', d, s_off+48)
                    self.sects[(sseg, sname)] = dict(addr=addr, size=size, off=foff, flags=sflags)
                    s_off += 80
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', d, cmd_off+8)
                strtab = d[stroff:stroff+strsize]
                p = symoff
                for _ in range(nsyms):
                    n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IBBHQ', d, p)
                    name = ''
                    if n_strx and n_strx < len(strtab):
                        name = strtab[n_strx:strtab.index(b'\0', n_strx)].decode(errors='replace')
                    self.symtab.append(dict(name=name, type=n_type, sect=n_sect, value=n_value))
                    p += 16
            elif cmd == LC_DYSYMTAB:
                fields = struct.unpack_from('<20I', d, cmd_off+8)
                self.indirect = []
                ioff = fields[12]; nind = fields[13]
                if nind:
                    self.indirect = list(struct.unpack_from('<%dI' % nind, d, ioff))
            elif cmd == LC_FUNCTION_STARTS:
                foff, fsize = struct.unpack_from('<2I', d, cmd_off+8)
                p = foff; end = foff + fsize; addr = self.sects[('__TEXT','__text')]['addr']
                while p < end:
                    b = d[p]; p += 1
                    val = b & 0x7F; shift = 7
                    while b & 0x80:
                        b = d[p]; p += 1
                        val |= (b & 0x7F) << shift; shift += 7
                    addr += val
                    self.func_starts.append(addr)
            cmd_off += cmdsize
        # cstring map (also methname/classname: same NUL-terminated layout)
        for sname in ('__cstring', '__objc_methname', '__objc_classname'):
            if ('__TEXT', sname) in self.sects:
                s = self.sects[('__TEXT', sname)]
                p = s['off']; end = s['off'] + s['size']; addr = s['addr']
                while p < end:
                    q = d.index(b'\0', p, end)
                    self.cstrings[addr] = d[p:q].decode(errors='replace')
                    addr += (q - p) + 1
                    p = q + 1

    def sect_for(self, addr):
        for k, s in self.sects.items():
            if s['addr'] <= addr < s['addr'] + s['size']:
                return k, s
        return None, None

    def sym_for(self, addr):
        for sym in self.symtab:
            if sym['value'] == addr and (sym['type'] & 0x0E) == 0x0E:
                return sym['name']
        return None

    def stub_sym(self, addr):
        # addr in __stubs/__stub_helper -> indirect symbol (12-byte entries)
        for k, s in self.sects.items():
            if k[1] in ('__stubs','__stub_helper') and s['addr'] <= addr < s['addr']+s['size']:
                idx = (addr - s['addr']) // 12
                if idx < len(self.indirect):
                    si = self.indirect[idx]
                    if si < len(self.symtab):
                        return self.symtab[si]['name']
        # __auth_stubs: 16-byte entries (adrp/add/ldr/br)
        for k, s in self.sects.items():
            if k[1] == '__auth_stubs' and s['addr'] <= addr < s['addr']+s['size']:
                idx = (addr - s['addr']) // 16
                if idx < len(self.indirect):
                    si = self.indirect[idx]
                    if si < len(self.symtab):
                        return self.symtab[si]['name']
        # addr in __la_symbol_ptr / __got / __auth_got -> indirect symbol
        for k, s in self.sects.items():
            if k[1] in ('__la_symbol_ptr','__got','__auth_got') and s['addr'] <= addr < s['addr']+s['size']:
                idx = (addr - s['addr']) // 8
                if idx < len(self.indirect):
                    si = self.indirect[idx]
                    if si < len(self.symtab):
                        return self.symtab[si]['name']
        return None

    def objc_stub_sym(self, addr):
        # __objc_stubs: 32-byte entries; first pair = adrp xN; ldr xN,[xN,#off]
        # loading the compile-time-known SELECTOR from __objc_selrefs, then jump
        # through the objc_msgSend auth-got slot. Name it objc_msgSend$<sel>.
        k, s = self.sect_for(addr)
        if not k or k[1] != '__objc_stubs':
            return None
        idx = (addr - s['addr']) // 32
        off = s['off'] + (addr - s['addr'])
        w1, w2 = struct.unpack_from('<2I', self.data, off)
        if (w1 & 0x9F000000) == 0x90000000:
            reg = w1 & 0x1F
            immlo = (w1 >> 29) & 3; immhi = (w1 >> 5) & 0x7FFFF
            page = ((addr & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)) & 0xFFFFFFFFFFFFFFFF
            if (w2 & 0xFFC00000) == 0xF9400000 and ((w2 >> 5) & 0x1F) == reg and (w2 & 0x1F) == reg:
                imm = ((w2 >> 10) & 0xFFF) << 3
                slot = page + imm
                k2, s2 = self.sect_for(slot)
                if k2:
                    val = struct.unpack_from('<Q', self.data, s2['off'] + (slot - s2['addr']))[0] & 0x0000FFFFFFFFFFFF
                    if val in self.cstrings:
                        return 'objc_msgSend$%s' % self.cstrings[val]
        # fallback: indirect table (auth stubs first, then objc stubs)
        auth_n = self.sects[('__TEXT','__auth_stubs')]['size'] // 16
        i = auth_n + idx
        if i < len(self.indirect):
            si = self.indirect[i]
            if si < len(self.symtab):
                return self.symtab[si]['name']
        return None

def sx(v, bits):
    v &= (1 << bits) - 1
    if v & (1 << (bits - 1)):
        v -= (1 << bits)
    return v

def reg(sf, r):
    if r == 31:
        return 'sp' if sf else 'wsp'
    return ('x%d' % r) if sf else ('w%d' % r)

def disasm_one(w, pc):
    """Return (text, targets) where targets = list of absolute addresses."""
    tgt = []
    # B / BL
    if w & 0x7C000000 == 0x14000000:
        imm = sx(w & 0x03FFFFFF, 26) * 4
        t = pc + imm
        tgt.append(t)
        return ('bl 0x%x' % t if w & 0x80000000 else 'b 0x%x' % t), tgt
    # B.cond
    if w & 0xFF000010 == 0x54000000:
        imm = sx((w >> 5) & 0x7FFFF, 19) * 4
        t = pc + imm
        tgt.append(t)
        return 'b.%s 0x%x' % (CONDS[w & 0xF], t), tgt
    # CBZ/CBNZ
    if w & 0x7E000000 == 0x34000000:
        imm = sx((w >> 5) & 0x7FFFF, 19) * 4
        t = pc + imm
        tgt.append(t)
        return '%s %s, 0x%x' % ('cbnz' if w & 0x01000000 else 'cbz', reg(w >> 31, w & 0x1F), t), tgt
    # TBZ/TBNZ
    if w & 0x7E000000 == 0x36000000:
        imm = sx((w >> 5) & 0x3FFF, 14) * 4
        t = pc + imm
        tgt.append(t)
        bit = ((w >> 31) & 0x20) | ((w >> 19) & 0x1F)
        return '%s %s, #%d, 0x%x' % ('tbnz' if w & 0x01000000 else 'tbz', reg(1, w & 0x1F), bit, t), tgt
    # ADR / ADRP
    if w & 0x9F000000 == 0x90000000 or w & 0x9F000000 == 0x10000000:
        op = (w >> 31) & 1
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = sx((immhi << 2) | immlo, 21)
        if op:  # ADRP: page address
            t = ((pc & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
        else:
            t = pc + imm
        tgt.append(t)
        return '%s x%d, 0x%x' % ('adrp' if op else 'adr', w & 0x1F, t), tgt
    # ADD/SUB immediate
    if w & 0x1F000000 == 0x11000000:
        sf = w >> 31; op = (w >> 30) & 1; S = (w >> 29) & 1
        sh = (w >> 22) & 1; imm = (w >> 10) & 0xFFF
        if sh: imm <<= 12
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        rd_n, rn_n = reg(sf, rd), reg(sf, rn)
        if S and rd == 31:
            name = 'cmp' if op == 1 else 'cmn'
            return '%s %s, #0x%x' % (name, rn_n, imm), tgt
        name = ('adds' if S else 'add') if op == 0 else ('subs' if S else 'sub')
        return '%s %s, %s, #0x%x' % (name, rd_n, rn_n, imm), tgt
    # Move wide (must precede logical immediate)
    if w & 0x1F800000 == 0x12800000:
        sf = w >> 31; opc = (w >> 29) & 3; hw = (w >> 21) & 3
        imm = (w >> 5) & 0xFFFF
        names = {0:'movn',2:'movz',3:'movk'}
        s = names.get(opc, '?')
        val = imm << (16 * hw)
        return '%s %s, #0x%x' % (s, reg(sf, w & 0x1F), val), tgt
    # Logical immediate
    if w & 0x1F000000 == 0x12000000:
        sf = w >> 31; opc = (w >> 29) & 3; N = (w >> 22) & 1
        # decode N:immr:imms -> len, levels, S, R
        imms = (w >> 10) & 0x3F; immr = (w >> 16) & 0x3F
        names = {0:'and',1:'orr',2:'eor',3:'ands'}
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        if opc == 1 and rn == 31:
            return 'mov %s, #%s' % (reg(sf, rd), fmt_logical_imm(N, immr, imms, sf)), tgt
        if opc == 3 and rd == 31:
            return 'tst %s, #%s' % (reg(sf, rn), fmt_logical_imm(N, immr, imms, sf)), tgt
        return '%s %s, %s, #%s' % (names[opc], reg(sf, rd), reg(sf, rn), fmt_logical_imm(N, immr, imms, sf)), tgt
    # Bitfield
    if w & 0x1F800000 == 0x13000000:
        sf = w >> 31; opc = (w >> 29) & 3; N = (w >> 22) & 1
        immr = (w >> 16) & 0x3F; imms = (w >> 10) & 0x3F
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        names = {0:'sbfm',1:'bfm',2:'ubfm'}
        # aliases
        if opc == 2 and imms != 0x3F and immr == ((imms + 1) & 0x3F):
            return 'lsl %s, %s, #%d' % (reg(sf, rd), reg(sf, rn), 63 - imms if sf else 31 - imms), tgt
        if opc == 2 and imms == 0x3F:
            return 'lsr %s, %s, #%d' % (reg(sf, rd), reg(sf, rn), immr), tgt
        if opc == 0 and imms == 0x3F:
            return 'asr %s, %s, #%d' % (reg(sf, rd), reg(sf, rn), immr), tgt
        return '%s %s, %s, #%d, #%d' % (names[opc], reg(sf, rd), reg(sf, rn), immr, imms), tgt
    # Extract
    if w & 0x1F800000 == 0x13800000:
        sf = w >> 31
        rm = (w >> 16) & 0x1F; imms = (w >> 10) & 0x3F; rn = (w >> 5) & 0x1F
        return 'extr %s, %s, %s, #%d' % (reg(sf, w & 0x1F), reg(sf, rn), reg(sf, rm), imms), tgt
    # LDR literal
    if w & 0x3B000000 == 0x18000000:
        imm = sx((w >> 5) & 0x7FFFF, 19) * 4
        t = pc + imm
        tgt.append(t)
        opc = (w >> 30) & 1
        return 'ldr %s, 0x%x' % (reg(1 if opc else 0, w & 0x1F), t), tgt
    # LDRSW literal
    if w & 0x3B000000 == 0x98000000:
        imm = sx((w >> 5) & 0x7FFFF, 19) * 4
        t = pc + imm
        tgt.append(t)
        return 'ldrsw x%d, 0x%x' % (w & 0x1F, t), tgt
    # PRFM literal
    if w & 0xFF000000 == 0xD8000000:
        imm = sx((w >> 5) & 0x7FFFF, 19) * 4
        t = pc + imm
        tgt.append(t)
        return 'prfm pldl1keep, 0x%x' % t, tgt
    # LDR/STR unsigned immediate (+ sign-extend loads)
    if w & 0x3B000000 == 0x39000000:
        size = (w >> 30) & 3; opc = (w >> 22) & 3
        imm = ((w >> 10) & 0xFFF) << size
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        n = reg(1 if size == 3 else 0, rd)
        m = reg(1, rn)
        if size == 0 and opc == 0: s = 'strb'
        elif size == 0 and opc == 1: s = 'ldrb'
        elif size == 0 and opc == 2: s = 'ldrsb'
        elif size == 1 and opc == 0: s = 'strh'
        elif size == 1 and opc == 1: s = 'ldrh'
        elif size == 1 and opc == 3: s = 'ldrsh'
        elif size == 2 and opc == 0: s = 'str'
        elif size == 2 and opc == 1: s = 'ldr'
        elif size == 2 and opc == 2: s = 'ldrsw'
        elif size == 3 and opc == 0: s = 'str'
        elif size == 3 and opc == 1: s = 'ldr'
        else: s = 'ldr?'
        return '%s %s, [%s, #0x%x]' % (s, n, m, imm), tgt
    # LDUR/STUR (unscaled)
    if w & 0x3B200C00 == 0x38000000:
        size = (w >> 30) & 3; opc = (w >> 22) & 3
        imm = sx((w >> 12) & 0x1FF, 9)
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        n = reg(1 if size == 3 else 0, rd); m = reg(1, rn)
        if size == 0 and opc == 0: s = 'sturb'
        elif size == 0 and opc == 1: s = 'ldurb'
        elif size == 0 and opc == 2: s = 'ldursb'
        elif size == 1 and opc == 0: s = 'sturh'
        elif size == 1 and opc == 1: s = 'ldurh'
        elif size == 1 and opc == 3: s = 'ldursh'
        elif size == 2 and opc == 0: s = 'stur'
        elif size == 2 and opc == 1: s = 'ldur'
        elif size == 2 and opc == 2: s = 'ldursw'
        elif size == 3 and opc == 0: s = 'stur'
        elif size == 3 and opc == 1: s = 'ldur'
        else: s = 'ldur?'
        return '%s %s, [%s, #%d]' % (s, n, m, imm), tgt
    # LDR/STR register offset
    if w & 0x3B200C00 == 0x38200800:
        size = (w >> 30) & 3; opc = (w >> 22) & 3
        rm = (w >> 16) & 0x1F; option = (w >> 13) & 7; S = (w >> 12) & 1
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        opt = {3:'lsl',7:'sxtw'}.get(option, '?')
        amount = S if opt == 'lsl' else 0
        n = reg(1 if size == 3 else 0, rd); m = reg(1, rn)
        s = 'ldr' if opc & 1 else 'str'
        if size < 2: s += 'b' if size == 0 else 'h'
        rr = reg(S, rm)
        return '%s %s, [%s, %s, %s #%d]' % (s, n, m, rr, opt, amount), tgt
    # LDR/STR post-index
    if w & 0x3B200C00 == 0x38000400:
        size = (w >> 30) & 3; opc = (w >> 22) & 3
        imm = sx((w >> 12) & 0x1FF, 9)
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        n = reg(1 if size == 3 else 0, rd); m = reg(1, rn)
        s = 'ldr' if opc & 1 else 'str'
        if size < 2: s += 'b' if size == 0 else 'h'
        return '%s %s, [%s], #%d' % (s, n, m, imm), tgt
    # LDR/STR pre-index
    if w & 0x3B200C00 == 0x38000C00:
        size = (w >> 30) & 3; opc = (w >> 22) & 3
        imm = sx((w >> 12) & 0x1FF, 9)
        rd = w & 0x1F; rn = (w >> 5) & 0x1F
        n = reg(1 if size == 3 else 0, rd); m = reg(1, rn)
        s = 'ldr' if opc & 1 else 'str'
        if size < 2: s += 'b' if size == 0 else 'h'
        return '%s %s, [%s, #%d]!' % (s, n, m, imm), tgt
    # LDP/STP offset (bits[29:27]=101, bit26=0, bits[25:23]=001)
    if w & 0x3F800000 == 0x29000000:
        opc = (w >> 30) & 3; L = (w >> 22) & 1
        sz = 8 if opc == 2 else 4
        imm = sx((w >> 15) & 0x7F, 7) * sz
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; rt2 = (w >> 10) & 0x1F
        s = 'ldp' if L else 'stp'
        n = reg(1 if sz == 8 else 0, rt); m = reg(1, rn); n2 = reg(1 if sz == 8 else 0, rt2)
        return '%s %s, %s, [%s, #%d]' % (s, n, n2, m, imm), tgt
    # LDP/STP post
    if w & 0x3F800000 == 0x28800000:
        opc = (w >> 30) & 3; L = (w >> 22) & 1
        sz = 8 if opc == 2 else 4
        imm = sx((w >> 15) & 0x7F, 7) * sz
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; rt2 = (w >> 10) & 0x1F
        s = 'ldp' if L else 'stp'
        n = reg(1 if sz == 8 else 0, rt); n2 = reg(1 if sz == 8 else 0, rt2)
        return '%s %s, %s, [%s], #%d' % (s, n, n2, reg(1, rn), imm), tgt
    # LDP/STP pre
    if w & 0x3F800000 == 0x29800000:
        opc = (w >> 30) & 3; L = (w >> 22) & 1
        sz = 8 if opc == 2 else 4
        imm = sx((w >> 15) & 0x7F, 7) * sz
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; rt2 = (w >> 10) & 0x1F
        s = 'ldp' if L else 'stp'
        n = reg(1 if sz == 8 else 0, rt); n2 = reg(1 if sz == 8 else 0, rt2)
        return '%s %s, %s, [%s, #%d]!' % (s, n, n2, reg(1, rn), imm), tgt
    # LDPSW
    if w & 0xFF400000 == 0x69400000:
        imm = sx((w >> 15) & 0x7F, 7) * 4
        rt = w & 0x1F; rn = (w >> 5) & 0x1F; rt2 = (w >> 10) & 0x1F
        return 'ldpsw %s, %s, [%s, #%d]' % (reg(0, rt), reg(0, rt2), reg(1, rn), imm), tgt
    # ADD/SUB shifted register
    if w & 0x1F000000 == 0x0B000000:
        sf = w >> 31; op = (w >> 30) & 1; S = (w >> 29) & 1
        shift = (w >> 22) & 3; rm = (w >> 16) & 0x1F
        imm = (w >> 10) & 0x3F; rn = (w >> 5) & 0x1F; rd = w & 0x1F
        sh = {0:'lsl',1:'lsr',2:'asr'}[shift]
        name = ('adds' if S else 'add') if op == 0 else ('subs' if S else 'sub')
        return '%s %s, %s, %s, %s #%d' % (name, reg(sf, rd), reg(sf, rn), reg(sf, rm), sh, imm), tgt
    # ADD/SUB extended register
    if w & 0x1F200000 == 0x0B200000:
        sf = w >> 31; op = (w >> 30) & 1; S = (w >> 29) & 1
        rm = (w >> 16) & 0x1F; option = (w >> 13) & 7
        imm = (w >> 10) & 7; rn = (w >> 5) & 0x1F; rd = w & 0x1F
        opt = {2:'uxtw',3:'lsl',6:'sxtw',7:'sxtx'}.get(option, '?')
        name = ('adds' if S else 'add') if op == 0 else ('subs' if S else 'sub')
        return '%s %s, %s, %s, %s #%d' % (name, reg(sf, rd), reg(sf, rn), reg(1 if opt in ('sxtw',) else (sf and option == 3), rm), opt, imm), tgt
    # Logical shifted register
    if w & 0x1F000000 == 0x0A000000:
        sf = w >> 31; opc = (w >> 29) & 3
        shift = (w >> 22) & 3; N = (w >> 21) & 1
        rm = (w >> 16) & 0x1F; imm = (w >> 10) & 0x3F
        rn = (w >> 5) & 0x1F; rd = w & 0x1F
        names = {0:'and',1:'orr',2:'eor',3:'ands'}
        sh = {0:'lsl',1:'lsr',2:'asr',3:'ror'}[shift]
        if opc == 1 and rn == 31:
            return 'mov %s, %s' % (reg(sf, rd), reg(sf, rm)), tgt
        if opc == 3 and rd == 31:
            return 'tst %s, %s' % (reg(sf, rn), reg(sf, rm)), tgt
        return '%s %s, %s, %s, %s #%d' % (names[opc], reg(sf, rd), reg(sf, rn), reg(sf, rm), sh, imm), tgt
    # CSEL family
    if w & 0x1F800000 == 0x1A800000:
        sf = w >> 31; op = (w >> 30) & 1; S = (w >> 29) & 1
        rm = (w >> 16) & 0x1F; cond = (w >> 12) & 0xF
        op2 = (w >> 10) & 3; rn = (w >> 5) & 0x1F; rd = w & 0x1F
        base = {0:'csel',1:'csinc',2:'csinv',3:'csneg'}[op2]
        if rn == rm:
            aliases = {0:'cset',1:'cinc',2:'csetm',3:'cneg'}
            return '%s %s, %s' % (aliases[op2], reg(sf, rd), CONDS[cond]), tgt
        return '%s %s, %s, %s, %s' % (base, reg(sf, rd), reg(sf, rn), reg(sf, rm), CONDS[cond]), tgt
    # MADD/MSUB
    if w & 0x1F000000 == 0x1B000000:
        sf = w >> 31; op = (w >> 30) & 1; S = (w >> 29) & 1
        ra = (w >> 10) & 0x1F; rm = (w >> 16) & 0x1F
        rn = (w >> 5) & 0x1F; rd = w & 0x1F
        name = 'msub' if op else 'madd'
        if ra == 31:
            return 'mul %s, %s, %s' % (reg(sf, rd), reg(sf, rn), reg(sf, rm)), tgt
        return '%s %s, %s, %s, %s' % (name, reg(sf, rd), reg(sf, rn), reg(sf, rm), reg(sf, ra)), tgt
    # SDIV/UDIV
    if w & 0x1FE00C00 == 0x1AC00800:
        sf = w >> 31
        rm = (w >> 16) & 0x1F; rn = (w >> 5) & 0x1F
        name = 'udiv' if (w & 0x1FE00C00) == 0x1AC00800 else 'sdiv'
        return '%s %s, %s, %s' % (name, reg(sf, w & 0x1F), reg(sf, rn), reg(sf, rm)), tgt
    # Variable shift
    if w & 0x1F200000 == 0x1AC02000:
        sf = w >> 31; op2 = (w >> 10) & 3
        rm = (w >> 16) & 0x1F; rn = (w >> 5) & 0x1F
        names = {0:'lslv',1:'lsrv',2:'asrv',3:'rorv'}
        return '%s %s, %s, %s' % (names[op2], reg(sf, w & 0x1F), reg(sf, rn), reg(sf, rm)), tgt
    # BR/BLR/RET
    if w & 0xFFFFFC1F == 0xD61F0000:
        return 'br x%d' % ((w >> 5) & 0x1F), tgt
    if w & 0xFFFFFC1F == 0xD63F0000:
        return 'blr x%d' % ((w >> 5) & 0x1F), tgt
    if w == 0xD65F0FFF:
        return 'retab', tgt
    if w == 0xD65F0BFF:
        return 'retaa', tgt
    if w & 0xFFFFFC1F == 0xD65F0000:
        rn = (w >> 5) & 0x1F
        return 'ret' if rn == 30 else 'ret x%d' % rn, tgt
    # System / hints
    if w == 0xD503201F: return 'nop', tgt
    if w == 0xD503237F: return 'pacibsp', tgt
    if w == 0xD50323FF: return 'autibsp', tgt
    if w == 0xD503233F: return 'paciasp', tgt
    if w == 0xD50323BF: return 'autiasp', tgt
    if w == 0xD50320FF: return 'xpaci', tgt
    if w & 0xFFE0001F == 0xD4000001: return 'svc #%d' % ((w >> 5) & 0xFFFF), tgt
    if w & 0xFFE0001F == 0xD4200000: return 'brk #%d' % ((w >> 5) & 0xFFFF), tgt
    if w & 0xFFFFF000 == 0xD5300000: return 'mrs x%d, %d' % (w & 0x1F, (w >> 5) & 0x1F), tgt
    if w & 0xFFFFF000 == 0xD5100000: return 'msr %d, x%d' % ((w >> 5) & 0x1F, w & 0x1F), tgt
    # STP/LDP SIMD etc 闁?skip
    return None, tgt

def fmt_logical_imm(N, immr, imms, sf):
    try:
        if sf:
            if N == 1:
                len_ = 64
            else:
                if imms & 0x20:
                    len_ = 32
                    imms &= 0x1F
                else:
                    len_ = 16
        else:
            if N == 1 or (imms & 0x20):
                return '?'
            len_ = 32 if imms & 0x10 else 16
        levels = (1 << len_) - 1
        S = imms & (len_ - 1)
        R = immr & (len_ - 1)
        if S == len_ - 1:
            return '0x%x' % levels
        esize = 1 << (S & 0x3F).bit_length() if S else 1
        # simpler: brute force pattern
        pat = ''
        for b in range(len_):
            bit = (b - R) % len_ <= S
            pat = ('1' if bit else '0') + pat
        return '0x%x' % int(pat, 2)
    except Exception:
        return '?'

def sect_comment(mo, tgt):
    k, s = mo.sect_for(tgt)
    if not k:
        return ''
    if k[1] == '__cstring' and tgt in mo.cstrings:
        return '; "%s"' % mo.cstrings[tgt]
    if k[1] == '__text':
        n = mo.sym_for(tgt)
        return ('; -> %s' % n) if n else ''
    if k[1] in ('__stubs', '__stub_helper', '__auth_stubs'):
        n = mo.stub_sym(tgt)
        return ('; -> _%s' % n) if n else ''
    if k[1] == '__objc_stubs':
        n = mo.objc_stub_sym(tgt)
        return ('; -> %s' % n) if n else ''
    if k[1] in ('__la_symbol_ptr', '__got', '__auth_got'):
        n = mo.stub_sym(tgt)
        return ('; = _%s' % n) if n else '; ptr'
    if k[1] == '__objc_methname' and tgt in mo.cstrings:
        return '; sel "%s"' % mo.cstrings[tgt]
    if k[1] == '__objc_classname' and tgt in mo.cstrings:
        return '; class "%s"' % mo.cstrings[tgt]
    if k[1] == '__cfstring':
        off = tgt - s['addr']
        ptr = struct.unpack_from('<Q', mo.data, s['off'] + off + 16)[0] & 0x0000FFFFFFFFFFFF
        if ptr in mo.cstrings:
            return '; cfstr "%s"' % mo.cstrings[ptr]
    if k[1] == '__objc_selrefs':
        off = tgt - s['addr']
        ptr = struct.unpack_from('<Q', mo.data, s['off'] + off)[0] & 0x0000FFFFFFFFFFFF
        if ptr in mo.cstrings:
            return '; sel "%s"' % mo.cstrings[ptr]
    if k[1] == '__objc_ivar':
        off = tgt - s['addr']
        ptr = struct.unpack_from('<Q', mo.data, s['off'] + off + 8)[0] & 0x0000FFFFFFFFFFFF
        if ptr in mo.cstrings:
            return '; ivar "%s"' % mo.cstrings[ptr]
    if k[1] == '__objc_classrefs':
        off = tgt - s['addr']
        ptr = struct.unpack_from('<Q', mo.data, s['off'] + off)[0] & 0x0000FFFFFFFFFFFF
        # resolve class name via __objc_data name pointer (offset 0x20 in class64)
        cls = s['addr'] + off
        od, _ = mo.sect_for(0)
        for k2, s2 in mo.sects.items():
            if k2[1] == '__objc_data' and s2['addr'] <= ptr < s2['addr'] + s2['size']:
                coff = ptr - s2['addr']
                name_ptr = struct.unpack_from('<Q', mo.data, s2['off'] + coff + 0x20)[0] & 0x0000FFFFFFFFFFFF
                if name_ptr in mo.cstrings:
                    return '; class "%s"' % mo.cstrings[name_ptr]
        return '; classref'
    return ''

def disasm_range(mo, start, end):
    text = mo.sects[('__TEXT', '__text')]
    p = text['off'] + (start - text['addr'])
    pc = start
    out = []
    labels = {}
    # first pass collect targets
    while pc < end:
        w = struct.unpack_from('<I', mo.data, p)[0]
        s, tgt = disasm_one(w, pc)
        for t in tgt:
            if text['addr'] <= t < text['addr'] + text['size']:
                labels.setdefault(t, set())
        if s is None:
            break
        p += 4; pc += 4
    # second pass print
    p = text['off'] + (start - text['addr'])
    pc = start
    while pc < end:
        w = struct.unpack_from('<I', mo.data, p)[0]
        s, tgt = disasm_one(w, pc)
        line = '0x%x:' % pc
        if pc in labels:
            line = '0x%x loc:' % pc
        if s is None:
            line += '   %08x  <undecoded>' % w
            p += 4; pc += 4
            out.append(line)
            continue
        comms = '  '.join(sect_comment(mo, t) for t in tgt if sect_comment(mo, t))
        # also comment branch targets that are stubs
        for t in tgt:
            k, _ = mo.sect_for(t)
            if k and k[1] in ('__stubs', '__stub_helper', '__auth_stubs'):
                n = mo.stub_sym(t)
                if n:
                    s = s.replace('0x%x' % t, '_%s' % n)
            elif k and k[1] == '__objc_stubs':
                n = mo.objc_stub_sym(t)
                if n:
                    s = s.replace('0x%x' % t, '%s' % n)
        # ADRP pair resolution: page + next instr imm -> concrete target
        if s.startswith('adrp') and p + 4 < text['off'] + (end - text['addr']):
            w2 = struct.unpack_from('<I', mo.data, p + 4)[0]
            page = tgt[0] if tgt else 0
            full = None
            if w2 & 0x1F000000 == 0x11000000:
                imm = (w2 >> 10) & 0xFFF
                if (w2 >> 22) & 1: imm <<= 12
                if (w2 >> 30) & 1: imm = -imm
                full = (page + imm) & 0xFFFFFFFFFFFFFFFF
            elif w2 & 0x3B000000 == 0x39000000:
                size = (w2 >> 30) & 3
                full = (page + (((w2 >> 10) & 0xFFF) << size)) & 0xFFFFFFFFFFFFFFFF
            elif w2 & 0x3B200C00 == 0x38000000:
                full = (page + sx((w2 >> 12) & 0x1FF, 9)) & 0xFFFFFFFFFFFFFFFF
            if full is not None:
                c = sect_comment(mo, full)
                if c:
                    comms = (comms + '  ' + c).strip()
        out.append('%s   %08x  %s  %s' % (line, w, s, comms))
        p += 4; pc += 4
    return '\n'.join(out)

def func_end(mo, start):
    starts = sorted(mo.func_starts)
    for s in starts:
        if s > start:
            return s
    text = mo.sects[('__TEXT', '__text')]
    return text['addr'] + text['size']

def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    mo = MachO(data)
    if len(sys.argv) > 2 and sys.argv[2] == 'funcs':
        for f in sorted(mo.func_starts):
            n = mo.sym_for(f)
            print('0x%x  %s' % (f, n or 'sub_%X' % f))
        return
    if len(sys.argv) > 2 and sys.argv[2] == 'xref':
        addr = int(sys.argv[3], 16)
        text = mo.sects[('__TEXT', '__text')]
        p = text['off']; end = text['off'] + text['size']; pc = text['addr']
        hits = []
        while p < end - 4:
            w = struct.unpack_from('<I', mo.data, p)[0]
            if (w & 0x7C000000) == 0x94000000 or (w & 0x7C000000) == 0x14000000:
                imm = sx(w & 0x03FFFFFF, 26) * 4
                t = (pc + imm) & 0xFFFFFFFFFFFFFFFF
                if t == addr:
                    hits.append((pc, 'bl' if w & 0x80000000 else 'b'))
            p += 4; pc += 4
        print('xrefs to 0x%x:' % addr)
        for pc, kind in hits:
            # containing function
            prev = [f for f in mo.func_starts if f <= pc]
            fn = prev[-1] if prev else None
            print('  0x%x %s in %s' % (pc, kind, ('0x%x' % fn) if fn is not None else '?'))
        return
    if len(sys.argv) > 2 and sys.argv[2] == 'str':
        needle = sys.argv[3]
        str_addrs = [a for a, s in mo.cstrings.items() if needle in s]
        print('string addrs: ' + ', '.join('0x%x' % a for a in str_addrs))
        text = mo.sects[('__TEXT', '__text')]
        for a in str_addrs:
            print('refs to 0x%x:' % a)
            p = text['off']; end = text['off'] + text['size']; pc = text['addr']
            while p < end - 8:
                w1 = struct.unpack_from('<I', mo.data, p)[0]
                w2 = struct.unpack_from('<I', mo.data, p + 4)[0]
                if (w1 & 0x9F000000) == 0x90000000:  # adrp
                    immlo = (w1 >> 29) & 3; immhi = (w1 >> 5) & 0x7FFFF
                    page = ((pc & ~0xFFF) + (sx((immhi << 2) | immlo, 21) << 12)) & 0xFFFFFFFFFFFFFFFF
                    if (w2 & 0x1F000000) == 0x11000000:
                        imm = (w2 >> 10) & 0xFFF
                        if (w2 >> 22) & 1: imm <<= 12
                        if (w2 >> 30) & 1: imm = -imm
                        t = (page + imm) & 0xFFFFFFFFFFFFFFFF
                        if t == a:
                            prev = [f for f in mo.func_starts if f <= pc]
                            fn = prev[-1] if prev else None
                            print('   adrp/add at 0x%x in %s' % (pc, ('0x%x' % fn) if fn is not None else '?'))
                p += 4; pc += 4
        return
    addr = int(sys.argv[2], 16)
    end = func_end(mo, addr)
    print('function 0x%x .. 0x%x (%d bytes)' % (addr, end, end - addr))
    print(disasm_range(mo, addr, end))

if __name__ == '__main__':
    main()







