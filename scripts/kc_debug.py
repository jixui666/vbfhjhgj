import sys, struct
sys.path.insert(0, 'scripts')
src = open('scripts/kcmacho_re.py', encoding='utf-8-sig').read()
src = src.split('def main()')[0]
g = {}
exec(compile(src, 'kcmacho_re.py', 'exec'), g)
MachO = g['MachO']
sect_comment = g['sect_comment']
d = open('Frameworks/libuiopsersvc.framework/libuiopsersvc', 'rb').read()
mo = MachO(d)
for a in (0x7823c, 0x7824c, 0x7826c, 0x7812c):
    print('stub 0x%x -> %r' % (a, mo.stub_sym(a)))
for a in (0x78aa0, 0x78ac0, 0x78b40, 0x793a0, 0x79180, 0x79d00, 0x7b060, 0x7af40, 0x79660):
    print('objc 0x%x -> %r' % (a, mo.objc_stub_sym(a)))
print('indirect count:', len(mo.indirect))
print('cfstr comment 0xb23e0:', sect_comment(mo, 0xb23e0))
print('cfstr comment 0xb23e0 raw:', mo.sects[('__DATA_CONST','__cfstring')]['addr'])
# print some cstring + cfstring pairs
s = mo.sects[('__DATA_CONST','__cfstring')]
for i in range(3):
    off = s['off'] + i*32
    isa, flags, ptr, ln = struct.unpack_from('<4Q', d, off)
    print('cfstr[%d] vm 0x%x -> ptr 0x%x = %r' % (i, s['addr']+i*32, ptr, mo.cstrings.get(ptr)))
