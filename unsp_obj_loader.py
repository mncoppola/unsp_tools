# Loader for u'nSP .obj files extracted from .lib

NAME = "SunPlus u'nSP ObjFile"

import ctypes
idaname = "ida64" if __EA64__ else "ida"
if sys.platform == "win32":
    ida_dll = ctypes.windll[idaname + ".wll"]
elif sys.platform == "linux2":
    ida_dll = ctypes.cdll["lib" + idaname + ".so"]
elif sys.platform == "darwin":
    ida_dll = ctypes.cdll["lib" + idaname + ".dylib"]
_mem2base = ida_dll.mem2base
_mem2base.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int32]

def read_str(fh):
    slen = struct.unpack("<L", fh.read(4))[0]
    s = fh.read(slen)
    return s

def read_str_tab(fh):
    l = []
    tlen = struct.unpack("<H", fh.read(2))[0]
    for idx in range(tlen):
        slen = struct.unpack("<L", fh.read(4))[0]
        assert slen < 0x800
        s = fh.read(slen)
        l.append(s)
    return l

from collections import namedtuple, defaultdict
Section = namedtuple("Section", ["name", "into", "size"])
def read_sec_table(fh):
    tsize = struct.unpack("<H", fh.read(2))[0]

    secs = {}
    for i in range(tsize):
        sname = fh.read(0x40).rstrip('\x00')
        overlap = struct.unpack("<H", fh.read(2))[0]

        tent = fh.read(0x14)
        assert tent[4:] == '\x00' * (len(tent) -4)

        size = struct.unpack("<L", tent[:4])[0]
        secs[i] = Section(sname, overlap, size)
    return secs



Symbol = namedtuple("Symbol", ["name", "sect", "addr", "is_const"])

def read_sym_table(fh, sections, is_def=False):
    syms = {}
    n = struct.unpack("<H",fh.read(2))[0]
    for x in range(n):
        sym = fh.read(0x21).rstrip("\x00")
        rem = fh.read(0x10)
        addr = struct.unpack("<L",rem[:4])[0]
        rem = rem[4:]
        
        typ = ord(rem[0])
        tstr = " "
        assert typ <= 1
        if typ == 1:
            tstr = 'V' # Symbol is a literal value, not an address

        rem = rem[1:]
        assert rem[:6] == "\x00" * 6
        sect = struct.unpack("<H", rem[6:8])[0]
        if not is_def:
            assert sect == 0
            sect_name = ""
        else:
            sect_name = sections[sect].name
            sect_size = sections[sect].size

        symb = Symbol(sym, sect, addr, typ == 1)
        syms[x] = symb

        assert rem[8:0xA] == '\x00\x00'
        is_priv = ord(rem[0xA])
        assert is_priv <=1

        pstr = ' '
        if not is_priv:
            pstr = 'P'

        #print "\t\t%04x %s%s %-32s %08x %s" %(x, tstr,pstr, sym, addr,
        #                                    sect_name)
        if typ == 0 and is_def:
            assert addr <= sect_size
    return syms

def accept_file(li, n):
    if n > 0:
        return 0

    li.seek(0)

    magic = li.read(0x20)
    if magic.rstrip("\x00") == "Sunnorth&SunplusObj":
        return NAME

    return 0


def read_0x15_rec(fh, imp_d, sect_bases, sect_offs):
    dat = fh.read(2)
    if not dat:
        return False

    a,sel = struct.unpack("BB", dat)

    if sel == 0:
        return False
    elif sel == 6:
        payload = fh.read(0xa)
        p2size = struct.unpack("<L", fh.read(4))[0]
        chunk = fh.read(p2size)
        p3 = fh.read(0x5)

        assert payload[:3] == '\x00\x00\x00'
        assert payload[4] == '\x00'
        assert payload[-1] == '\x02'
        assert a == 0

        sect, startline = struct.unpack("<HL", payload[3:-1])

        #print "%-40s %08x <= %08x+%08x" % (sectab[sect].name, sectab[sect].size,
                                          #add1, p2size)
        #assert (add1 + p2size) <= sectab[sect].size

        # Seems to always be '\x03'
        assert p3[0] == '\x03'
        p3size = struct.unpack("<L",p3[1:])[0]

        
        # Save the chunk (do relocs later)
        _mem2base(chunk, sect_offs[sect], sect_offs[sect] + p2size/2, -1) 

        ts = 0
        for i in range(p3size):
            b = fh.read(0x11)
            fixpoint, reloc_type, offset,base, lineafter = struct.unpack("<LBLHL", b[:15])
            if base & 0x8000:
                fix_val = imp_d[base&0x7ff] + offset
            else:
                fix_val = sect_bases[base] + offset 

            #if base & 0x8000:
            #    obstr = "%s" % (imptab[base&0x7FFF].name,)
            #else:
            #    obstr = "%s" % (sectab[base].name,)
            ts += reloc_type
            #print "\t\t\t%08x %02x %32s:%-6x (LineA: %d)" % (
            #    fixpoint,reloc_type,obstr,offset, lineafter), b[15:].encode("hex")

            fp = fixpoint 
            #print "\t\t\t\t%s %s" % (
            #    pay2[fp-2:fp].encode('hex'),
            #    pay2[fp:fp+8].encode('hex')
            #)


            if reloc_type == 4:
                o = 0
                #d = struct.unpack("<H", chunk[fp:fp+2])[0]
                #assert d == offset
            elif reloc_type == 7:
                o = 1
                #d = struct.unpack("<H", chunk[fp+2:fp+4])[0]
                #assert d == offset
            elif reloc_type == 9:
                o = 2
                #d = struct.unpack("<H", chunk[fp+4:fp+6])[0]
                #assert d == offset
            else:
                assert False

            print("%08x" % (sect_offs[sect] + fixpoint/2 + o))
            idaapi.put_byte(sect_offs[sect] + fixpoint/2 + o,fix_val)


            # The fixup inside the buffer must be within the size of the data
            assert fixpoint < p2size
            # As its a word arch, fixups are on word boundaries
            assert fixpoint % 2 == 0

            # LMA
            assert lineafter >= startline
            #assert addr_at_reloc <= (add1 + p2size)

            assert reloc_type in (4,7,9)

        sect_offs[sect] += p2size/2
    else: 
        print "Unknown selector %x at %x" % (sel, fh.tell())
        return False

    return True

def load_file(li, neflags, format):
    if format == NAME:
        # Set the procesor type
        idaapi.set_processor_type('unsp', SETPROC_ALL|SETPROC_FATAL)

        li.seek(0)
        magic = li.read(0x20)
        if magic.rstrip("\x00") != "Sunnorth&SunplusObj":
            return 0

        vers = li.read(4).rstrip()
        unk = li.read(6)

        source_files = read_str_tab(li)
        sections = read_sec_table(li)

        imptab = read_sym_table(li, sections)
        exptab = read_sym_table(li, sections, True)
        private = read_sym_table(li, sections, True)
 
        # Setup the final image layout

        # Final merged section sizes
        #section_sizes = defaultdict(int)
        section_offsets = {}
        section_bases = {}

        if 0:
            section_akas = defaultdict(list)
            section_final_map = {}
            final_sections = set()

            for n, section in sections.items():
                orig_n = n

                while section.into != n:
                    n = section.into
                    section = sections[n]

                section_sizes[n] += sections[orig_n].size

                section_final_map[orig_n] = n
                if (n != orig_n):
                    section_akas[n].append(sections[orig_n].name)
                final_sections.add(n)

        ea = 0
        for n in sections:
            section_offsets[n] = ea
            section_bases[n] = ea

            start = ea
            ea += sections[n].size
            end = ea

            if sections[n].size:
                AddSeg(start, end, 0, 1, idaapi.saRelPara, idaapi.scPub)
                RenameSeg(start, sections[n].name)
                #MakeComm(start, "Seg AKA: %s" % ",".join(section_akas[n]))
    
            ea += 0x1F
            ea -= ea % 0x20

        for symbol in private.values():
            if not symbol.is_const:
                MakeName(section_bases[symbol.sect] + symbol.addr, symbol.name)

        # Create the 'imports' section
        import_d = {}
        imp_ea_base = imp_ea = ea
        AddSeg(imp_ea, imp_ea + len(imptab), 0, 1, idaapi.saRelPara, idaapi.scPub)
        RenameSeg(imp_ea_base, "IMPORTS")
        for n,symbol in imptab.items():
            if not symbol.is_const:
                import_d[n] = imp_ea
                MakeName(imp_ea, symbol.name)
                imp_ea += 1

        # Now start loading chunks
        while 1:
            if not read_0x15_rec(li, import_d, section_bases, section_offsets):
                break
        #for n in sorted(final_sections):
            #print "%d %s (%04x): [%s]" % (n, sections[n].name, sections[n], ",".join(section_akas[n]))

        #for n, section in item(sections):

            #AddSeg(startea, endea, base, use32, align, comb)

        #    pass



        return 1
    pass

print "Loaded unsp lib loader"
