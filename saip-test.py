#!/usr/bin/env python3

from pySim.utils import b2h, h2b
from pySim.esim.saip import *
from pySim.esim.saip.validation import *

from pySim.pprint import HexBytesPrettyPrinter

pp = HexBytesPrettyPrinter(indent=4,width=500)

import abc




with open('smdpp-data/upp/TS48v2_SAIP2.3_NoBERTLV.der', 'rb') as f:
    pes = ProfileElementSequence.from_der(f.read())

if False:
    # iterate over each pe in the pes.pe_list
    for pe in pes.pe_list:
        print("="*70 + " " + pe.type)
        pp.pprint(pe.decoded)

if False:
    # sort by PE type and show all PE within that type
    for pe_type in pes.pe_by_type.keys():
        print("="*70 + " " + pe_type)
        for pe in pes.pe_by_type[pe_type]:
            pp.pprint(pe)
            pp.pprint(pe.decoded)

checker = CheckBasicStructure()
checker.check(pes)

if False:
    for naa in pes.pes_by_naa:
        i = 0
        for naa_instance in pes.pes_by_naa[naa]:
            print("="*70 + " " + naa + str(i))
            i += 1
            for pe in naa_instance:
                pp.pprint(pe.type)
                for d in pe.decoded:
                    print("    %s" % d)
                    #pp.pprint(pe.decoded[d])
                #if pe.type in ['akaParameter', 'pinCodes', 'pukCodes']:
                #    pp.pprint(pe.decoded)


from pySim.esim.saip.personalization import *

params = [Iccid('984944000000000000'), Imsi('901990123456789'),
          Puk1(value='01234567'), Puk2(value='98765432'), Pin1('1111'), Pin2('2222'), Adm1('11111111'),
          K(h2b('000102030405060708090a0b0c0d0e0f')), Opc(h2b('101112131415161718191a1b1c1d1e1f')),
          SdKeyScp80_01Kic(h2b('000102030405060708090a0b0c0d0e0f'))]

from pySim.esim.saip.templates import *

for p in params:
    p.apply(pes)

if False:
    for pe in pes:
        pp.pprint(pe.decoded)
        pass

if True:
    naas = pes.pes_by_naa.keys()
    for naa in naas:
        for pe in pes.pes_by_naa[naa][0]:
            print(pe)
            #pp.pprint(pe.decoded)
            #print(pe.header)
            tpl_id = pe.templateID
            if tpl_id:
                prof = ProfileTemplateRegistry.get_by_oid(tpl_id)
                print(prof)
                #pp.pprint(pe.decoded)
            for fname, fdata in pe.files.items():
                print()
                print("============== %s" % fname)
                ftempl = None
                if prof:
                    ftempl = prof.files_by_pename[fname]
                print("Template: %s" % repr(ftempl))
                print("Data: %s" % fdata)
                file = File(fname, fdata, ftempl)
                print(repr(file))
                #pp.pprint(pe.files)

if True:
    # iterate over each pe in the pes (using its __iter__ method)
    for pe in pes:
        print("="*70 + " " + pe.type)
        pp.pprint(pe.decoded)



#print(ProfileTemplateRegistry.by_oid)
