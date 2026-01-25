#!/usr/bin/env python3

# (C) 2025 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
#
# Author: Neels Hofmeyr
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import io
import sys
import unittest
import io
from importlib import resources
from osmocom.utils import hexstr
from pySim.esim.saip import ProfileElementSequence
import pySim.esim.saip.personalization as p13n
import smdpp_data.upp

import xo
update_expected_output = False

def valstr(val):
    if isinstance(val, io.BytesIO):
        val = val.getvalue()
    if isinstance(val, bytearray):
        val = bytes(val)
    return f'{val!r}'

def valtypestr(val):
    if isinstance(val, dict):
        types = []
        for v in val.values():
            types.append(f'{type(v).__name__}')

        val_type = '{' + ', '.join(types) + '}'
    else:
        val_type = f'{type(val).__name__}'
    return f'{valstr(val)}:{val_type}'

class ConfigurableParameterTest(unittest.TestCase):

    def test_parameters(self):

        upp_fnames = (
                'TS48v5_SAIP2.1A_NoBERTLV.der',
                'TS48v5_SAIP2.3_BERTLV_SUCI.der',
                'TS48v5_SAIP2.1B_NoBERTLV.der',
                'TS48v5_SAIP2.3_NoBERTLV.der',
               )

        class Paramtest:
            def __init__(self, param_cls, val, expect_val, expect_clean_val=None):
                self.param_cls = param_cls
                self.val = val
                self.expect_clean_val = expect_clean_val
                self.expect_val = expect_val

        param_tests = [
            Paramtest(param_cls=p13n.Imsi, val='123456',
                      expect_clean_val=str('123456'),
                      expect_val={'IMSI': hexstr('123456'),
                                  'IMSI-ACC': '0040'}),
            Paramtest(param_cls=p13n.Imsi, val=int(123456),
                      expect_val={'IMSI': hexstr('123456'),
                                  'IMSI-ACC': '0040'}),

            Paramtest(param_cls=p13n.Imsi, val='123456789012345',
                      expect_clean_val=str('123456789012345'),
                      expect_val={'IMSI': hexstr('123456789012345'),
                                  'IMSI-ACC': '0020'}),
            Paramtest(param_cls=p13n.Imsi, val=int(123456789012345),
                      expect_val={'IMSI': hexstr('123456789012345'),
                                  'IMSI-ACC': '0020'}),

            Paramtest(param_cls=p13n.Puk1,
                      val='12345678',
                      expect_clean_val=b'12345678',
                      expect_val='12345678'),
            Paramtest(param_cls=p13n.Puk1,
                      val=int(12345678),
                      expect_clean_val=b'12345678',
                      expect_val='12345678'),

            Paramtest(param_cls=p13n.Puk2,
                      val='12345678',
                      expect_clean_val=b'12345678',
                      expect_val='12345678'),

            Paramtest(param_cls=p13n.Pin1,
                      val='1234',
                      expect_clean_val=b'1234\xff\xff\xff\xff',
                      expect_val='1234'),
            Paramtest(param_cls=p13n.Pin1,
                      val='123456',
                      expect_clean_val=b'123456\xff\xff',
                      expect_val='123456'),
            Paramtest(param_cls=p13n.Pin1,
                      val='12345678',
                      expect_clean_val=b'12345678',
                      expect_val='12345678'),
            Paramtest(param_cls=p13n.Pin1,
                      val=int(1234),
                      expect_clean_val=b'1234\xff\xff\xff\xff',
                      expect_val='1234'),
            Paramtest(param_cls=p13n.Pin1,
                      val=int(123456),
                      expect_clean_val=b'123456\xff\xff',
                      expect_val='123456'),
            Paramtest(param_cls=p13n.Pin1,
                      val=int(12345678),
                      expect_clean_val=b'12345678',
                      expect_val='12345678'),

            Paramtest(param_cls=p13n.Adm1,
                      val='1234',
                      expect_clean_val=b'1234\xff\xff\xff\xff',
                      expect_val='1234'),
            Paramtest(param_cls=p13n.Adm1,
                      val='123456',
                      expect_clean_val=b'123456\xff\xff',
                      expect_val='123456'),
            Paramtest(param_cls=p13n.Adm1,
                      val='12345678',
                      expect_clean_val=b'12345678',
                      expect_val='12345678'),
            Paramtest(param_cls=p13n.Adm1,
                      val=int(123456),
                      expect_clean_val=b'123456\xff\xff',
                      expect_val='123456'),

            Paramtest(param_cls=p13n.AlgorithmID,
                      val='Milenage',
                      expect_clean_val=1,
                      expect_val='Milenage'),
            Paramtest(param_cls=p13n.AlgorithmID,
                      val='TUAK',
                      expect_clean_val=2,
                      expect_val='TUAK'),
            Paramtest(param_cls=p13n.AlgorithmID,
                      val='usim-test',
                      expect_clean_val=3,
                      expect_val='usim-test'),

            Paramtest(param_cls=p13n.AlgorithmID,
                      val=1,
                      expect_clean_val=1,
                      expect_val='Milenage'),
            Paramtest(param_cls=p13n.AlgorithmID,
                      val=2,
                      expect_clean_val=2,
                      expect_val='TUAK'),
            Paramtest(param_cls=p13n.AlgorithmID,
                      val=3,
                      expect_clean_val=3,
                      expect_val='usim-test'),

            Paramtest(param_cls=p13n.K,
                      val='01020304050607080910111213141516',
                      expect_clean_val=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_val='01020304050607080910111213141516'),
            Paramtest(param_cls=p13n.K,
                      val=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_clean_val=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_val='01020304050607080910111213141516'),
            Paramtest(param_cls=p13n.K,
                      val=bytearray(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16'),
                      expect_clean_val=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_val='01020304050607080910111213141516'),
            Paramtest(param_cls=p13n.K,
                      val=io.BytesIO(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16'),
                      expect_clean_val=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_val='01020304050607080910111213141516'),
            Paramtest(param_cls=p13n.K,
                      val=int(11020304050607080910111213141516),
                      expect_clean_val=b'\x11\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_val='11020304050607080910111213141516'),

            Paramtest(param_cls=p13n.Opc,
                      val='01020304050607080910111213141516',
                      expect_clean_val=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_val='01020304050607080910111213141516'),
            Paramtest(param_cls=p13n.Opc,
                      val=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_clean_val=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_val='01020304050607080910111213141516'),
            Paramtest(param_cls=p13n.Opc,
                      val=bytearray(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16'),
                      expect_clean_val=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_val='01020304050607080910111213141516'),
            Paramtest(param_cls=p13n.Opc,
                      val=io.BytesIO(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16'),
                      expect_clean_val=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16',
                      expect_val='01020304050607080910111213141516'),

            Paramtest(param_cls=p13n.SmspTpScAddr,
                      val='+1234567',
                      expect_clean_val=(True, '1234567'),
                      expect_val='+1234567'),
            Paramtest(param_cls=p13n.SmspTpScAddr,
                      val=1234567,
                      expect_clean_val=(False, '1234567'),
                      expect_val='1234567'),

            Paramtest(param_cls=p13n.TuakNumberOfKeccak,
                      val='123',
                      expect_clean_val=123,
                      expect_val='123'),
            Paramtest(param_cls=p13n.TuakNumberOfKeccak,
                      val=123,
                      expect_clean_val=123,
                      expect_val='123'),

            Paramtest(param_cls=p13n.MilenageRotationConstants,
                      val='0a 0b 0c 01 02',
                      expect_clean_val=b'\x0a\x0b\x0c\x01\x02',
                      expect_val='0a0b0c0102'),
            Paramtest(param_cls=p13n.MilenageRotationConstants,
                      val=b'\x0a\x0b\x0c\x01\x02',
                      expect_clean_val=b'\x0a\x0b\x0c\x01\x02',
                      expect_val='0a0b0c0102'),
            Paramtest(param_cls=p13n.MilenageRotationConstants,
                      val=bytearray(b'\x0a\x0b\x0c\x01\x02'),
                      expect_clean_val=b'\x0a\x0b\x0c\x01\x02',
                      expect_val='0a0b0c0102'),

            Paramtest(param_cls=p13n.MilenageXoringConstants,
                      val='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                          ' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                          ' cccccccccccccccccccccccccccccccc'
                          ' 11111111111111111111111111111111'
                          ' 22222222222222222222222222222222',
                      expect_clean_val=b'\xaa' * 16
                                       + b'\xbb' * 16
                                       + b'\xcc' * 16
                                       + b'\x11' * 16
                                       + b'\x22' * 16,
                      expect_val='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                                 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                                 'cccccccccccccccccccccccccccccccc'
                                 '11111111111111111111111111111111'
                                 '22222222222222222222222222222222'),
            Paramtest(param_cls=p13n.MilenageXoringConstants,
                      val=b'\xaa' * 16
                          + b'\xbb' * 16
                          + b'\xcc' * 16
                          + b'\x11' * 16
                          + b'\x22' * 16,
                      expect_clean_val=b'\xaa' * 16
                                       + b'\xbb' * 16
                                       + b'\xcc' * 16
                                       + b'\x11' * 16
                                       + b'\x22' * 16,
                      expect_val='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                                 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                                 'cccccccccccccccccccccccccccccccc'
                                 '11111111111111111111111111111111'
                                 '22222222222222222222222222222222'),

            ]

        for sdkey_cls in (
            # thin out the number of tests, as a compromise between completeness and test runtime
            p13n.SdKeyScp02Kvn20AesDek,
           #p13n.SdKeyScp02Kvn20AesEnc,
           #p13n.SdKeyScp02Kvn20AesMac,
           #p13n.SdKeyScp02Kvn21AesDek,
            p13n.SdKeyScp02Kvn21AesEnc,
           #p13n.SdKeyScp02Kvn21AesMac,
           #p13n.SdKeyScp02Kvn22AesDek,
           #p13n.SdKeyScp02Kvn22AesEnc,
            p13n.SdKeyScp02Kvn22AesMac,
           #p13n.SdKeyScp02KvnffAesDek,
           #p13n.SdKeyScp02KvnffAesEnc,
           #p13n.SdKeyScp02KvnffAesMac,
            p13n.SdKeyScp03Kvn30AesDek,
           #p13n.SdKeyScp03Kvn30AesEnc,
           #p13n.SdKeyScp03Kvn30AesMac,
           #p13n.SdKeyScp03Kvn31AesDek,
            p13n.SdKeyScp03Kvn31AesEnc,
           #p13n.SdKeyScp03Kvn31AesMac,
           #p13n.SdKeyScp03Kvn32AesDek,
           #p13n.SdKeyScp03Kvn32AesEnc,
            p13n.SdKeyScp03Kvn32AesMac,
           #p13n.SdKeyScp80Kvn01AesDek,
           #p13n.SdKeyScp80Kvn01AesEnc,
           #p13n.SdKeyScp80Kvn01AesMac,
            p13n.SdKeyScp80Kvn01DesDek,
           #p13n.SdKeyScp80Kvn01DesEnc,
           #p13n.SdKeyScp80Kvn01DesMac,
           #p13n.SdKeyScp80Kvn02AesDek,
            p13n.SdKeyScp80Kvn02AesEnc,
           #p13n.SdKeyScp80Kvn02AesMac,
           #p13n.SdKeyScp80Kvn02DesDek,
           #p13n.SdKeyScp80Kvn02DesEnc,
            p13n.SdKeyScp80Kvn02DesMac,
           #p13n.SdKeyScp80Kvn03AesDek,
           #p13n.SdKeyScp80Kvn03AesEnc,
           #p13n.SdKeyScp80Kvn03AesMac,
            p13n.SdKeyScp80Kvn03DesDek,
           #p13n.SdKeyScp80Kvn03DesEnc,
           #p13n.SdKeyScp80Kvn03DesMac,
            p13n.SdKeyScp81Kvn40Dek   ,
           #p13n.SdKeyScp81Kvn40Tlspsk,
           #p13n.SdKeyScp81Kvn41Dek   ,
            p13n.SdKeyScp81Kvn41Tlspsk,
           #p13n.SdKeyScp81Kvn42Dek   ,
           #p13n.SdKeyScp81Kvn42Tlspsk,
            ):

            for key_len in sdkey_cls.allow_len:
                val = '0102030405060708091011121314151617181920212223242526272829303132'
                expect_clean_val = (b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16'
                                    b'\x17\x18\x19\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x30\x31\x32')
                expect_val = '0102030405060708091011121314151617181920212223242526272829303132'

                val = val[:key_len*2]
                expect_clean_val = expect_clean_val[:key_len]
                expect_val = val

                param_tests.append(Paramtest(param_cls=sdkey_cls, val=val, expect_clean_val=expect_clean_val, expect_val=expect_val))

                # test bytes input
                val = expect_clean_val
                param_tests.append(Paramtest(param_cls=sdkey_cls, val=val, expect_clean_val=expect_clean_val, expect_val=expect_val))

                # test bytearray input
                val = bytearray(expect_clean_val)
                param_tests.append(Paramtest(param_cls=sdkey_cls, val=val, expect_clean_val=expect_clean_val, expect_val=expect_val))

                # test BytesIO input
                val = io.BytesIO(expect_clean_val)
                param_tests.append(Paramtest(param_cls=sdkey_cls, val=val, expect_clean_val=expect_clean_val, expect_val=expect_val))

                if key_len == 16:
                    # test huge integer input.
                    # needs to start with nonzero.. stupid
                    val = 11020304050607080910111213141516
                    expect_clean_val = (b'\x11\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16')
                    expect_val = '11020304050607080910111213141516'
                    param_tests.append(Paramtest(param_cls=sdkey_cls, val=val, expect_clean_val=expect_clean_val, expect_val=expect_val))

        outputs = []

        for upp_fname in upp_fnames:
            test_idx = -1
            try:

                der = resources.read_binary(smdpp_data.upp, upp_fname)

                for t in param_tests:
                    test_idx += 1
                    logloc = f'{upp_fname} {t.param_cls.__name__}(val={valtypestr(t.val)})'

                    param = None
                    try:
                        param = t.param_cls()
                        param.input_value = t.val
                        param.validate()
                    except ValueError as e:
                        raise ValueError(f'{logloc}: {e}') from e

                    clean_val = param.value
                    logloc = f'{logloc} clean_val={valtypestr(clean_val)}'
                    if t.expect_clean_val is not None and t.expect_clean_val != clean_val:
                        raise ValueError(f'{logloc}: expected'
                                         f' expect_clean_val={valtypestr(t.expect_clean_val)}')

                    # on my laptop, deepcopy is about 30% slower than decoding the DER from scratch:
                    # pes = copy.deepcopy(orig_pes)
                    pes = ProfileElementSequence.from_der(der)
                    try:
                        param.apply(pes)
                    except ValueError as e:
                        raise ValueError(f'{logloc} apply_val(clean_val): {e}') from e

                    changed_der = pes.to_der()

                    pes2 = ProfileElementSequence.from_der(changed_der)

                    read_back_val = t.param_cls.get_value_from_pes(pes2)

                    # compose log string to show the precise type of dict values
                    if isinstance(read_back_val, dict):
                        types = set()
                        for v in read_back_val.values():
                            types.add(f'{type(v).__name__}')

                        read_back_val_type = '{' + ', '.join(types) + '}'
                    else:
                        read_back_val_type = f'{type(read_back_val).__name__}'

                    logloc = (f'{logloc} read_back_val={valtypestr(read_back_val)}')

                    if isinstance(read_back_val, dict) and not t.param_cls.get_name() in read_back_val.keys():
                        raise ValueError(f'{logloc}: expected to find name {t.param_cls.get_name()!r} in read_back_val')

                    expect_val = t.expect_val
                    if not isinstance(expect_val, dict):
                        expect_val = { t.param_cls.get_name(): expect_val }
                    if read_back_val != expect_val:
                        raise ValueError(f'{logloc}: expected {expect_val=!r}:{type(t.expect_val).__name__}')

                    ok = logloc.replace(' clean_val', '\n\tclean_val'
                              ).replace(' read_back_val', '\n\tread_back_val'
                              ).replace('=', '=\t'
                              )
                    output = f'\nok: {ok}'
                    outputs.append(output)
                    print(output)

            except Exception as e:
                raise RuntimeError(f'Error while testing UPP {upp_fname} {test_idx=}: {e}') from e

        output = '\n'.join(outputs) + '\n'
        xo_name = 'test_configurable_parameters'
        if update_expected_output:
            with resources.path(xo, xo_name) as xo_path:
                with open(xo_path, 'w', encoding='utf-8') as f:
                    f.write(output)
        else:
            xo_str = resources.read_text(xo, xo_name)
            if xo_str != output:
                at = 0
                while at < len(output):
                    if output[at] == xo_str[at]:
                        at += 1
                        continue
                    break

                raise RuntimeError(f'output differs from expected output at position {at}: "{output[at:at+20]}" != "{xo_str[at:at+20]}"')


if __name__ == "__main__":
    if '-u' in sys.argv:
        update_expected_output = True
        sys.argv.remove('-u')
    unittest.main()
