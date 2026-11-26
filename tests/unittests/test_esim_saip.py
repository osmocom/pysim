#!/usr/bin/env python3

# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
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

import unittest
import logging
import copy
from osmocom.utils import h2b, b2h

from pySim.esim.saip import *
from pySim.esim.saip import personalization
from pySim.global_platform import KeyUsageQualifier
from pprint import pprint as pp


class SaipTest(unittest.TestCase):
    with open('smdpp-data/upp/TS48v2_SAIP2.3_NoBERTLV.der', 'rb') as f:
        per_input = f.read()
    pes = ProfileElementSequence.from_der(per_input)
    expected_pet_list = ['header', 'mf', 'pukCodes', 'pinCodes', 'telecom', 'pinCodes', 'genericFileManagement', 'usim', 'opt-usim', 'pinCodes', 'akaParameter', 'gsm-access', 'df-5gs', 'df-saip','csim', 'opt-csim', 'pinCodes', 'cdmaParameter', 'isim', 'opt-isim', 'pinCodes', 'akaParameter', 'genericFileManagement', 'genericFileManagement', 'securityDomain', 'rfm', 'rfm', 'rfm', 'rfm', 'end']

    def test_reencode_sequence(self):
        """Test that we can decode and re-encode the entire DER encoded UPP."""
        reencoded_der = self.pes.to_der()
        self.assertEqual(reencoded_der, self.per_input)

    def test_reencode_pe(self):
        """Test that we can decode and re-encode reach individual ProfileElement."""
        remainder = self.per_input
        while len(remainder):
            first_tlv, remainder = bertlv_first_segment(remainder)
            pe = ProfileElement.from_der(first_tlv)
            with self.subTest(pe.type):
                reenc_tlv = pe.to_der()
                self.assertEqual(reenc_tlv, first_tlv)


    def test_rfu_pe(self):
        """Test that an rfu PE (PE-Dummy, an empty SEQUENCE without header) decodes and re-encodes."""
        rfu_der = asn1.encode('ProfileElement', ('rfu1', {}))
        pe = ProfileElement.from_der(rfu_der)
        self.assertEqual(pe.type, 'rfu1')
        self.assertEqual(pe.to_der(), rfu_der)
        # within a sequence: insert it before the trailing PE-End
        tlvs = []
        remainder = self.per_input
        while len(remainder):
            first_tlv, remainder = bertlv_first_segment(remainder)
            tlvs.append(first_tlv)
        der = b''.join(tlvs[:-1]) + rfu_der + tlvs[-1]
        pes = ProfileElementSequence.from_der(der)
        self.assertEqual(pes.to_der(), der)

    def test_sd_key_access_and_counter(self):
        """Test that keyAccess and keyCounterValue of a security domain key survive a re-encode."""
        decoded = copy.deepcopy(self.pes.get_pe_for_type('securityDomain').decoded)
        # KVN 0x01: SCP80 keyset, five byte counter
        decoded['keyList'][0]['keyAccess'] = b'\x01'
        decoded['keyList'][0]['keyCounterValue'] = h2b('0000000001')
        der = asn1.encode('ProfileElement', ('securityDomain', decoded))
        pe = ProfileElement.from_der(der)
        self.assertEqual(pe.keys[0].key_access, 1)
        self.assertEqual(pe.keys[0].key_counter_value, 1)
        self.assertEqual(pe.to_der(), der)

    def test_sd_key_counter_len(self):
        """Test that a key counter is encoded with the length of the protocol its KVN is reserved for."""
        key = self.pes.get_pe_for_type('securityDomain').keys[0]
        def counter(kvn: int, value: int = 1) -> str:
            sd_key = SecurityDomainKey(kvn, key.key_identifier, key.key_usage_qualifier, key.key_components,
                                       key_counter_value=value)
            return b2h(sd_key.to_saip_dict()['keyCounterValue'])
        self.assertEqual(counter(0x01), '0000000001') # SCP80
        self.assertEqual(counter(0x20), '0001') # SCP02
        self.assertEqual(counter(0xff), '0001') # SCP02
        self.assertEqual(counter(0x30), '000001') # SCP03
        # KVN 0x70 is not reserved for SCP80, SCP02 or SCP03; 0x1000000 needs more than 3 bytes
        for kvn, value in ((0x70, 1), (0x30, 0x1000000)):
            with self.assertRaises(ValueError):
                counter(kvn, value)
        # a decoded counter of another length re-encodes with the length of its KVN
        decoded = copy.deepcopy(self.pes.get_pe_for_type('securityDomain').decoded)
        decoded['keyList'][3]['keyCounterValue'] = h2b('0001') # KVN 0x02: SCP80
        pe = ProfileElement.from_der(asn1.encode('ProfileElement', ('securityDomain', decoded)))
        self.assertEqual(pe.keys[3].to_saip_dict()['keyCounterValue'], h2b('0000000001'))

    def test_sequence_helpers(self):
        """Verify that the convenience helpers worked as expected."""
        self.assertEqual([x.type for x in self.pes.pe_list], self.expected_pet_list)
        self.assertEqual(len(self.pes.pes_by_naa), 4)

    def test_personalization(self):
        """Test some of the personalization operations."""
        pes = copy.deepcopy(self.pes)
        params = [personalization.Puk1('01234567'),
                  personalization.Puk2(98765432),
                  personalization.Pin1('1111'),
                  personalization.Pin2(2222),
                  personalization.Adm1('11111111'),
                  personalization.K(h2b('000102030405060708090a0b0c0d0e0f')),
                  personalization.Opc(h2b('101112131415161718191a1b1c1d1e1f'))]
        for p in params:
            p.validate()
            p.apply(pes)
        # TODO: we don't actually test the results here, but we just verify there is no exception
        pes.to_der()

    def test_personalization2(self):
        """Test some of the personalization operations."""
        cls = personalization.SdKeyScp80Kvn01DesEnc
        pes = ProfileElementSequence.from_der(self.per_input)
        prev_val = tuple(cls.get_values_from_pes(pes))
        print(f'{prev_val=}')
        self.assertTrue(prev_val)

        set_val = '42342342342342342342342342342342'
        param = cls(set_val)
        param.validate()
        param.apply(pes)

        get_val1 = tuple(cls.get_values_from_pes(pes))
        print(f'{get_val1=} {set_val=}')
        self.assertEqual(get_val1, ({cls.name: set_val},))

        get_val1b = tuple(cls.get_values_from_pes(pes))
        print(f'{get_val1b=} {set_val=}')
        self.assertEqual(get_val1b, ({cls.name: set_val},))

        der = pes.to_der()

        get_val1c = tuple(cls.get_values_from_pes(pes))
        print(f'{get_val1c=} {set_val=}')
        self.assertEqual(get_val1c, ({cls.name: set_val},))

        # assertTrue to not dump the entire der.
        # Expecting the modified DER to be different. If this assertion fails, then no change has happened in the output
        # DER and the ConfigurableParameter subclass is buggy.
        self.assertTrue(der != self.per_input)

        pes2 = ProfileElementSequence.from_der(der)
        get_val2 = tuple(cls.get_values_from_pes(pes2))
        print(f'{get_val2=} {set_val=}')
        self.assertEqual(get_val2, ({cls.name: set_val},))

    def test_sd_key_personalization_creates_usage_qualifier(self):
        """helper created key qualifier must match"""
        pes = ProfileElementSequence()
        pes.append(ProfileElementHeader())
        pes.append(ProfileElementSD())
        pes.append(ProfileElementEnd())

        cls = personalization.SdKeyScp02Kvn20AesEnc
        cls('00112233445566778899aabbccddeeff').apply(pes)
        key = pes.get_pe_for_type('securityDomain').find_key(0x20, 0x01)
        self.assertEqual(KeyUsageQualifier.build(key.key_usage_qualifier), b'\x18')

        round_trip = ProfileElementSequence.from_der(pes.to_der())
        key = round_trip.get_pe_for_type('securityDomain').find_key(0x20, 0x01)
        self.assertEqual(KeyUsageQualifier.build(key.key_usage_qualifier), b'\x18')

    def test_constructor_encode(self):
        """Test that DER-encoding of PE created by "empty" constructor works without raising exception."""
        for cls in [ProfileElementMF, ProfileElementPuk, ProfileElementPin, ProfileElementTelecom,
                    ProfileElementUSIM, ProfileElementISIM, ProfileElementAKA, ProfileElementSD,
                    ProfileElementSSD, ProfileElementOptUSIM, ProfileElementOptISIM,
                    ProfileElementHeader, ProfileElementEnd]:
            with self.subTest(cls.__name__):
                pes = ProfileElementSequence()
                inst = cls()
                pes.append(inst)
                pes.to_der()

        # RFM requires some constructor arguments
        cls = ProfileElementRFM
        with self.subTest(cls.__name__):
                pes = ProfileElementSequence()
                inst = cls(inst_aid=b'\x01\x02', sd_aid=b'\x03\x04', tar_list=[b'\x01\x02\x03'])
                pes.append(inst)
                pes.to_der()

    def test_gfm_pe2files_files2pe(self):
        """Test that pe2files work and also files2pe produces the same profile element content."""
        self.maxDiff = None
        gfm_elements = [pe for pe in self.pes.pe_list if pe.type == 'genericFileManagement']
        self.assertTrue(len(gfm_elements) > 0)
        for gdm in gfm_elements:
            gfm = gfm_elements[0]
            self.assertIsNotNone(gfm)
            orig_decoded = copy.deepcopy(gfm.decoded)
            gfm.files2pe()
            orig_cmds = orig_decoded['fileManagementCMD']
            new_cmds = gfm.decoded['fileManagementCMD']
            self.assertEqual(len(orig_cmds), len(new_cmds))
            for b, (orig_block, new_block) in enumerate(zip(orig_cmds, new_cmds)):
                self.assertEqual(len(orig_block), len(new_block))
                for c, (orig_cmd, new_cmd) in enumerate(zip(orig_block, new_block)):
                    with self.subTest(cmd_index=b, cmd=c):
                        self.assertEqual(orig_cmd, new_cmd)


class FileContentTest(unittest.TestCase):
    def test_fill_file_offset_fits_uint16(self):
        # fillFileOffset is a UInt16 (SAIP 8.3.2): a longer gap takes several steps
        template = templates.FileTemplate(0x6f99, 'EF.TEST', 'TR', None, 70000, 5, None, None)
        body = bytearray(b'\xff' * 70000)
        body[66000] = 0x00
        f = File('test', [('fileDescriptor', {})], template)
        f.body = bytes(body)
        tuples = f.file_content_to_tuples(optimize=True)
        offsets = [v for k, v in tuples if k == 'fillFileOffset']
        self.assertEqual(offsets, [0xffff, 66000 - 0xffff])
        self.assertEqual(f.file_content_from_tuples(tuples), bytes(body))

    def test_compression_decompression(self):
        # Test compression algorithm with out default value
        template = templates.FileTemplate(0x6f99, 'EF.TEST', 'LF', 2, 38, 5)
        test_tuples = [
            ('fileDescriptor', {}),
            ('fillFileContent', b'12345678'), # overwrite default value with some pattern
            ('fillFileOffset', 30),
            ('fillFileContent', b'\xff' * 38), # overwrite record with 0xff
        ]
        expect_body = bytearray(b'12345678' + b'\xff' * (30 + 38))
        expect_tuples = [
            ('fillFileContent', b'12345678'), # overwrite default value with some pattern
        ]
        f = File('test', test_tuples, template)
        self.assertEqual(f.body, expect_body)
        tuples = f.file_content_to_tuples(optimize=True)
        self.assertEqual(tuples, expect_tuples)

    def test_compression_decompression_default(self):
        # Test compression algorithm with default value
        template = templates.FileTemplate(0x6f99, 'EF.TEST', 'LF', 3, 38, 5, default_val = 'fdfeff...', repeat = True)
        test_tuples = [
            ('fileDescriptor', {}),
            ('fillFileContent', b'12345678'), # overwrite default value with some pattern
            ('fillFileOffset', 30 + 38),    # no not overwrite default value
            ('fillFileContent', b'\xff' * 38), # overwrite record with 0xff
        ]
        expect_body = bytearray(b'12345678' + b'\xff' * 30 + b'\xfd\xfe' + b'\xff' * (36 + 38))
        expect_tuples = [
            ('fillFileContent', b'12345678'), # overwrite default value with some pattern
            ('fillFileOffset', 30 + 38),    # no not overwrite default value
            ('fillFileContent', b'\xff' * 2), # overwrite only part of the record with 0xff that differs
        ]
        f = File('test', test_tuples, template)
        self.assertEqual(f.body, expect_body)
        tuples = f.file_content_to_tuples(optimize=True)
        self.assertEqual(tuples, expect_tuples)

class EfDirTest(unittest.TestCase):
    def setUp(self):
        self.pes = ProfileElementSequence()
        hdr = ProfileElementHeader(iccid='01234567890123456789', profile_type='Osmocom Test Profile')
        self.pes.append(hdr)
        mf = ProfileElementMF(pe_sequence = self.pes)
        mf.create_file('mf')
        self.pes.append(mf)

    def _add_usim(self, df_name):
        """Helper to create USIM-PE."""
        usim = ProfileElementUSIM(pe_sequence = self.pes)
        adf_usim = usim.create_file('adf-usim')
        adf_usim.fid = 0x7fd0
        adf_usim.df_name = bytes.fromhex(df_name)
        usim.files2pe()
        self.pes.append(usim)
        mf = self.pes.get_pe_for_type('mf')

    def test_add_adf(self):
        """Test if EF-DIR is created and AID is added when USIM is appended."""
        self._add_usim('A0000000871002FFFFFFFF8907090000')
        mf = self.pes.get_pe_for_type('mf')
        ef_dir_tuples = mf.decoded['ef-dir']
        fill_contents = [val for key, val in ef_dir_tuples if key == 'fillFileContent']
        self.assertGreater(len(fill_contents), 0, "Failed to automatically add AID to EF-DIR.")
        expected_content = bytes.fromhex('61194f10a0000000871002ffffffff890709000050055573696d31')
        self.assertEqual(fill_contents[0], expected_content)

    def test_remove_adf(self):
        """Test if record in EF-DIR is removed whten USIM is removed."""
        self._add_usim('A0000000871002FFFFFFFF8907090000')
        self.pes.remove_naas_of_type(NaaUsim);
        mf = self.pes.get_pe_for_type('mf')
        ef_dir_tuples = mf.decoded['ef-dir']
        fill_contents = [val for key, val in ef_dir_tuples if key == 'fillFileContent']
        self.assertEqual(len(fill_contents), 0, "Failed to automatically remove AID from EF-DIR.")

    def test_add_record(self):
        """Test if EF-DIR record number is increased, when USIM is added, but not record is available."""
        self._add_usim('A0000000871002FFFFFFFF8907090001')
        self._add_usim('A0000000871002FFFFFFFF8907090002')
        self._add_usim('A0000000871002FFFFFFFF8907090003')
        mf = self.pes.get_pe_for_type('mf')
        ef_dir_file = mf.files['ef-dir']
        self.assertEqual(ef_dir_file.nb_rec, 3, "Expected number of records are not in EF-DIR.")

    def test_resize_record(self):
        """Test if EF-DIR record number is increased, when USIM is added, but not record is available."""
        mf = self.pes.get_pe_for_type('mf')
        mf.create_file('ef-dir')
        ef_dir = mf.files['ef-dir']
        ef_dir.rec_len = 16
        ef_dir.nb_rec = 2
        ef_dir.body = b'\xff' * ef_dir.rec_len * ef_dir.nb_rec
        self._add_usim('A0000000871002FFFFFFFF8907090001')
        ef_dir_file = mf.files['ef-dir']
        self.assertGreater(ef_dir_file.rec_len, 16, "Record length of EF-DIR did not increase.")


class LinkPathTest(unittest.TestCase):
    def _create_pes(self, use_gfm = False, link_path = None):
        self.maxDiff = None
        self.pes = ProfileElementSequence()
        hdr = ProfileElementHeader(iccid='01234567890123456789', profile_type='Osmocom Test Profile')
        self.pes.append(hdr)
        mf = ProfileElementMF(pe_sequence = self.pes)
        mf.create_file('mf')
        self.pes.append(mf)
        telecom = ProfileElementTelecom(pe_sequence = self.pes)
        telecom.create_file('df-telecom')
        telecom.files2pe()
        self.pes.append(telecom)

    def _add_gfm(self, link_path = None):
        gfm_decoded = OrderedDict([
            ('gfm-header', OrderedDict([('mandated', None), ('identification', 10)])),
            ('fileManagementCMD', [[
                ('filePath', b'\x7f\x10'),
                ('createFCP', OrderedDict([
                    ('fileDescriptor', b'\x38\x21'), # 0x38 = DF
                    ('pinStatusTemplateDO', None),
                    ('fileID', b'\x5f\x3a'), # 5f3a = DF.PHONEBOOK
                    ('lcsi', b'\x05'),
                ]))
            ]])
        ])
        if link_path is not None:
            gfm_decoded['fileManagementCMD'][0][1][1]['linkPath'] = link_path
        self.gfm = ProfileElementGFM(decoded=gfm_decoded, pe_sequence=self.pes)
        self.pes.append(self.gfm)
        self.gfm.pe2files()
        self.orig_decoded = copy.deepcopy(self.gfm.decoded)
        self.gfm.files2pe()

    def _add_optcsim(self, link_path = None):
        optcsim_decoded = OrderedDict([
            ('optcsim-header', OrderedDict([('mandated', None), ('identification', 16)])),
            ('templateID', '2.23.143.1.2.11'),
            ('ef-sms', [
                ('fileDescriptor', OrderedDict([
                    ('fileDescriptor', b'\x42\x21\x00\xc0'),
                    ('securityAttributesReferenced', b'\x6f\x06\x06'),
                    ('shortEFID', b''),
                    ('linkPath', b'\x7f\xd0\x6f\x3c'),
                    ('lcsi', b'\x05'),
                ]))
            ]),
        ])
        if link_path is not None:
            optcsim_decoded['ef-sms'][0][1]['linkPath'] = link_path
        self.optcsim = ProfileElementOptCSIM(decoded=optcsim_decoded, pe_sequence=self.pes)
        self.pes.append(self.optcsim)
        self.optcsim.pe2files()
        self.orig_decoded = copy.deepcopy(self.optcsim.decoded)
        self.optcsim.files2pe()

    def test_link_path_transcoding_gfm(self):
        """Test that pe2files and files2pe preserve linkPath in genericFileManagement."""
        self._create_pes()
        self._add_gfm(b'\x7f\x10\x5f\x3a') # 7f10 = DF.TELECOM / 5f3a = DF.PHONEBOOK
        self.assertEqual(self.orig_decoded, self.gfm.decoded)

    def test_link_path_transcoding_optcsim(self):
        """Test that pe2files and files2pe preserve linkPath in genericFileManagement."""
        self._create_pes()
        self._add_optcsim(b'\x7f\xd0\x6f\x3c') # 7f10 = DF.TELECOM / 6f3c = EF.SMS
        self.assertEqual(self.orig_decoded, self.optcsim.decoded)

    def test_dflink_in_service(self):
        """Test that an exsiting DF with linkPath will cause dfLink tag to exist in ServicesList."""
        self._create_pes()
        self._add_gfm(b'\x7f\x10\x5f\x3a') # 7f10 = DF.TELECOM / 5f3a = DF.PHONEBOOK
        self.pes.rebuild_mandatory_services()
        hdr_pe = self.pes.get_pe_for_type('header')
        services = hdr_pe.decoded['eUICC-Mandatory-services']
        self.assertIn('dfLink', services)

    def test_dflink_not_in_service(self):
        """Test that a non exsiting DF with linkPath will cause dfLink tag to not exist in ServicesList."""
        self._create_pes()
        self._add_gfm()
        self.pes.rebuild_mandatory_services()
        hdr_pe = self.pes.get_pe_for_type('header')
        services = hdr_pe.decoded['eUICC-Mandatory-services']
        self.assertNotIn('dfLink', services)

class OidTest(unittest.TestCase):
    def test_cmp(self):
        self.assertTrue(oid.OID('1.0') > oid.OID('0.9'))
        self.assertTrue(oid.OID('1.0') == oid.OID('1.0'))
        self.assertTrue(oid.OID('1.0.1') > oid.OID('1.0'))
        self.assertTrue(oid.OID('1.0.2') > oid.OID('1.0.1'))

class NonMatchTest(unittest.TestCase):
    def test_nonmatch(self):
        # non-matches before, in between and after matches
        match_list = [Match(a=10, b=10, size=5), Match(a=20, b=20, size=4)]
        nm_list = NonMatch.from_matchlist(match_list, 26)
        self.assertEqual(nm_list, [NonMatch(a=0, b=0, size=10), NonMatch(a=15, b=15, size=5),
                                   NonMatch(a=24, b=24, size=2)])

    def test_nonmatch_beg(self):
        # single match at beginning
        match_list = [Match(a=0, b=0, size=5)]
        nm_list = NonMatch.from_matchlist(match_list, 20)
        self.assertEqual(nm_list, [NonMatch(a=5, b=5, size=15)])

    def test_nonmatch_end(self):
        # single match at end
        match_list = [Match(a=19, b=19, size=5)]
        nm_list = NonMatch.from_matchlist(match_list, 24)
        self.assertEqual(nm_list, [NonMatch(a=0, b=0, size=19)])

    def test_nonmatch_none(self):
        # no match at all
        match_list = []
        nm_list = NonMatch.from_matchlist(match_list, 24)
        self.assertEqual(nm_list, [NonMatch(a=0, b=0, size=24)])




if __name__ == "__main__":
	unittest.main()
