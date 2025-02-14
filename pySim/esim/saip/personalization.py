# Implementation of SimAlliance/TCA Interoperable Profile handling
#
# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import abc
import io
from typing import List, Tuple

from osmocom.tlv import camel_to_snake
from pySim.utils import enc_iccid, enc_imsi, h2b, rpad, sanitize_iccid
from pySim.esim.saip import ProfileElement, ProfileElementSequence

def unrpad(s: str, c='f') -> str:
    """unpad string on the right side.
    Args:
            s : string to pad
            c : padding character
    Returns:
            String 's' with all rightmost c stripped.
    """
    at = s.find(c)
    if at > 0:
        return s[:at]
    return s

def remove_unwanted_tuples_from_list(l: List[Tuple], unwanted_keys: List[str]) -> List[Tuple]:
    """In a list of tuples, remove all tuples whose first part equals 'unwanted_key'."""
    return list(filter(lambda x: x[0] not in unwanted_keys, l))

def file_replace_content(file: List[Tuple], new_content: bytes):
    """Completely replace all fillFileContent of a decoded 'File' with the new_content."""
    # use [:] to avoid making a copy, as we're doing in-place modification of the list here
    file[:] = remove_unwanted_tuples_from_list(file, ['fillFileContent', 'fillFileOffset'])
    file.append(('fillFileContent', new_content))
    return file

class ConfigurableParameter:
    """Base class representing a part of the eSIM profile that is configurable during the
    personalization process (with dynamic data from elsewhere)."""
    name = None
    allow_types = (str, int, )
    allow_chars = None
    strip_chars = None
    min_len = None
    max_len = None
    allow_len = None # a list of specific lengths
    default_value = None

    def __init__(self, input_value=None, min_len=None, max_len=None, default_value=None):
        self.input_value = input_value # the raw input value as given by caller
        self.value = None # the processed input value (e.g. with check digit) as produced by validate()
        if self.name is None:
            self.name = self.__class__.__name__

    @classmethod
    def get_min_len(cls):
        vals = []
        if cls.allow_len is not None:
            if isinstance(cls.allow_len, (tuple, list)):
                vals.extend(cls.allow_len)
            else:
                vals.append(cls.allow_len)
        if cls.min_len is not None:
            vals.append(cls.min_len)
        if cls.max_len is not None:
            vals.append(cls.max_len)
        if not vals:
            return None
        return min(vals)

    @classmethod
    def validate_val(cls, val):
        '''subclasses may override this function:
           Validate the contents of val, and raise ValueError if appropriate.
           Return a sanitized version of val, that is ready for cls.apply_val().
           This function is a default implementation, with the behavior configured by subclasses' allow_types...max_len
           settings.'''

        if cls.allow_types is not None:
            if not isinstance(val, cls.allow_types):
                raise ValueError(f'input value must be one of {cls.allow_types}, not {type(val)}')
        elif val is None:
            raise ValueError('there is no value (val is None)')

        if isinstance(val, str):
            if cls.strip_chars is not None:
                val = ''.join(c for c in val if c not in cls.strip_chars)
            if cls.allow_chars is not None:
                if any(c not in cls.allow_chars for c in val):
                    raise ValueError(f"invalid characters in input value, valid are {cls.allow_chars}")
        if cls.allow_len is not None:
            l = cls.allow_len
            if not isinstance(l, (tuple, list)):
                l = (l,)
            if len(val) not in l:
                raise ValueError(f'length must be one of {cls.allow_len}')
        if cls.min_len is not None:
            if len(val) < cls.min_len:
                raise ValueError(f'length must be at least {cls.min_len}')
        if cls.max_len is not None:
            if len(val) > cls.max_len:
                raise ValueError(f'length must be at most {cls.max_len}')
        return val

    @abc.abstractmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        '''this is what subclasses implement:
           write the given val in the right format at the right place in pes'''
        pass

    @abc.abstractmethod
    def read_all(cls, pes: ProfileElementSequence):
        '''this is what subclasses implement:
           find all values in the pes, and yield them decoded to a valid input_val format.
           If there can be multiple occurences of this value in the profile, return all distinct values in a set().'''
        pass

    def validate(self):
        '''Validate self.input_value and place the result in self.value.
           This is also called implicitly by apply(), if self.value is still None.
           To override validation in a subclass, rather re-implement the classmethod validate_val().'''
        try:
            self.value = self.__class__.validate_val(self.input_value)
        except ValueError as e:
            raise ValueError(f'{self.name or self.__class__.__name__}: {e}') from e

    def apply(self, pes: ProfileElementSequence):
        '''Place self.value into the ProfileElementSequence at the right place.
           If self.value is None, first call self.validate() to generate a sanitized self.value from self.input_value.
           To override apply() in a subclass, rather re-implement the classmethod apply_val().'''
        if self.value is None:
            self.validate()
            assert self.value is not None
        self.__class__.apply_val(pes, self.value)

    def read_from(self, pes: ProfileElementSequence):
        '''find all values in the pes, and yield them decoded to a valid input_val format.
           If there are multiple occurrences of this value in the profile, return all distinct values in a set().
           If no occurrences were found, return None.
           To override in a subclass, rather re-implement the classmethod read_all().'''
        values = set()
        for val in self.read_all(pes):
            values.add(val)
        if not values:
            return None
        elif len(values) == 1:
            return tuple(values)[0]
        else:
            return values

class DecimalParam(ConfigurableParameter):
    allow_types = (str, int)
    allow_chars = '0123456789'

    @classmethod
    def validate_val(cls, val):
        if isinstance(val, int):
            l = cls.get_min_len() or 1
            val = '%0*d' % (l, val)
        return super().validate_val(val)

class BinaryParam(ConfigurableParameter):
    allow_types = (str, io.BytesIO, bytes, bytearray)
    allow_chars = '0123456789abcdefABCDEF'
    strip_chars = ' \t\r\n'

    @classmethod
    def validate_val(cls, val):
        # take care that min_len and max_len are applied to the binary length
        if type(val) is str:
            val = h2b(val)
        val = super().validate_val(val)
        return val


class Iccid(DecimalParam):
    """ICCID Parameter. Input: string of decimal digits.
       If the string of digits is only 18 digits long, add a Luhn check digit."""
    name = 'ICCID'
    min_len = 18
    max_len = 20
    default_value = '0' * 18

    @classmethod
    def validate_val(cls, val):
        iccid_str = super().validate_val(val)
        return sanitize_iccid(iccid_str)

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        # patch the header
        pes.get_pe_for_type('header').decoded['iccid'] = h2b(rpad(self.value, 20))
        # patch MF/EF.ICCID
        file_replace_content(pes.get_pe_for_type('mf').decoded['ef-iccid'], h2b(enc_iccid(self.value)))

    @classmethod
    def read_all(cls, pes: ProfileElementSequence):
        padded = b2h(pes.get_pe_for_type('header').decoded['iccid'])
        iccid = unrpad(padded)
        yield iccid

        for pe in pes.get_pes_for_type('mf'):
            iccid_pe = pe.decoded.get('ef-iccid', None)
            if iccid_pe:
                yield dec_iccid(b2h(file_tuples_content_as_bytes(iccid_pe)))

class Imsi(DecimalParam):
    """Configurable IMSI. Expects value to be a string of digits. Automatically sets the ACC to
    the last digit of the IMSI."""
    name = 'IMSI'
    min_len = 6
    max_len = 15
    default_value = '00101' + ('0' * 10)

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        imsi_str = val
        # we always use the least significant byte of the IMSI as ACC
        acc = (1 << int(imsi_str[-1]))
        # patch ADF.USIM/EF.IMSI
        for pe in pes.get_pes_for_type('usim'):
            file_replace_content(pe.decoded['ef-imsi'], h2b(enc_imsi(imsi_str)))
            file_replace_content(pe.decoded['ef-acc'], acc.to_bytes(2, 'big'))
        # TODO: DF.GSM_ACCESS if not linked?

    @classmethod
    def read_all(cls, pes: ProfileElementSequence):
        for pe in pes.get_pes_for_type('usim'):
            imsi_pe = pe.decoded.get('ef-imsi', None)
            if imsi_pe:
                yield dec_imsi(b2h(file_tuples_content_as_bytes(imsi_pe)))


class SdKey(BinaryParam):
    """Configurable Security Domain (SD) Key.  Value is presented as bytes."""
    # these will be set by subclasses
    key_type = None
    key_id = None
    kvn = None
    key_usage_qual = None

    @classmethod
    def _apply_sd(cls, pe: ProfileElement, value):
        assert pe.type == 'securityDomain'
        for key in pe.decoded['keyList']:
            if key['keyIdentifier'][0] == cls.key_id and key['keyVersionNumber'][0] == cls.kvn:
                assert len(key['keyComponents']) == 1
                key['keyComponents'][0]['keyData'] = value
                return
        # Could not find matching key to patch, create a new one
        key = {
            'keyUsageQualifier': bytes([cls.key_usage_qual]),
            'keyIdentifier': bytes([cls.key_id]),
            'keyVersionNumber': bytes([cls.kvn]),
            'keyComponents': [
                { 'keyType': bytes([cls.key_type]), 'keyData': value },
            ]
        }
        pe.decoded['keyList'].append(key)

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, value):
        for pe in pes.get_pes_for_type('securityDomain'):
            cls._apply_sd(pe, value)

    @classmethod
    def read_all(cls, pes: ProfileElementSequence):
        for pe in pes.get_pes_for_type('securityDomain'):
            for key in pe.decoded['keyList']:
                if key['keyIdentifier'][0] == cls.key_id and key['keyVersionNumber'][0] == cls.kvn:
                    if len(key['keyComponents']) >= 1:
                        yield b2h(key['keyComponents'][0]['keyData'])

class SdKeyScp80_01(SdKey):
    kvn = 0x01
    key_type = 0x88
    allow_len = (16,24,32) # AES key type

class SdKeyScp80_01Kic(SdKeyScp80_01):
    key_id = 0x01
    key_usage_qual = 0x18 # FIXME: ordering?

class SdKeyScp80_01Kid(SdKeyScp80_01):
    key_id = 0x02
    key_usage_qual = 0x14

class SdKeyScp80_01Kik(SdKeyScp80_01):
    key_id = 0x03
    key_usage_qual = 0x48


class SdKeyScp81_01(SdKey):
    kvn = 0x81 # FIXME

class SdKeyScp81_01Psk(SdKeyScp81_01):
    key_id = 0x01
    key_type = 0x85
    key_usage_qual = 0x3C

class SdKeyScp81_01Dek(SdKeyScp81_01):
    key_id = 0x02
    key_type = 0x88
    key_usage_qual = 0x48


class SdKeyScp02_20(SdKey):
    kvn = 0x20
    key_type = 0x88
    allow_len = (16,24,32) # AES key type

class SdKeyScp02_20Enc(SdKeyScp02_20):
    key_id = 0x01
    key_usage_qual = 0x18

class SdKeyScp02_20Mac(SdKeyScp02_20):
    key_id = 0x02
    key_usage_qual = 0x14

class SdKeyScp02_20Dek(SdKeyScp02_20):
    key_id = 0x03
    key_usage_qual = 0x48


class SdKeyScp03_30(SdKey):
    kvn = 0x30
    key_type = 0x88
    allow_len = (16,24,32) # AES key type

class SdKeyScp03_30Enc(SdKeyScp03_30):
    key_id = 0x01
    key_usage_qual = 0x18

class SdKeyScp03_30Mac(SdKeyScp03_30):
    key_id = 0x02
    key_usage_qual = 0x14

class SdKeyScp03_30Dek(SdKeyScp03_30):
    key_id = 0x03
    key_usage_qual = 0x48


class SdKeyScp03_31(SdKey):
    kvn = 0x31
    key_type = 0x88
    allow_len = (16,24,32) # AES key type

class SdKeyScp03_31Enc(SdKeyScp03_31):
    key_id = 0x01
    key_usage_qual = 0x18

class SdKeyScp03_31Mac(SdKeyScp03_31):
    key_id = 0x02
    key_usage_qual = 0x14

class SdKeyScp03_31Dek(SdKeyScp03_31):
    key_id = 0x03
    key_usage_qual = 0x48


class SdKeyScp03_32(SdKey):
    kvn = 0x32
    key_type = 0x88
    allow_len = [16,24,32] # AES key type

class SdKeyScp03_32Enc(SdKeyScp03_32):
    key_id = 0x01
    key_usage_qual = 0x18

class SdKeyScp03_32Mac(SdKeyScp03_32):
    key_id = 0x02
    key_usage_qual = 0x14

class SdKeyScp03_32Dek(SdKeyScp03_32):
    key_id = 0x03
    key_usage_qual = 0x48



def obtain_pe_from_pelist(l: List[ProfileElement], wanted_type: str) -> ProfileElement:
    return (pe for pe in l if pe.type == wanted_type)

def obtain_singleton_pe_from_pelist(l: List[ProfileElement], wanted_type: str) -> ProfileElement:
    filtered = list(filter(lambda x: x.type == wanted_type, l))
    assert len(filtered) == 1
    return filtered[0]

def obtain_first_pe_from_pelist(l: List[ProfileElement], wanted_type: str) -> ProfileElement:
    filtered = list(filter(lambda x: x.type == wanted_type, l))
    return filtered[0]

class DecimalHexParam(DecimalParam):
    rpad = None
    rpad_char = None

    @classmethod
    def validate_val(cls, val):
        val = super().validate_val(val)
        val = ''.join('%02x' % ord(x) for x in val)
        if cls.rpad is not None:
            c = cls.rpad_char or 'f'
            val = rpad(val, cls.rpad, c)
        return h2b(val)

    # a DecimalHexParam subclass expects the apply_val() input to be a bytes instance ready for the pes

    @classmethod
    def decimal_hex_to_str(cls, val):
        'useful for read_all() implementations of subclasses'
        if isinstance(val, bytes):
            val = b2h(val)
        assert isinstance(val, hexstr)
        if cls.rpad is not None:
            c = cls.rpad_char or 'f'
            val = unrpad(val, c)
        return val.to_bytes().decode('ascii')

class Puk(DecimalHexParam):
    """Configurable PUK (Pin Unblock Code). String ASCII-encoded digits."""
    allow_len = 8
    default_value = '0' * 8
    rpad = 16
    keyReference = None

    @classmethod
    def apply_val(self, pes: ProfileElementSequence, val_bytes):
        mf_pes = pes.pes_by_naa['mf'][0]
        pukCodes = obtain_singleton_pe_from_pelist(mf_pes, 'pukCodes')
        for pukCode in pukCodes.decoded['pukCodes']:
            if pukCode['keyReference'] == self.keyReference:
                pukCode['pukValue'] = val_bytes
                return
        raise ValueError('input template UPP has unexpected structure:'
                + f' cannot find pukCode with keyReference={cls.keyReference}')

    @classmethod
    def read_all(self, pes: ProfileElementSequence):
        mf_pes = pes.pes_by_naa['mf'][0]
        for pukCodes in obtain_pe_from_pelist(mf_pes, 'pukCodes'):
            for pukCode in pukCodes.decoded['pukCodes']:
                if pukCode['keyReference'] == self.keyReference:
                    yield cls.decimal_hex_to_str(pukCode['pukValue'])

class Puk1(Puk):
    name = 'PUK1'
    keyReference = 0x01

class Puk2(Puk):
    name = 'PUK2'
    keyReference = 0x81

class Pin(DecimalHexParam):
    """Configurable PIN (Personal Identification Number).  String of digits."""
    rpad = 16
    min_len = 4
    max_len = 8
    default_value = '0' * 4
    keyReference = None

    @staticmethod
    def _apply_pinvalue(pe: ProfileElement, keyReference, val_bytes):
        for pinCodes in obtain_pe_from_pelist(pe, 'pinCodes'):
            if pinCodes.decoded['pinCodes'][0] != 'pinconfig':
                continue

            for pinCode in pinCodes.decoded['pinCodes'][1]:
                if pinCode['keyReference'] == keyReference:
                     pinCode['pinValue'] = val_bytes
                     return True
        return False

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val_bytes):
        if not cls._apply_pinvalue(pes.pes_by_naa['mf'][0], cls.keyReference, val_bytes):
            raise ValueError('input template UPP has unexpected structure:'
                             + f' {cls.name} cannot find pinCode with keyReference={cls.keyReference}')

    @classmethod
    def _read_all_pinvalues_from_pe(cls, pe: ProfileElement):
        for pinCodes in obtain_pe_from_pelist(pe, 'pinCodes'):
            if pinCodes.decoded['pinCodes'][0] != 'pinconfig':
                continue

            for pinCode in pinCodes.decoded['pinCodes'][1]:
                if pinCode['keyReference'] == cls.keyReference:
                     yield cls.decimal_hex_to_str(pinCode['pinValue'])

    @classmethod
    def read_all(cls, pes: ProfileElementSequence):
        yield from cls._read_all_pinvalues_from_pe(pes.pes_by_naa['mf'][0])

class Pin1(Pin):
    name = 'PIN1'
    keyReference = 0x01

class Pin2(Pin):
    name = 'PIN2'
    keyReference = 0x81

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val_bytes):
        # PIN2 is special: telecom + usim + isim + csim
        for naa in pes.pes_by_naa:
            if naa not in ['usim','isim','csim','telecom']:
                continue
            for instance in pes.pes_by_naa[naa]:
                if not cls._apply_pinvalue(instance, cls.keyReference, val_bytes):
                    raise ValueError('input template UPP has unexpected structure:'
                            + f' {cls.name} cannot find pinCode with keyReference={cls.keyReference} in {naa=}')

    @classmethod
    def read_all(cls, pes: ProfileElementSequence):
        for naa in pes.pes_by_naa:
            if naa not in ['usim','isim','csim','telecom']:
                continue
            for pe in pes.pes_by_naa[naa]:
                yield from cls._read_all_pinvalues_from_pe(pe)

class Adm1(Pin):
    name = 'ADM1'
    keyReference = 0x0A

class Adm2(Pin):
    name = 'ADM2'
    keyReference = 0x0B

class AlgoConfig(BinaryParam):
    """Configurable Algorithm parameter."""
    key = None

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        found = 0
        for pe in pes.get_pes_for_type('akaParameter'):
            algoConfiguration = pe.decoded['algoConfiguration']
            if algoConfiguration[0] != 'algoParameter':
                continue
            algoConfiguration[1][cls.key] = val
            found += 1
        if not found:
            raise ValueError('input template UPP has unexpected structure:'
                             f' {cls.name} cannot find algoParameter with key={cls.key}')

    @classmethod
    def read_all(cls, pes: ProfileElementSequence):
        for pe in pes.get_pes_for_type('akaParameter'):
            algoConfiguration = pe.decoded['algoConfiguration']
            if algoConfiguration[0] != 'algoParameter':
                continue
            yield algoConfiguration[1][cls.key]

class K(AlgoConfig):
    name = 'K'
    default_value = '00' * int(128/8)
    key = 'key'

class Opc(AlgoConfig):
    name = 'OP/OPc'
    default_value = '00' * int(128/8)
    key = 'opc'

class AlgorithmID(AlgoConfig):
    key = 'algorithmID'

    @classmethod
    def validate_val(cls, val):
        val = super().validate_val(val)
        valid = (b'\x01', b'\x02', b'\x03')
        if val not in valid:
            raise ValueError(f'Invalid algorithmID {val}, must be one of {valid}')
        return val
