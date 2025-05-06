"""Implementation of Personalization of eSIM profiles in SimAlliance/TCA Interoperable Profile."""

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

def remove_unwanted_tuples_from_list(l: List[Tuple], unwanted_keys: List[str]) -> List[Tuple]:
    """In a list of tuples, remove all tuples whose first part equals 'unwanted_key'."""
    return list(filter(lambda x: x[0] not in unwanted_keys, l))

def file_replace_content(file: List[Tuple], new_content: bytes):
    """Completely replace all fillFileContent of a decoded 'File' with the new_content."""
    # use [:] to avoid making a copy, as we're doing in-place modification of the list here
    file[:] = remove_unwanted_tuples_from_list(file, ['fillFileContent', 'fillFileOffset'])
    file.append(('fillFileContent', new_content))
    return file

class ClassVarMeta(abc.ABCMeta):
    """Metaclass that puts all additional keyword-args into the class. We use this to have one
    class definition for something like a PIN, and then have derived classes for PIN1, PIN2, ..."""
    def __new__(metacls, name, bases, namespace, **kwargs):
        #print("Meta_new_(metacls=%s, name=%s, bases=%s, namespace=%s, kwargs=%s)" % (metacls, name, bases, namespace, kwargs))
        x = super().__new__(metacls, name, bases, namespace)
        for k, v in kwargs.items():
            setattr(x, k, v)
        setattr(x, 'name', camel_to_snake(name))
        return x

class ConfigurableParameter(abc.ABC, metaclass=ClassVarMeta):
    """Base class representing a part of the eSIM profile that is configurable during the
    personalization process (with dynamic data from elsewhere)."""
    def __init__(self, input_value):
        self.input_value = input_value # the raw input value as given by caller
        self.value = None # the processed input value (e.g. with check digit) as produced by validate()

    def validate(self):
        """Optional validation method. Can be used by derived classes to perform validation
        of the input value (self.value).  Will raise an exception if validation fails."""
        # default implementation: simply copy input_value over to value
        self.value = self.input_value

    @abc.abstractmethod
    def apply(self, pes: ProfileElementSequence):
        pass

class Iccid(ConfigurableParameter):
    """Configurable ICCID.  Expects the value to be a string of decimal digits.
    If the string of digits is only 18 digits long, a Luhn check digit will be added."""

    def validate(self):
        # convert to string as it might be an integer
        iccid_str = str(self.input_value)
        if len(iccid_str) < 18 or len(iccid_str) > 20:
            raise ValueError('ICCID must be 18, 19 or 20 digits long')
        if not iccid_str.isdecimal():
            raise ValueError('ICCID must only contain decimal digits')
        self.value = sanitize_iccid(iccid_str)

    def apply(self, pes: ProfileElementSequence):
        # patch the header
        pes.get_pe_for_type('header').decoded['iccid'] = h2b(rpad(self.value, 20))
        # patch MF/EF.ICCID
        file_replace_content(pes.get_pe_for_type('mf').decoded['ef-iccid'], h2b(enc_iccid(self.value)))

class Imsi(ConfigurableParameter):
    """Configurable IMSI. Expects value to be a string of digits. Automatically sets the ACC to
    the last digit of the IMSI."""

    def validate(self):
        # convert to string as it might be an integer
        imsi_str = str(self.input_value)
        if len(imsi_str) < 6 or len(imsi_str) > 15:
            raise ValueError('IMSI must be 6..15 digits long')
        if not imsi_str.isdecimal():
            raise ValueError('IMSI must only contain decimal digits')
        self.value = imsi_str

    def apply(self, pes: ProfileElementSequence):
        imsi_str = self.value
        # we always use the least significant byte of the IMSI as ACC
        acc = (1 << int(imsi_str[-1]))
        # patch ADF.USIM/EF.IMSI
        for pe in pes.get_pes_for_type('usim'):
            file_replace_content(pe.decoded['ef-imsi'], h2b(enc_imsi(imsi_str)))
            file_replace_content(pe.decoded['ef-acc'], acc.to_bytes(2, 'big'))
        # TODO: DF.GSM_ACCESS if not linked?


class SdKey(ConfigurableParameter, metaclass=ClassVarMeta):
    """Configurable Security Domain (SD) Key.  Value is presented as bytes."""
    # these will be set by derived classes
    key_type = None
    key_id = None
    kvn = None
    key_usage_qual = None
    permitted_len = []

    def validate(self):
        if not isinstance(self.input_value, (io.BytesIO, bytes, bytearray)):
            raise ValueError('Value must be of bytes-like type')
        if self.permitted_len:
            if len(self.input_value) not in self.permitted_len:
                raise ValueError('Value length must be %s' % self.permitted_len)
        self.value = self.input_value

    def _apply_sd(self, pe: ProfileElement):
        assert pe.type == 'securityDomain'
        for key in pe.decoded['keyList']:
            if key['keyIdentifier'][0] == self.key_id and key['keyVersionNumber'][0] == self.kvn:
                assert len(key['keyComponents']) == 1
                key['keyComponents'][0]['keyData'] = self.value
                return
        # Could not find matching key to patch, create a new one
        key = {
            'keyUsageQualifier': bytes([self.key_usage_qual]),
            'keyIdentifier': bytes([self.key_id]),
            'keyVersionNumber': bytes([self.kvn]),
            'keyComponents': [
                { 'keyType': bytes([self.key_type]), 'keyData': self.value },
            ]
        }
        pe.decoded['keyList'].append(key)

    def apply(self, pes: ProfileElementSequence):
        for pe in pes.get_pes_for_type('securityDomain'):
            self._apply_sd(pe)

class SdKeyScp80_01(SdKey, kvn=0x01, key_type=0x88, permitted_len=[16,24,32]): # AES key type
    pass
class SdKeyScp80_01Kic(SdKeyScp80_01, key_id=0x01, key_usage_qual=0x18): # FIXME: ordering?
    pass
class SdKeyScp80_01Kid(SdKeyScp80_01, key_id=0x02, key_usage_qual=0x14):
    pass
class SdKeyScp80_01Kik(SdKeyScp80_01, key_id=0x03, key_usage_qual=0x48):
    pass

class SdKeyScp81_01(SdKey, kvn=0x81): # FIXME
    pass
class SdKeyScp81_01Psk(SdKeyScp81_01, key_id=0x01, key_type=0x85, key_usage_qual=0x3C):
    pass
class SdKeyScp81_01Dek(SdKeyScp81_01, key_id=0x02, key_type=0x88, key_usage_qual=0x48):
    pass

class SdKeyScp02_20(SdKey, kvn=0x20, key_type=0x88, permitted_len=[16,24,32]): # AES key type
    pass
class SdKeyScp02_20Enc(SdKeyScp02_20, key_id=0x01, key_usage_qual=0x18):
    pass
class SdKeyScp02_20Mac(SdKeyScp02_20, key_id=0x02, key_usage_qual=0x14):
    pass
class SdKeyScp02_20Dek(SdKeyScp02_20, key_id=0x03, key_usage_qual=0x48):
    pass

class SdKeyScp03_30(SdKey, kvn=0x30, key_type=0x88, permitted_len=[16,24,32]): # AES key type
    pass
class SdKeyScp03_30Enc(SdKeyScp03_30, key_id=0x01, key_usage_qual=0x18):
    pass
class SdKeyScp03_30Mac(SdKeyScp03_30, key_id=0x02, key_usage_qual=0x14):
    pass
class SdKeyScp03_30Dek(SdKeyScp03_30, key_id=0x03, key_usage_qual=0x48):
    pass

class SdKeyScp03_31(SdKey, kvn=0x31, key_type=0x88, permitted_len=[16,24,32]): # AES key type
    pass
class SdKeyScp03_31Enc(SdKeyScp03_31, key_id=0x01, key_usage_qual=0x18):
    pass
class SdKeyScp03_31Mac(SdKeyScp03_31, key_id=0x02, key_usage_qual=0x14):
    pass
class SdKeyScp03_31Dek(SdKeyScp03_31, key_id=0x03, key_usage_qual=0x48):
    pass

class SdKeyScp03_32(SdKey, kvn=0x32, key_type=0x88, permitted_len=[16,24,32]): # AES key type
    pass
class SdKeyScp03_32Enc(SdKeyScp03_32, key_id=0x01, key_usage_qual=0x18):
    pass
class SdKeyScp03_32Mac(SdKeyScp03_32, key_id=0x02, key_usage_qual=0x14):
    pass
class SdKeyScp03_32Dek(SdKeyScp03_32, key_id=0x03, key_usage_qual=0x48):
    pass




def obtain_singleton_pe_from_pelist(l: List[ProfileElement], wanted_type: str) -> ProfileElement:
    filtered = list(filter(lambda x: x.type == wanted_type, l))
    assert len(filtered) == 1
    return filtered[0]

def obtain_first_pe_from_pelist(l: List[ProfileElement], wanted_type: str) -> ProfileElement:
    filtered = list(filter(lambda x: x.type == wanted_type, l))
    return filtered[0]

class Puk(ConfigurableParameter, metaclass=ClassVarMeta):
    """Configurable PUK (Pin Unblock Code). String ASCII-encoded digits."""
    keyReference = None
    def validate(self):
        if isinstance(self.input_value, int):
            self.value = '%08d' % self.input_value
        else:
            self.value = self.input_value
        # FIXME: valid length?
        if not self.value.isdecimal():
            raise ValueError('PUK must only contain decimal digits')

    def apply(self, pes: ProfileElementSequence):
        puk = ''.join(['%02x' % (ord(x)) for x in self.value])
        padded_puk = rpad(puk, 16)
        mf_pes = pes.pes_by_naa['mf'][0]
        pukCodes = obtain_singleton_pe_from_pelist(mf_pes, 'pukCodes')
        for pukCode in pukCodes.decoded['pukCodes']:
            if pukCode['keyReference'] == self.keyReference:
                pukCode['pukValue'] = h2b(padded_puk)
                return
        raise ValueError('cannot find pukCode')
class Puk1(Puk, keyReference=0x01):
    pass
class Puk2(Puk, keyReference=0x81):
    pass

class Pin(ConfigurableParameter, metaclass=ClassVarMeta):
    """Configurable PIN (Personal Identification Number).  String of digits."""
    keyReference = None
    def validate(self):
        if isinstance(self.input_value, int):
            self.value = '%04d' % self.input_value
        else:
            self.value = self.input_value
        if len(self.value) < 4 or len(self.value) > 8:
            raise ValueError('PIN mus be 4..8 digits long')
        if not self.value.isdecimal():
            raise ValueError('PIN must only contain decimal digits')
    def apply(self, pes: ProfileElementSequence):
        pin = ''.join(['%02x' % (ord(x)) for x in self.value])
        padded_pin = rpad(pin, 16)
        mf_pes = pes.pes_by_naa['mf'][0]
        pinCodes = obtain_first_pe_from_pelist(mf_pes, 'pinCodes')
        if pinCodes.decoded['pinCodes'][0] != 'pinconfig':
            return
        for pinCode in pinCodes.decoded['pinCodes'][1]:
            if pinCode['keyReference'] == self.keyReference:
                 pinCode['pinValue'] = h2b(padded_pin)
                 return
        raise ValueError('cannot find pinCode')
class AppPin(ConfigurableParameter, metaclass=ClassVarMeta):
    """Configurable PIN (Personal Identification Number).  String of digits."""
    keyReference = None
    def validate(self):
        if isinstance(self.input_value, int):
            self.value = '%04d' % self.input_value
        else:
            self.value = self.input_value
        if len(self.value) < 4 or len(self.value) > 8:
            raise ValueError('PIN mus be 4..8 digits long')
        if not self.value.isdecimal():
            raise ValueError('PIN must only contain decimal digits')
    def _apply_one(self, pe: ProfileElement):
        pin = ''.join(['%02x' % (ord(x)) for x in self.value])
        padded_pin = rpad(pin, 16)
        pinCodes = obtain_first_pe_from_pelist(pe, 'pinCodes')
        if pinCodes.decoded['pinCodes'][0] != 'pinconfig':
            return
        for pinCode in pinCodes.decoded['pinCodes'][1]:
            if pinCode['keyReference'] == self.keyReference:
                pinCode['pinValue'] = h2b(padded_pin)
                return
        raise ValueError('cannot find pinCode')
    def apply(self, pes: ProfileElementSequence):
        for naa in pes.pes_by_naa:
            if naa not in ['usim','isim','csim','telecom']:
                continue
            for instance in pes.pes_by_naa[naa]:
                self._apply_one(instance)
class Pin1(Pin, keyReference=0x01):
    pass
# PIN2 is special: telecom + usim + isim + csim
class Pin2(AppPin, keyReference=0x81):
    pass
class Adm1(Pin, keyReference=0x0A):
    pass
class Adm2(Pin, keyReference=0x0B):
    pass


class AlgoConfig(ConfigurableParameter, metaclass=ClassVarMeta):
    """Configurable Algorithm parameter."""
    key = None
    def validate(self):
        if not isinstance(self.input_value, (io.BytesIO, bytes, bytearray)):
            raise ValueError('Value must be of bytes-like type')
        self.value = self.input_value
    def apply(self, pes: ProfileElementSequence):
        for pe in pes.get_pes_for_type('akaParameter'):
            algoConfiguration = pe.decoded['algoConfiguration']
            if algoConfiguration[0] != 'algoParameter':
                continue
            algoConfiguration[1][self.key] = self.value

class K(AlgoConfig, key='key'):
    pass
class Opc(AlgoConfig, key='opc'):
    pass
class AlgorithmID(AlgoConfig, key='algorithmID'):
    def validate(self):
        if self.input_value not in [1, 2, 3]:
            raise ValueError('Invalid algorithmID %s' % (self.input_value))
        self.value = self.input_value
