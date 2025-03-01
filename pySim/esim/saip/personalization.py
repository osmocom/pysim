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

class ConfigurableParameter:
    r"""Base class representing a part of the eSIM profile that is configurable during the
    personalization process (with dynamic data from elsewhere).

    This class is abstract, you will only use subclasses in practice.

    Subclasses have to implement the apply_val() classmethods, and may choose to override the default validate_val()
    implementation.
    The default validate_val() is a generic validator that uses the following class members (defined in subclasses) to
    configure the validation; if any of them is None, it means that the particular validation is skipped:

    allow_types: a list of types permitted as argument to validate_val(); allow_types = (bytes, str,)
    allow_chars: if val is a str, accept only these characters; allow_chars = "0123456789"
    strip_chars: if val is a str, remove these characters; strip_chars = ' \t\r\n'
    min_len: minimum length of an input str; min_len = 4
    max_len: maximum length of an input str; max_len = 8
    allow_len: permit only specific lengths; allow_len = (8, 16, 32)

    Subclasses may change the meaning of these by overriding validate_val(), for example that the length counts
    resulting bytes instead of a hexstring length. Most subclasses will be covered by the default validate_val().

    Usage examples, by example of Iccid:

    1) use a ConfigurableParameter instance, with .input_value and .value state:

      iccid = Iccid()
      try:
        iccid.input_value = '123456789012345678'
        iccid.validate()
      except ValueError:
        print(f"failed to validate {iccid.name} == {iccid.input_value}")

      pes = ProfileElementSequence.from_der(der_data_from_file)
      try:
        iccid.apply(pes)
      except ValueError:
        print(f"failed to apply {iccid.name} := {iccid.input_value}")

      changed_der = pes.to_der()

    2) use a ConfigurableParameter class, without state:

      cls = Iccid
      input_val = '123456789012345678'

      try:
        clean_val = cls.validate_val(input_val)
      except ValueError:
        print(f"failed to validate {cls.get_name()} = {input_val}")

      pes = ProfileElementSequence.from_der(der_data_from_file)
      try:
        cls.apply_val(pes, clean_val)
      except ValueError:
        print(f"failed to apply {cls.get_name()} = {input_val}")

      changed_der = pes.to_der()
    """

    # A subclass can set an explicit string as name (like name = "PIN1").
    # If name is left None, then __init__() will set self.name to a name derived from the python class name (like
    # "pin1"). See also the get_name() classmethod when you have no instance at hand.
    name = None
    allow_types = (str, int, )
    allow_chars = None
    strip_chars = None
    min_len = None
    max_len = None
    allow_len = None # a list of specific lengths

    def __init__(self, input_value=None):
        self.input_value = input_value # the raw input value as given by caller
        self.value = None # the processed input value (e.g. with check digit) as produced by validate()

        # set the instance's name to either an explicit name string, or to a name derived from the class name.
        if self.name is None:
            self.name = self.get_name()

    @classmethod
    def get_name(cls):
        """Return cls.name when it is set, otherwise return the python class name converted from 'CamelCase' to
        'snake_case'.
        When using class *instances*, you can just use my_instance.name.
        When using *classes*, cls.get_name() returns the same name a class instance would have.
        """
        if cls.name:
            return cls.name
        return camel_to_snake(cls.__name__)

    def validate(self):
        """Validate self.input_value and place the result in self.value.
        This is also called implicitly by apply(), if self.value is still None.
        To override validation in a subclass, rather re-implement the classmethod validate_val()."""
        try:
            self.value = self.__class__.validate_val(self.input_value)
        except (TypeError, ValueError, KeyError) as e:
            raise ValueError(f'{self.name}: {e}') from e

    def apply(self, pes: ProfileElementSequence):
        """Place self.value into the ProfileElementSequence at the right place.
        If self.value is None, this implicitly calls self.validate() first, to generate a sanitized self.value from
        self.input_value.
        To override apply() in a subclass, rather override the classmethod apply_val()."""
        if self.value is None:
            self.validate()
            assert self.value is not None
        try:
            self.__class__.apply_val(pes, self.value)
        except (TypeError, ValueError, KeyError) as e:
            raise ValueError(f'{self.name}: {e}') from e

    @classmethod
    def validate_val(cls, val):
        """This is a default implementation, with the behavior configured by subclasses' allow_types...max_len settings.
        subclasses may override this function:
        Validate the contents of val, and raise ValueError on validation errors.
        Return a sanitized version of val, that is ready for cls.apply_val().
        """

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
                    raise ValueError(f"invalid characters in input value {val!r}, valid chars are {cls.allow_chars}")
        if cls.allow_len is not None:
            l = cls.allow_len
            # cls.allow_len could be one int, or a tuple of ints. Wrap a single int also in a tuple.
            if not isinstance(l, (tuple, list)):
                l = (l,)
            if len(val) not in l:
                raise ValueError(f'length must be one of {cls.allow_len}, not {len(val)}: {val!r}')
        if cls.min_len is not None:
            if len(val) < cls.min_len:
                raise ValueError(f'length must be at least {cls.min_len}, not {len(val)}: {val!r}')
        if cls.max_len is not None:
            if len(val) > cls.max_len:
                raise ValueError(f'length must be at most {cls.max_len}, not {len(val)}: {val!r}')
        return val

    @classmethod
    @abc.abstractmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        """This is what subclasses implement: store a value in a decoded profile package.
        Write the given val in the right format in all the right places in pes."""
        pass

    @classmethod
    def get_len_range(cls):
        """considering all of min_len, max_len and allow_len, get a tuple of the resulting (min, max) of permitted
        value length. For example, if an input value is an int, which needs to be represented with a minimum nr of
        digits, this function is useful to easily get that minimum permitted length.
        """
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
            return (None, None)
        return (min(vals), max(vals))


class DecimalParam(ConfigurableParameter):
    """Decimal digits. The input value may be a string of decimal digits like '012345', or an int. The output of
    validate_val() is a string with only decimal digits 0-9, in the required length with leading zeros if necessary.
    """
    allow_types = (str, int)
    allow_chars = '0123456789'

    @classmethod
    def validate_val(cls, val):
        if isinstance(val, int):
            min_len, max_len = cls.get_len_range()
            l = min_len or 1
            val = '%0*d' % (l, val)
        return super().validate_val(val)


class DecimalHexParam(DecimalParam):
    """The input value is decimal digits. The decimal value is stored such that each hexadecimal digit represents one
    decimal digit, useful for various PIN type parameters.

    Optionally, the value is stored with padding, for example: rpad = 8 would store '123' as '123fffff'. This is also
    common in PIN type parameters.
    """
    rpad = None
    rpad_char = 'f'

    @classmethod
    def validate_val(cls, val):
        val = super().validate_val(val)
        val = ''.join('%02x' % ord(x) for x in val)
        if cls.rpad is not None:
            c = cls.rpad_char
            val = rpad(val, cls.rpad, c)
        # a DecimalHexParam subclass expects the apply_val() input to be a bytes instance ready for the pes
        return h2b(val)


class Iccid(DecimalParam):
    """ICCID Parameter. Input: string of decimal digits.
    If the string of digits is only 18 digits long, add a Luhn check digit."""
    min_len = 18
    max_len = 20

    @classmethod
    def validate_val(cls, val):
        iccid_str = super().validate_val(val)
        return sanitize_iccid(iccid_str)

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        # patch the header
        pes.get_pe_for_type('header').decoded['iccid'] = h2b(rpad(val, 20))
        # patch MF/EF.ICCID
        file_replace_content(pes.get_pe_for_type('mf').decoded['ef-iccid'], h2b(enc_iccid(val)))

class Imsi(DecimalParam):
    """Configurable IMSI. Expects value to be a string of digits. Automatically sets the ACC to
    the last digit of the IMSI."""
    min_len = 6
    max_len = 15

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


class SdKey(ConfigurableParameter):
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

class SdKeyScp80_01(SdKey):
    kvn = 0x01
    key_type = 0x88 # AES key type
    allow_len = (16,24,32)

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
    key_type = 0x88 # AES key type
    allow_len = (16,24,32)

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
    key_type = 0x88 # AES key type
    allow_len = (16,24,32)

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
    key_type = 0x88 # AES key type
    allow_len = (16,24,32)

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
    key_type = 0x88 # AES key type
    allow_len = (16,24,32)

class SdKeyScp03_32Enc(SdKeyScp03_32):
    key_id = 0x01
    key_usage_qual = 0x18

class SdKeyScp03_32Mac(SdKeyScp03_32):
    key_id = 0x02
    key_usage_qual = 0x14

class SdKeyScp03_32Dek(SdKeyScp03_32):
    key_id = 0x03
    key_usage_qual = 0x48


def obtain_singleton_pe_from_pelist(l: List[ProfileElement], wanted_type: str) -> ProfileElement:
    filtered = list(filter(lambda x: x.type == wanted_type, l))
    assert len(filtered) == 1
    return filtered[0]

def obtain_first_pe_from_pelist(l: List[ProfileElement], wanted_type: str) -> ProfileElement:
    filtered = list(filter(lambda x: x.type == wanted_type, l))
    return filtered[0]


class Puk(DecimalHexParam):
    """Configurable PUK (Pin Unblock Code). String ASCII-encoded digits."""
    allow_len = 8
    rpad = 16
    keyReference = None

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        val_bytes = val
        mf_pes = pes.pes_by_naa['mf'][0]
        pukCodes = obtain_singleton_pe_from_pelist(mf_pes, 'pukCodes')
        for pukCode in pukCodes.decoded['pukCodes']:
            if pukCode['keyReference'] == cls.keyReference:
                pukCode['pukValue'] = val_bytes
                return
        raise ValueError("input template UPP has unexpected structure:"
                         f" cannot find pukCode with keyReference={cls.keyReference}")

class Puk1(Puk):
    keyReference = 0x01

class Puk2(Puk):
    keyReference = 0x81


class Pin(ConfigurableParameter):
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

class AppPin(ConfigurableParameter):
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
class Pin1(Pin):
    keyReference = 0x01

# PIN2 is special: telecom + usim + isim + csim
class Pin2(AppPin):
    keyReference = 0x81

class Adm1(Pin):
    keyReference = 0x0A

class Adm2(Pin):
    keyReference = 0x0B


class AlgoConfig(ConfigurableParameter):
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

class K(AlgoConfig):
    key = 'key'
class Opc(AlgoConfig):
    key = 'opc'

class AlgorithmID(AlgoConfig):
    key = 'algorithmID'
    def validate(self):
        if self.input_value not in [1, 2, 3]:
            raise ValueError('Invalid algorithmID %s' % (self.input_value))
        self.value = self.input_value
