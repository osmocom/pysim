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
import os
import copy
import re
import pprint
from typing import List, Tuple, Generator, Optional

from osmocom.tlv import camel_to_snake
from osmocom.utils import hexstr
from pySim.utils import enc_iccid, dec_iccid, enc_imsi, dec_imsi, h2b, b2h, rpad, sanitize_iccid, all_subclasses_of
from pySim.esim.saip import param_source
from pySim.esim.saip import ProfileElement, ProfileElementSD, ProfileElementSequence
from pySim.esim.saip import SecurityDomainKey, SecurityDomainKeyComponent
from pySim.global_platform import KeyUsageQualifier, KeyType

def unrpad(s: hexstr, c='f') -> hexstr:
    return hexstr(s.rstrip(c))

def remove_unwanted_tuples_from_list(l: List[Tuple], unwanted_keys: List[str]) -> List[Tuple]:
    """In a list of tuples, remove all tuples whose first part equals 'unwanted_key'."""
    return list(filter(lambda x: x[0] not in unwanted_keys, l))

def file_replace_content(file: List[Tuple], new_content: bytes):
    """Completely replace all fillFileContent of a decoded 'File' with the new_content."""
    # use [:] to avoid making a copy, as we're doing in-place modification of the list here
    file[:] = remove_unwanted_tuples_from_list(file, ['fillFileContent', 'fillFileOffset'])
    file.append(('fillFileContent', new_content))
    return file

def file_tuples_content_as_bytes(l: List[Tuple]) -> Optional[bytes]:
    """linearize a list of fillFileContent / fillFileOffset tuples into a stream of bytes."""
    stream = io.BytesIO()
    for k, v in l:
        if k == 'doNotCreate':
            return None
        if k == 'fileDescriptor':
            pass
        elif k == 'fillFileOffset':
            stream.seek(v, os.SEEK_CUR)
        elif k == 'fillFileContent':
            stream.write(v)
        else:
            return ValueError("Unknown key '%s' in tuple list" % k)
    return stream.getvalue()

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

    # for get_all_implementations(), telling callers about all practically useful parameters
    is_abstract = True

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
    default_value = None
    default_source = None # a param_source.ParamSource subclass

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
        elif isinstance(val, io.BytesIO):
            val = val.getvalue()

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
    def get_value_from_pes(cls, pes: ProfileElementSequence):
        """Same as get_values_from_pes() but expecting a single value.
           get_values_from_pes() may return values like this:
             [{ 'AlgorithmID': 'Milenage' }, { 'AlgorithmID': 'Milenage' }]
           This ensures that all these entries are identical and would return only
              { 'AlgorithmID': 'Milenage' }.

           This is relevant for any profile element that may appear multiple times in the same PES (only a few),
           where each occurrence should reflect the same value (all currently known parameters).
        """

        val = None
        for v in cls.get_values_from_pes(pes):
            if val is None:
                val = v
            elif val != v:
                    raise ValueError(f'get_value_from_pes(): got distinct values: {val!r} != {v!r}')
        return val

    @classmethod
    def get_values_from_pes(cls, pes: ProfileElementSequence) -> Generator:
        """This is what subclasses implement: yield all values from a decoded profile package.
           Find all values in the pes, and yield them decoded to a valid cls.input_value format.
           Should be a generator function, i.e. use 'yield' instead of 'return'.

           Yielded value must be a dict(). Usually, an implementation will return only one key, like

              { "ICCID": "1234567890123456789" }

           Some implementations have more than one value to return, like

              { "IMSI": "00101012345678", "IMSI-ACC" : "5" }

           Implementation example:

             for pe in pes:
                if my_condition(pe):
                    yield { cls.name: b2h(my_bin_value_from(pe)) }
           """
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

    @classmethod
    def get_typical_input_len(cls):
        '''return a good length to use as the visible width of a user interface input field.
           May be overridden by subclasses.
           This default implementation returns the maximum allowed value length -- a good fit for most subclasses.
           '''
        return cls.get_len_range()[1] or 16

    @classmethod
    def get_all_implementations(cls, blacklist=None, allow_abstract=False):
        # return a set() so that multiple inheritance does not return dups
        return set(c
                   for c in all_subclasses_of(cls)
                   if ((allow_abstract or not c.is_abstract)
                       and ((not blacklist) or (c not in blacklist)))
                  )

    @classmethod
    def is_super_of(cls, other_class):
        try:
            return issubclass(other_class, cls)
        except TypeError:
            return False

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

    @classmethod
    def decimal_hex_to_str(cls, val):
        'useful for get_values_from_pes() implementations of subclasses'
        if isinstance(val, bytes):
            val = b2h(val)
        assert isinstance(val, hexstr)
        if cls.rpad is not None:
            c = cls.rpad_char or 'f'
            val = unrpad(val, c)
        return val.to_bytes().decode('ascii')


class BinaryParam(ConfigurableParameter):
    allow_types = (str, io.BytesIO, bytes, bytearray, int)
    allow_chars = '0123456789abcdefABCDEF'
    strip_chars = ' \t\r\n'

    @classmethod
    def validate_val(cls, val):
        # take care that min_len and max_len are applied to the binary length by converting to bytes first
        if isinstance(val, int):
            min_len, _max_len = cls.get_len_range()
            val = '%0*d' % (min_len, val)

        if isinstance(val, str):
            if cls.strip_chars is not None:
                val = ''.join(c for c in val if c not in cls.strip_chars)
            if len(val) & 1:
                raise ValueError('Invalid hexadecimal string, must have even number of digits:'
                                 f' {val!r} {len(val)=}')
            try:
                val = h2b(val)
            except ValueError as e:
                raise ValueError(f'Invalid hexadecimal string: {val!r} {len(val)=}') from e

        val = super().validate_val(val)
        return bytes(val)

    @classmethod
    def get_typical_input_len(cls):
        # override to return twice the length, because of hex digits.
        min_len, max_len = cls.get_len_range()
        if max_len is None:
            return None
        # two hex characters per value octet.
        # (maybe *3 to also allow for spaces?)
        return max_len * 2


class EnumParam(ConfigurableParameter):
    value_map = {
            # For example:
            #'Meaningful label for value 23': 0x23,
            # Where 0x23 is a valid value to use for apply_val().
        }
    _value_map_reverse = None

    @classmethod
    def validate_val(cls, val):
        orig_val = val
        enum_val = None
        if isinstance(val, str):
            enum_name = val
            enum_val = cls.map_name_to_val(enum_name)

        # if the str is not one of the known value_map.keys(), is it maybe one of value_map.keys()?
        if enum_val is None and val in cls.value_map.values():
            enum_val = val

        if enum_val not in cls.value_map.values():
            raise ValueError(f"{cls.get_name()}: invalid argument: {orig_val!r}. Valid arguments are:"
                             f" {', '.join(cls.value_map.keys())}")

        return enum_val

    @classmethod
    def map_name_to_val(cls, name:str, strict=True):
        val = cls.value_map.get(name)
        if val is not None:
            return val

        clean_name = cls.clean_name_str(name)
        for k, v in cls.value_map.items():
            if clean_name == cls.clean_name_str(k):
                return v

        if strict:
            raise ValueError(f"Problem in {cls.get_name()}: {name!r} is not a known value."
                    f" Known values are: {cls.value_map.keys()!r}")
        return None

    @classmethod
    def map_val_to_name(cls, val, strict=False) -> str:
        if cls._value_map_reverse is None:
            cls._value_map_reverse = dict((v, k) for k, v in cls.value_map.items())

        name = cls._value_map_reverse.get(val)
        if name:
            return name
        if strict:
            raise ValueError(f"Problem in {cls.get_name()}: {val!r} ({type(val)}) is not a known value."
                    f" Known values are: {cls.value_map.values()!r}")
        return None

    @classmethod
    def name_normalize(cls, name:str) -> str:
        return cls.map_val_to_name(cls.map_name_to_val(name))

    @classmethod
    def clean_name_str(cls, val):
        return re.sub('[^0-9A-Za-z-_]', '', val).lower()


class Iccid(DecimalParam):
    """ICCID Parameter. Input: string of decimal digits.
    If the string of digits is only 18 digits long, add a Luhn check digit."""
    is_abstract = False
    name = 'ICCID'
    min_len = 18
    max_len = 20
    default_value = '0*18'
    default_source = param_source.IncDigitSource

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

    @classmethod
    def get_values_from_pes(cls, pes: ProfileElementSequence):
        padded = b2h(pes.get_pe_for_type('header').decoded['iccid'])
        iccid = unrpad(padded)
        yield { cls.name: iccid }

        for pe in pes.get_pes_for_type('mf'):
            iccid_pe = pe.decoded.get('ef-iccid', None)
            if iccid_pe:
                yield { cls.name: dec_iccid(b2h(file_tuples_content_as_bytes(iccid_pe))) }

class Imsi(DecimalParam):
    """Configurable IMSI. Expects value to be a string of digits. Automatically sets the ACC to
    the last digit of the IMSI."""
    is_abstract = False

    name = 'IMSI'
    min_len = 6
    max_len = 15
    default_value = '00101' + ('0' * 10)
    default_source = param_source.IncDigitSource

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
    def get_values_from_pes(cls, pes: ProfileElementSequence):
        for pe in pes.get_pes_for_type('usim'):
            imsi_pe = pe.decoded.get('ef-imsi', None)
            acc_pe = pe.decoded.get('ef-acc', None)
            y = {}
            if imsi_pe:
                y[cls.name] = dec_imsi(b2h(file_tuples_content_as_bytes(imsi_pe)))
            if acc_pe:
                y[cls.name + '-ACC'] = b2h(file_tuples_content_as_bytes(acc_pe))
            yield y


class SdKey(BinaryParam):
    """Configurable Security Domain (SD) Key.  Value is presented as bytes."""
    # these will be set by subclasses
    key_type = None
    kvn = None
    reserved_kvn = tuple() # tuple of all reserved kvn for a given SCPxx
    key_id = None
    key_usage_qual = None
    default_source = param_source.RandomHexDigitSource

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        set_components = [ SecurityDomainKeyComponent(cls.key_type, val) ]

        for pe in pes.pe_list:
            if pe.type != 'securityDomain':
                continue
            assert isinstance(pe, ProfileElementSD)

            key = pe.find_key(key_version_number=cls.kvn, key_id=cls.key_id)
            if not key:
                # Could not find matching key to patch, create a new one
                key = SecurityDomainKey(
                        key_version_number=cls.kvn,
                        key_id=cls.key_id,
                        key_usage_qualifier=cls.key_usage_qual,
                        key_components=set_components,
                        )
                pe.add_key(key)
            else:
                key.key_components = set_components

    @classmethod
    def get_values_from_pes(cls, pes: ProfileElementSequence):
        for pe in pes.pe_list:
            if pe.type != 'securityDomain':
                continue
            assert isinstance(pe, ProfileElementSD)

            key = pe.find_key(key_version_number=cls.kvn, key_id=cls.key_id)
            if not key:
                continue
            kc = key.get_key_component(cls.key_type)
            if kc:
                yield { cls.name: b2h(kc) }

# Offer these Security Domain Keys:
#
# security domain | reserved KVN range
# ----------------------------
# SCP80 | 0x01 .. 0x0f
# SCP81 | 0x81 .. 0x8f
# SCP02 | 0x20 .. 0x2f, 0xff
# SCP03 | 0x30 .. 0x3f
#
# The KVN allows adding multiple security domains of the same type.
#
# Also, for each security domain, there are three keys: ENC, MAC and DEK, indicated by key_id.
# key | alternate name | key_id | key_usage_qual
#-----------------------------------------------
# ENC | KIC            | 0x01   | 0x18
# MAC | KID            | 0x02   | 0x14
# DEK | KIK            | 0x03   | 0x48
#
# For each, offer a couple of separate SdKey subclasses, only partially covering the reserved KVN range. For KVN, again
# a separate subclass for eack key_id for ENC, MAC and DEK.
#
# All of these are AES keys.
#
# For example, for SCP80 we have:
# SdKeyAes
#   SdKeyScp80Kvn01
#     SdKeyScp80Kvn01Enc
#     SdKeyScp80Kvn01Mac
#     SdKeyScp80Kvn01Dek
#   SdKeyScp80Kvn02
#     SdKeyScp80Kvn02Enc
#     SdKeyScp80Kvn02Mac
#     SdKeyScp80Kvn02Dek
#   SdKeyScp80Kvn03
#     SdKeyScp80Kvn03Enc
#     SdKeyScp80Kvn03Mac
#     SdKeyScp80Kvn03Dek
#
# (Only the leaf nodes with ...Enc/Mac/Dek are returned by
# ConfigurableParameter.get_all_implementations(allow_abstract=False))

class SdKeyAes(SdKey):
    key_type = KeyType.aes
    allow_len = (16,24,32)
    default_value = '00*32'


class SdKeyScp80(SdKeyAes):
    name = 'SCP80'
    reserved_kvn = tuple(range(0x01, 0x0f + 1))

class SdKeyScp80AesKvn01(SdKeyScp80):
    name = 'SCP80-KVN01-AES'
    kvn = 0x01
class SdKeyScp80AesKvn01Enc(SdKeyScp80AesKvn01):
    is_abstract = False
    name = SdKeyScp80AesKvn01.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp80AesKvn01Mac(SdKeyScp80AesKvn01):
    is_abstract = False
    name = SdKeyScp80AesKvn01.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp80AesKvn01Dek(SdKeyScp80AesKvn01):
    is_abstract = False
    name = SdKeyScp80AesKvn01.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

class SdKeyScp80DesKvn01(SdKeyScp80):
    name = 'SCP80-KVN01-DES'
    kvn = 0x01
    key_type = KeyType.des
class SdKeyScp80DesKvn01Enc(SdKeyScp80DesKvn01):
    is_abstract = False
    name = SdKeyScp80DesKvn01.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp80DesKvn01Mac(SdKeyScp80DesKvn01):
    is_abstract = False
    name = SdKeyScp80DesKvn01.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp80DesKvn01Dek(SdKeyScp80DesKvn01):
    is_abstract = False
    name = SdKeyScp80DesKvn01.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

class SdKeyScp80Kvn02(SdKeyScp80):
    name = 'SCP80-KVN02-AES'
    kvn = 0x02
class SdKeyScp80Kvn02Enc(SdKeyScp80Kvn02):
    is_abstract = False
    name = SdKeyScp80Kvn02.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp80Kvn02Mac(SdKeyScp80Kvn02):
    is_abstract = False
    name = SdKeyScp80Kvn02.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp80Kvn02Dek(SdKeyScp80Kvn02):
    is_abstract = False
    name = SdKeyScp80Kvn02.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

class SdKeyScp80Kvn03(SdKeyScp80):
    name = 'SCP80-KVN03-AES'
    kvn = 0x03
class SdKeyScp80Kvn03Enc(SdKeyScp80Kvn03):
    is_abstract = False
    name = SdKeyScp80Kvn03.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp80Kvn03Mac(SdKeyScp80Kvn03):
    is_abstract = False
    name = SdKeyScp80Kvn03.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp80Kvn03Dek(SdKeyScp80Kvn03):
    is_abstract = False
    name = SdKeyScp80Kvn03.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

# "omitting" SdKeyScp80Kvn04 ... Kvn0f

class SdKeyScp81(SdKeyAes):
    name = 'SCP81'
    reserved_kvn = tuple(range(0x81, 0x8f + 1))

class SdKeyScp81Kvn81(SdKeyScp81):
    name = 'SCP81-KVN81-AES'
    kvn = 0x81
class SdKeyScp81Kvn81Enc(SdKeyScp81Kvn81):
    is_abstract = False
    name = SdKeyScp81Kvn81.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp81Kvn81Mac(SdKeyScp81Kvn81):
    is_abstract = False
    name = SdKeyScp81Kvn81.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp81Kvn81Dek(SdKeyScp81Kvn81):
    is_abstract = False
    name = SdKeyScp81Kvn81.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

class SdKeyScp81Kvn82(SdKeyScp81):
    name = 'SCP81-KVN82-AES'
    kvn = 0x82
class SdKeyScp81Kvn82Enc(SdKeyScp81Kvn82):
    is_abstract = False
    name = SdKeyScp81Kvn82.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp81Kvn82Mac(SdKeyScp81Kvn82):
    is_abstract = False
    name = SdKeyScp81Kvn82.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp81Kvn82Dek(SdKeyScp81Kvn82):
    is_abstract = False
    name = SdKeyScp81Kvn82.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

class SdKeyScp81Kvn83(SdKeyScp81):
    name = 'SCP81-KVN83-AES'
    kvn = 0x83
class SdKeyScp81Kvn83Enc(SdKeyScp81Kvn83):
    is_abstract = False
    name = SdKeyScp81Kvn83.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp81Kvn83Mac(SdKeyScp81Kvn83):
    is_abstract = False
    name = SdKeyScp81Kvn83.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp81Kvn83Dek(SdKeyScp81Kvn83):
    is_abstract = False
    name = SdKeyScp81Kvn83.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

# "omitting" SdKeyScp81Kvn84 ... Kvn8f

class SdKeyScp02(SdKeyAes):
    name = 'SCP02'
    reserved_kvn = tuple(range(0x20, 0x2f + 1)) + (0xff, )
class SdKeyScp02Kvn20(SdKeyScp02):
    name = 'SCP02-20-AES'
    kvn = 0x20
class SdKeyScp02Kvn20Enc(SdKeyScp02Kvn20):
    is_abstract = False
    name = SdKeyScp02Kvn20.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp02Kvn20Mac(SdKeyScp02Kvn20):
    is_abstract = False
    name = SdKeyScp02Kvn20.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp02Kvn20Dek(SdKeyScp02Kvn20):
    is_abstract = False
    name = SdKeyScp02Kvn20.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

class SdKeyScp02Kvn21(SdKeyScp02):
    name = 'SCP02-21-AES'
    kvn = 0x21
class SdKeyScp02Kvn21Enc(SdKeyScp02Kvn21):
    is_abstract = False
    name = SdKeyScp02Kvn21.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp02Kvn21Mac(SdKeyScp02Kvn21):
    is_abstract = False
    name = SdKeyScp02Kvn21.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp02Kvn21Dek(SdKeyScp02Kvn21):
    is_abstract = False
    name = SdKeyScp02Kvn21.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

class SdKeyScp02Kvn22(SdKeyScp02):
    name = 'SCP02-22-AES'
    kvn = 0x22
class SdKeyScp02Kvn22Enc(SdKeyScp02Kvn22):
    is_abstract = False
    name = SdKeyScp02Kvn22.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp02Kvn22Mac(SdKeyScp02Kvn22):
    is_abstract = False
    name = SdKeyScp02Kvn22.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp02Kvn22Dek(SdKeyScp02Kvn22):
    is_abstract = False
    name = SdKeyScp02Kvn22.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

# "omitting" SdKeyScp02Kvn23 ... Kvn2f

class SdKeyScp02Kvnff(SdKeyScp02):
    name = 'SCP02-ff-AES'
    kvn = 0xff
class SdKeyScp02KvnffEnc(SdKeyScp02Kvnff):
    is_abstract = False
    name = SdKeyScp02Kvnff.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp02KvnffMac(SdKeyScp02Kvnff):
    is_abstract = False
    name = SdKeyScp02Kvnff.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp02KvnffDek(SdKeyScp02Kvnff):
    is_abstract = False
    name = SdKeyScp02Kvnff.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48


class SdKeyScp03(SdKeyAes):
    name = 'SCP03'
    reserved_kvn = tuple(range(0x30, 0x3f + 1))

class SdKeyScp03Kvn30(SdKeyScp03):
    name = 'SCP03-30-AES'
    kvn = 0x30
class SdKeyScp03Kvn30Enc(SdKeyScp03Kvn30):
    is_abstract = False
    name = SdKeyScp03Kvn30.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp03Kvn30Mac(SdKeyScp03Kvn30):
    is_abstract = False
    name = SdKeyScp03Kvn30.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp03Kvn30Dek(SdKeyScp03Kvn30):
    is_abstract = False
    name = SdKeyScp03Kvn30.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

class SdKeyScp03Kvn31(SdKeyScp03):
    name = 'SCP03-31-AES'
    kvn = 0x31
class SdKeyScp03Kvn31Enc(SdKeyScp03Kvn31):
    is_abstract = False
    name = SdKeyScp03Kvn31.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp03Kvn31Mac(SdKeyScp03Kvn31):
    is_abstract = False
    name = SdKeyScp03Kvn31.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp03Kvn31Dek(SdKeyScp03Kvn31):
    is_abstract = False
    name = SdKeyScp03Kvn31.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

class SdKeyScp03Kvn32(SdKeyScp03):
    name = 'SCP03-32-AES'
    kvn = 0x32
class SdKeyScp03Kvn32Enc(SdKeyScp03Kvn32):
    is_abstract = False
    name = SdKeyScp03Kvn32.name + '-ENC'
    key_id = 0x01
    key_usage_qual = 0x18
class SdKeyScp03Kvn32Mac(SdKeyScp03Kvn32):
    is_abstract = False
    name = SdKeyScp03Kvn32.name + '-MAC'
    key_id = 0x02
    key_usage_qual = 0x14
class SdKeyScp03Kvn32Dek(SdKeyScp03Kvn32):
    is_abstract = False
    name = SdKeyScp03Kvn32.name + '-DEK'
    key_id = 0x03
    key_usage_qual = 0x48

# "omitting" SdKeyScp03Kvn33 ... Kvn3f

def obtain_all_pe_from_pelist(l: List[ProfileElement], wanted_type: str) -> ProfileElement:
    return (pe for pe in l if pe.type == wanted_type)

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
    default_value = f'0*{allow_len}'
    default_source = param_source.RandomDigitSource

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

    @classmethod
    def get_values_from_pes(cls, pes: ProfileElementSequence):
        mf_pes = pes.pes_by_naa['mf'][0]
        for pukCodes in obtain_all_pe_from_pelist(mf_pes, 'pukCodes'):
            for pukCode in pukCodes.decoded['pukCodes']:
                if pukCode['keyReference'] == cls.keyReference:
                    yield { cls.name: cls.decimal_hex_to_str(pukCode['pukValue']) }

class Puk1(Puk):
    is_abstract = False
    name = 'PUK1'
    keyReference = 0x01

class Puk2(Puk):
    is_abstract = False
    name = 'PUK2'
    keyReference = 0x81

class Pin(DecimalHexParam):
    """Configurable PIN (Personal Identification Number).  String of digits."""
    rpad = 16
    min_len = 4
    max_len = 8
    default_value = f'0*{max_len}'
    default_source = param_source.RandomDigitSource
    keyReference = None

    @staticmethod
    def _apply_pinvalue(pe: ProfileElement, keyReference, val_bytes):
        for pinCodes in obtain_all_pe_from_pelist(pe, 'pinCodes'):
            if pinCodes.decoded['pinCodes'][0] != 'pinconfig':
                continue

            for pinCode in pinCodes.decoded['pinCodes'][1]:
                if pinCode['keyReference'] == keyReference:
                     pinCode['pinValue'] = val_bytes
                     return True
        return False

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        val_bytes = val
        if not cls._apply_pinvalue(pes.pes_by_naa['mf'][0], cls.keyReference, val_bytes):
            raise ValueError('input template UPP has unexpected structure:'
                             + f' {cls.get_name()} cannot find pinCode with keyReference={cls.keyReference}')

    @classmethod
    def _read_all_pinvalues_from_pe(cls, pe: ProfileElement):
        "This is a separate function because subclasses may feed different pe arguments."
        for pinCodes in obtain_all_pe_from_pelist(pe, 'pinCodes'):
            if pinCodes.decoded['pinCodes'][0] != 'pinconfig':
                continue

            for pinCode in pinCodes.decoded['pinCodes'][1]:
                if pinCode['keyReference'] == cls.keyReference:
                     yield { cls.name: cls.decimal_hex_to_str(pinCode['pinValue']) }

    @classmethod
    def get_values_from_pes(cls, pes: ProfileElementSequence):
        yield from cls._read_all_pinvalues_from_pe(pes.pes_by_naa['mf'][0])

class Pin1(Pin):
    is_abstract = False
    name = 'PIN1'
    default_value = '0*4'  # PIN are usually 4 digits
    keyReference = 0x01

class Pin2(Pin1):
    is_abstract = False
    name = 'PIN2'
    keyReference = 0x81

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        val_bytes = val
        # PIN2 is special: telecom + usim + isim + csim
        for naa in pes.pes_by_naa:
            if naa not in ['usim','isim','csim','telecom']:
                continue
            for instance in pes.pes_by_naa[naa]:
                if not cls._apply_pinvalue(instance, cls.keyReference, val_bytes):
                    raise ValueError('input template UPP has unexpected structure:'
                            + f' {cls.get_name()} cannot find pinCode with keyReference={cls.keyReference} in {naa=}')

    @classmethod
    def get_values_from_pes(cls, pes: ProfileElementSequence):
        for naa in pes.pes_by_naa:
            if naa not in ['usim','isim','csim','telecom']:
                continue
            for pe in pes.pes_by_naa[naa]:
                yield from cls._read_all_pinvalues_from_pe(pe)

class Adm1(Pin):
    is_abstract = False
    name = 'ADM1'
    keyReference = 0x0A

class Adm2(Adm1):
    is_abstract = False
    name = 'ADM2'
    keyReference = 0x0B

class AlgoConfig(ConfigurableParameter):
    algo_config_key = None

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        found = 0
        for pe in pes.get_pes_for_type('akaParameter'):
            algoConfiguration = pe.decoded['algoConfiguration']
            if algoConfiguration[0] != 'algoParameter':
                continue
            algoConfiguration[1][cls.algo_config_key] = val
            found += 1
        if not found:
            raise ValueError('input template UPP has unexpected structure:'
                             f' {cls.__name__} cannot find algoParameter with key={cls.algo_config_key}')

    @classmethod
    def get_values_from_pes(cls, pes: ProfileElementSequence):
        for pe in pes.get_pes_for_type('akaParameter'):
            algoConfiguration = pe.decoded['algoConfiguration']
            if algoConfiguration[0] != 'algoParameter':
                continue
            val = algoConfiguration[1][cls.algo_config_key]
            if isinstance(val, bytes):
                val = b2h(val)
            # if it is an int (algorithmID), just pass thru as int
            yield { cls.name: val }

class AlgorithmID(EnumParam, AlgoConfig):
    '''use validate_val() from EnumParam, and apply_val() from AlgoConfig.
    In get_values_from_pes(), return enum value names, not raw values.'''
    is_abstract = False
    name = "Algorithm"

    # as in pySim/esim/asn1/saip/PE_Definitions-3.3.1.asn
    value_map = {
            "Milenage" : 1,
            "TUAK" : 2,
            "usim-test" : 3,
        }
    default_value = "Milenage"
    default_source = param_source.ConstantSource

    algo_config_key = 'algorithmID'

    # EnumParam.validate_val() returns the int values from value_map

    @classmethod
    def get_values_from_pes(cls, pes: ProfileElementSequence):
        # return enum names, not raw values.
        # use of super(): this intends to call AlgoConfig.get_values_from_pes() so that the cls argument is this cls
        # here (AlgorithmID); i.e. AlgoConfig.get_values_from_pes(pes) doesn't work, because AlgoConfig needs to look up
        # cls.algo_config_key.
        for d in super(cls, cls).get_values_from_pes(pes):
            if cls.name in d:
                # convert int to value string
                val = d[cls.name]
                d[cls.name] = cls.map_val_to_name(val, strict=True)
            yield d


class K(BinaryParam, AlgoConfig):
    """use validate_val() from BinaryParam, and apply_val() from AlgoConfig"""
    is_abstract = False
    name = 'K'
    algo_config_key = 'key'
    allow_len = int(128/8) # length in bytes (from BinaryParam)
    default_value = f'00*{allow_len}'
    default_source = param_source.RandomHexDigitSource

class Opc(K):
    name = 'OPc'
    algo_config_key = 'opc'


class BatchPersonalization:
    """Produce a series of eSIM profiles from predefined parameters.
    Personalization parameters are derived from pysim.esim.saip.param_source.ParamSource.

    Usage example:

    der_input = some_file.open('rb').read()
    pes = ProfileElementSequence.from_der(der_input)
    p = pers.BatchPersonalization(
        n=10,
        src_pes=pes,
        csv_rows=get_csv_reader())

    p.add_param_and_src(
        personalization.Iccid(),
        param_source.IncDigitSource(
            num_digits=18,
            first_value=123456789012340001,
            last_value=123456789012340010))

    # add more parameters here, using ConfigurableParameter and ParamSource subclass instances to define the profile
    # ...

    # generate all 10 profiles (from n=10 above)
    for result_pes in p.generate_profiles():
        upp = result_pes.to_der()
        store_upp(upp)
    """

    class ParamAndSrc:
        'tie a ConfigurableParameter to a source of actual values'
        def __init__(self, param:ConfigurableParameter, src:param_source.ParamSource):
            self.param = param
            self.src = src

    def __init__(self,
                 n:int,
                 src_pes:ProfileElementSequence,
                 params:list[ParamAndSrc]=None,
                 csv_rows:Generator=None,
                ):
        """
        n: number of eSIM profiles to generate.
        src_pes: a decoded eSIM profile as ProfileElementSequence, to serve as template. This is not modified, only
                 copied.
        params: list of ParamAndSrc instances, defining a ConfigurableParameter and corresponding ParamSource to fill in
                profile values.
        csv_rows: A list or generator producing all CSV rows one at a time, starting with a row containing the column
                  headers. This is compatible with the python csv.reader. Each row gets passed to
                  ParamSource.get_next(), such that ParamSource implementations can access the row items.
                  See param_source.CsvSource.
        """
        self.n = n
        self.params = params or []
        self.src_pes = src_pes
        self.csv_rows = csv_rows

    def add_param_and_src(self, param:ConfigurableParameter, src:param_source.ParamSource):
        self.params.append(BatchPersonalization.ParamAndSrc(param=param, src=src))

    def generate_profiles(self):
        # get first row of CSV: column names
        csv_columns = None
        if self.csv_rows:
            try:
                csv_columns = next(self.csv_rows)
            except StopIteration as e:
                raise ValueError('the input CSV file appears to be empty') from e

        for i in range(self.n):
            csv_row = None
            if self.csv_rows and csv_columns:
                try:
                    csv_row_list = next(self.csv_rows)
                except StopIteration as e:
                    raise ValueError(f'not enough rows in the input CSV for eSIM nr {i+1} of {self.n}') from e

                csv_row = dict(zip(csv_columns, csv_row_list))

            pes = copy.deepcopy(self.src_pes)

            for p in self.params:
                try:
                    input_value = p.src.get_next(csv_row=csv_row)
                    assert input_value is not None
                    value = p.param.__class__.validate_val(input_value)
                    p.param.__class__.apply_val(pes, value)
                except (
                        TypeError,
                        ValueError,
                        KeyError,
                       ) as e:
                    raise ValueError(f'{p.param.name} fed by {p.src.name}: {e}'
                                     f' (input_value={p.param.input_value!r} value={p.param.value!r})') from e

            yield pes


class UppAudit(dict):
    """
    Key-value pairs collected from a single UPP DER or PES.

    UppAudit itself is a dict, callers may use the standard python dict API to access key-value pairs read from the UPP.
    """

    @classmethod
    def from_der(cls, der: bytes, params: List, additional_sd_keys=False, der_size=False):
        '''return a dict of parameter name and set of selected parameter values found in a DER encoded profile. Note:
        some ConfigurableParameter implementations return more than one key-value pair, for example, Imsi returns
        both 'IMSI' and 'IMSI-ACC' parameters.

        e.g.
            UppAudit.from_der(my_der, [Imsi, ])
            --> {'IMSI': '001010000000023', 'IMSI-ACC': '5'}

        (where 'IMSI' == Imsi.name)

        Read all parameters listed in params. params is a list of either ConfigurableParameter classes or
        ConfigurableParameter class instances. This calls only classmethods, so each entry in params can either be the
        class itself, or a class-instance of, a (non-abstract) ConfigurableParameter subclass.
        For example, params = [Imsi, ] is equivalent to params = [Imsi(), ].

        For additional_sd_keys=True, output also all Security Domain KVN that there are *no* ConfigurableParameter
        subclasses for. For example, SCP80 has reserved kvn 0x01..0x0f, but we offer only Scp80Kvn01, Scp80Kvn02,
        Scp80Kvn03. So we would not show kvn 0x04..0x0f in an audit. additional_sd_keys=True includes audits of all SD
        key KVN there may be in the UPP. This helps to spot SD keys that may already be present in a UPP template, with
        unexpected / unusual kvn.

        For der_size=True, also include a {'der_size':12345} entry.
        '''

        # make an instance of this class
        upp_audit = cls()

        if der_size:
            upp_audit['der_size'] = set((len(der), ))

        pes = ProfileElementSequence.from_der(der)
        for param in params:
            try:
                for valdict in param.get_values_from_pes(pes):
                    upp_audit.add_values(valdict)
            except (TypeError, ValueError) as e:
                raise ValueError(f'Error during audit for parameter {key}: {e}') from e

        if not additional_sd_keys:
            return upp_audit

        # additional_sd_keys
        for pe in pes.pe_list:
            if pe.type != 'securityDomain':
                continue
            assert isinstance(pe, ProfileElementSD)

            for key in pe.keys:
                audit_key = f'SdKey_KVN{key.key_version_number:02x}_ID{key.key_identifier:02x}'
                audit_val = f'{key.key_components=!r} {key.key_usage_qualifier=!r}'
                upp_audit[audit_key] = audit_val
        return upp_audit

    def get_single_val(self, key, validate=True, allow_absent=False, absent_val=None):
        """
        Return the audit's value for the given audit key (like 'IMSI' or 'IMSI-ACC').
        Any kind of value may occur multiple times in a profile. When all of these agree to the same unambiguous value,
        return that value. When they do not agree, raise a ValueError.
        """
        # key should be a string, but if someone passes a ConfigurableParameter, just use its default name
        if ConfigurableParameter.is_super_of(key):
            key = key.get_name()

        assert isinstance(key, str)
        v = self.get(key)
        if v is None and allow_absent:
            return absent_val
        if not isinstance(v, set):
            raise ValueError(f'audit value should be a set(), got {v!r}')
        if len(v) != 1:
            raise ValueError(f'expected a single value for {key}, got {v!r}')
        v = tuple(v)[0]
        return v

    @staticmethod
    def audit_val_to_str(v):
        """
        Usually, we want to see a single value in an audit. Still, to be able to collect multiple ambiguous values,
        audit values are always python sets. Turn it into a nice string representation: only the value when it is
        unambiguous, otherwise a list of the ambiguous values.
        A value may also be completely absent, then return 'not present'.
        """
        def try_single_val(w):
            'change single-entry sets to just the single value'
            if isinstance(w, set):
                if len(w) == 1:
                    return tuple(w)[0]
                if len(w) == 0:
                    return None
            return w

        v = try_single_val(v)
        if isinstance(v, bytes):
            v = bytes_to_hexstr(v)
        if v is None:
            return 'not present'
        return str(v)

    def get_val_str(self, key):
        """Return a string of the value stored for the given key"""
        return UppAudit.audit_val_to_str(self.get(key))

    def add_values(self, src:dict):
        """self and src are both a dict of sets.
        For example from
            self == { 'a': set((123,)) }
        and
            src == { 'a': set((456,)), 'b': set((789,)) }
        then after this function call:
            self == { 'a': set((123, 456,)), 'b': set((789,)) }
        """
        assert isinstance(src, dict)
        for key, srcvalset in src.items():
            dstvalset = self.get(key)
            if dstvalset is None:
                dstvalset = set()
                self[key] = dstvalset
            dstvalset.add(srcvalset)

    def __str__(self):
        return '\n'.join(f'{key}: {self.get_val_str(key)}' for key in sorted(self.keys()))

class BatchAudit(list):
    """
    Collect UppAudit instances for a batch of UPP, for example from a personalization.BatchPersonalization.
    Produce an output CSV.

    Usage example:

        ba = BatchAudit(params=(personalization.Iccid, ))
        for upp_der in upps:
            ba.add_audit(upp_der)
        print(ba.summarize())

        with open('output.csv', 'wb') as csv_data:
            csv_str = io.TextIOWrapper(csv_data, 'utf-8', newline='')
            csv.writer(csv_str).writerows( ba.to_csv_rows() )
            csv_str.flush()

    BatchAudit itself is a list, callers may use the standard python list API to access the UppAudit instances.
    """

    def __init__(self, params:List=None):
        if params is None:
            params = ConfigurableParameter.get_all_implementations()
        self.params = params

    def add_audit(self, upp_der:bytes):
        audit = UppAudit.from_der(upp_der, self.params)
        self.append(audit)
        return audit

    def summarize(self):
        batch_audit = UppAudit()

        audits = self

        if len(audits) > 2:
            val_sep = ', ..., '
        else:
            val_sep = ', '

        first_audit = None
        last_audit = None
        if len(audits) >= 1:
            first_audit = audits[0]
        if len(audits) >= 2:
            last_audit = audits[-1]

        if first_audit:
            if last_audit:
                for key in first_audit.keys():
                    first_val = first_audit.get_val_str(key)
                    last_val = last_audit.get_val_str(key)

                    if first_val == last_val:
                        val = first_val
                    else:
                        val_sep_with_newline = f"{val_sep.rstrip()}\n{' ' * (len(key) + 2)}"
                        val = val_sep_with_newline.join((first_val, last_val))
                    batch_audit[key] = val
            else:
                batch_audit.update(first_audit)

        return batch_audit

    def to_csv_rows(self, headers=True, sort_key=None):
        '''generator that yields all audits' values as rows, useful feed to a csv.writer.'''
        columns = set()
        for audit in self:
            columns.update(audit.keys())

        columns = tuple(sorted(columns, key=sort_key))

        if headers:
            yield columns

        for audit in self:
            yield (audit.get_single_val(col, allow_absent=True, absent_val="") for col in columns)

def bytes_to_hexstr(b:bytes, sep=''):
    return sep.join(f'{x:02x}' for x in b)

def esim_profile_introspect(upp):
    pes = ProfileElementSequence.from_der(upp.read())
    d = {}
    d['upp'] = repr(pes)

    def show_bytes_as_hexdump(item):
        if isinstance(item, bytes):
            return bytes_to_hexstr(item)
        if isinstance(item, list):
            return list(show_bytes_as_hexdump(i) for i in item)
        if isinstance(item, tuple):
            return tuple(show_bytes_as_hexdump(i) for i in item)
        if isinstance(item, dict):
            d = {}
            for k, v in item.items():
                d[k] = show_bytes_as_hexdump(v)
            return d
        return item

    l = list((pe.type, show_bytes_as_hexdump(pe.decoded)) for pe in pes)
    d['pp'] = pprint.pformat(l, width=120)
    return d
