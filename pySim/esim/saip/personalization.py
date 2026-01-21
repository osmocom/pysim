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
import re
import pprint
from typing import List, Tuple, Generator, Optional

from osmocom.tlv import camel_to_snake
from osmocom.utils import hexstr
from pySim.utils import enc_iccid, dec_iccid, enc_imsi, dec_imsi, h2b, b2h, rpad, sanitize_iccid
from pySim.ts_51_011 import EF_SMSP
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

class ClassVarMeta(abc.ABCMeta):
    """Metaclass that puts all additional keyword-args into the class. We use this to have one
    class definition for something like a PIN, and then have derived classes for PIN1, PIN2, ..."""
    def __new__(metacls, name, bases, namespace, **kwargs):
        #print("Meta_new_(metacls=%s, name=%s, bases=%s, namespace=%s, kwargs=%s)" % (metacls, name, bases, namespace, kwargs))
        x = super().__new__(metacls, name, bases, namespace)
        for k, v in kwargs.items():
            setattr(x, k, v)
        return x

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

class ConfigurableParameter(abc.ABC, metaclass=ClassVarMeta):
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

    1) use a ConfigurableParameter instance, with .input_value and .value state::

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

    2) use a ConfigurableParameter class, without state::

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
    example_input = None
    default_source = None # a param_source.ParamSource subclass

    def __init__(self, input_value=None):
        self.input_value = input_value # the raw input value as given by caller
        self.value = None # the processed input value (e.g. with check digit) as produced by validate()

        # if there is no explicit name string set, use the class name
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
    @abc.abstractmethod
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

class IntegerParam(ConfigurableParameter):
    allow_types = (str, int)
    allow_chars = '0123456789'

    # two integers, if the resulting int should be range limited
    min_val = None
    max_val = None

    @classmethod
    def validate_val(cls, val):
        val = super().validate_val(val)
        val = int(val)
        exceeds_limits = False
        if cls.min_val is not None:
            if val < cls.min_val:
                exceeds_limits = True
        if cls.max_val is not None:
            if val > cls.max_val:
                exceeds_limits = True
        if exceeds_limits:
            raise ValueError(f'Value {val} is out of range, must be [{cls.min_val}..{cls.max_val}]')
        return val

    @classmethod
    def get_values_from_pes(cls, pes: ProfileElementSequence):
        for valdict in super().get_values_from_pes(pes):
            for key, val in valdict.items():
                if isinstance(val, int):
                    valdict[key] = str(val)
            yield valdict

class BinaryParam(ConfigurableParameter):
    allow_types = (str, io.BytesIO, bytes, bytearray, int)
    allow_chars = '0123456789abcdefABCDEF'
    strip_chars = ' \t\r\n'
    default_source = param_source.RandomHexDigitSource

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
    name = 'ICCID'
    min_len = 18
    max_len = 20
    example_input = '998877665544332211'
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
            iccid_f = pe.files.get('ef-iccid', None)
            if iccid_f is not None:
                yield { cls.name: dec_iccid(b2h(iccid_f.body)) }

class Imsi(DecimalParam):
    """Configurable IMSI. Expects value to be a string of digits. Automatically sets the ACC to
    the last digit of the IMSI."""

    name = 'IMSI'
    min_len = 6
    max_len = 15
    example_input = '00101' + ('0' * 10)
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
            imsi_f = pe.files.get('ef-imsi', None)
            acc_f = pe.files.get('ef-acc', None)
            y = {}
            if imsi_f:
                y[cls.name] = dec_imsi(b2h(imsi_f.body))
            if acc_f:
                y[cls.name + '-ACC'] = b2h(acc_f.body)
            yield y

class SmspTpScAddr(ConfigurableParameter):
    """Configurable SMSC (SMS Service Centre) TP-SC-ADDR. Expects to be a phone number in national or
    international format (designated by a leading +). Automatically sets the NPI to E.164 and the TON based on
    presence or absence of leading +."""

    name = 'SMSP-TP-SC-ADDR'
    allow_chars = '+0123456789'
    strip_chars = ' \t\r\n'
    max_len = 21 # '+' and 20 digits
    min_len = 1
    example_input = '+49301234567'
    default_source = param_source.ConstantSource

    @classmethod
    def validate_val(cls, val):
        val = super().validate_val(val)
        addr_str = str(val)
        if addr_str[0] == '+':
            digits = addr_str[1:]
            international = True
        else:
            digits = addr_str
            international = False
        if len(digits) > 20:
            raise ValueError(f'TP-SC-ADDR must not exceed 20 digits: {digits!r}')
        if not digits.isdecimal():
            raise ValueError(f'TP-SC-ADDR must only contain decimal digits: {digits!r}')
        return (international, digits)

    @classmethod
    def apply_val(cls, pes: ProfileElementSequence, val):
        """val must be a tuple (international[bool], digits[str]).
        For example, an input of "+1234" corresponds to (True, "1234");
        An input of "1234" corresponds to (False, "1234")."""
        international, digits = val
        for pe in pes.get_pes_for_type('usim'):
            # obtain the File instance from the ProfileElementUSIM
            f_smsp = pe.files['ef-smsp']
            #print("SMSP (orig): %s" % f_smsp.body)
            # instantiate the pySim.ts_51_011.EF_SMSP class for decode/encode
            ef_smsp = EF_SMSP()
            # decode the existing file body
            ef_smsp_dec = ef_smsp.decode_record_bin(f_smsp.body, 1)
            # patch the actual number
            ef_smsp_dec['tp_sc_addr']['call_number'] = digits
            # patch the NPI to isdn_e164
            ef_smsp_dec['tp_sc_addr']['ton_npi']['numbering_plan_id'] = 'isdn_e164'
            # patch the TON to international or unknown depending on +
            ef_smsp_dec['tp_sc_addr']['ton_npi']['type_of_number'] = 'international' if international else 'unknown'
            # ensure the parameter_indicators.tp_sc_addr is True
            ef_smsp_dec['parameter_indicators']['tp_sc_addr'] = True
            # re-encode into the File body
            f_smsp.body = ef_smsp.encode_record_bin(ef_smsp_dec, 1)
            #print("SMSP  (new): %s" % f_smsp.body)
            # re-generate the pe.decoded member from the File instance
            pe.file2pe(f_smsp)

    @classmethod
    def get_values_from_pes(cls, pes: ProfileElementSequence):
        for pe in pes.get_pes_for_type('usim'):
            f_smsp = pe.files.get('ef-smsp', None)
            if f_smsp is None:
                continue

            try:
                ef_smsp = EF_SMSP()
                ef_smsp_dec = ef_smsp.decode_record_bin(f_smsp.body, 1)
            except IndexError:
                continue

            tp_sc_addr = ef_smsp_dec.get('tp_sc_addr', None)
            if not tp_sc_addr:
                continue

            digits = tp_sc_addr.get('call_number', None)
            if not digits:
                continue

            ton_npi = tp_sc_addr.get('ton_npi', None)
            if not ton_npi:
                continue
            international = ton_npi.get('type_of_number', None)
            if international is None:
                continue
            international = (international == 'international')

            yield (international, digits)


class SdKey(BinaryParam):
    """Configurable Security Domain (SD) Key.  Value is presented as bytes.
       Non-abstract implementations are generated in SdKey.generate_sd_key_classes"""
    # these will be set by subclasses
    key_type = None
    kvn = None
    reserved_kvn = tuple() # tuple of all reserved kvn for a given SCPxx
    key_id = None
    key_usage_qual = None

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


    NO_OP = (('', {}))

    LEN_128 = (16,)
    LEN_128_192_256 = (16, 24, 32)
    LEN_128_256 = (16, 32)

    DES =    ('DES', dict(key_type=KeyType.des, allow_len=LEN_128) )
    AES =    ('AES', dict(key_type=KeyType.aes, allow_len=LEN_128_192_256) )

    ENC =    ('ENC', dict(key_id=0x01, key_usage_qual=0x18) )
    MAC =    ('MAC', dict(key_id=0x02, key_usage_qual=0x14) )
    DEK =    ('DEK', dict(key_id=0x03, key_usage_qual=0x48) )

    TLSPSK_PSK = ('TLSPSK', dict(key_type=KeyType.tls_psk, key_id=0x01, key_usage_qual=0x3c, allow_len=LEN_128_192_256) )
    TLSPSK_DEK = ('DEK',    dict(key_type=KeyType.des, key_id=0x02, key_usage_qual=0x48, allow_len=LEN_128) )

    # THIS IS THE LIST that controls which SdKeyXxx subclasses exist:
    SD_KEY_DEFS = (
        # name    KVN                     x variants            x variants
        ('SCP02', (0x20, 0x21, 0x22, 0xff), (AES, ),              (ENC, MAC, DEK) ),
        ('SCP03', (0x30, 0x31, 0x32),       (AES, ),              (ENC, MAC, DEK) ),
        ('SCP80', (0x01, 0x02, 0x03),       (DES, AES),           (ENC, MAC, DEK) ),
        ('SCP81', (0x40, 0x41, 0x42),       (TLSPSK_PSK, TLSPSK_DEK, ), ),
    )

    all_implementations = None

    @classmethod
    def generate_sd_key_classes(cls, sd_key_defs=SD_KEY_DEFS):
        '''This generates python classes to be exported in this module, as subclasses of class SdKey.

        We create SdKey subclasses dynamically from a list.
        You can list all of them via:
          from pySim.esim.saip.personalization import SdKey
          SdKey.all_implementations
        or
          print('\n'.join(sorted(f'{x.__name__}\t{x.name}' for x in SdKey.all_implementations)))

        at time of writing this comment, this prints:

        SdKeyScp02Kvn20AesDek SCP02-KVN20-AES-DEK
        SdKeyScp02Kvn20AesEnc SCP02-KVN20-AES-ENC
        SdKeyScp02Kvn20AesMac SCP02-KVN20-AES-MAC
        SdKeyScp02Kvn21AesDek SCP02-KVN21-AES-DEK
        SdKeyScp02Kvn21AesEnc SCP02-KVN21-AES-ENC
        SdKeyScp02Kvn21AesMac SCP02-KVN21-AES-MAC
        SdKeyScp02Kvn22AesDek SCP02-KVN22-AES-DEK
        SdKeyScp02Kvn22AesEnc SCP02-KVN22-AES-ENC
        SdKeyScp02Kvn22AesMac SCP02-KVN22-AES-MAC
        SdKeyScp02KvnffAesDek SCP02-KVNff-AES-DEK
        SdKeyScp02KvnffAesEnc SCP02-KVNff-AES-ENC
        SdKeyScp02KvnffAesMac SCP02-KVNff-AES-MAC
        SdKeyScp03Kvn30AesDek SCP03-KVN30-AES-DEK
        SdKeyScp03Kvn30AesEnc SCP03-KVN30-AES-ENC
        SdKeyScp03Kvn30AesMac SCP03-KVN30-AES-MAC
        SdKeyScp03Kvn31AesDek SCP03-KVN31-AES-DEK
        SdKeyScp03Kvn31AesEnc SCP03-KVN31-AES-ENC
        SdKeyScp03Kvn31AesMac SCP03-KVN31-AES-MAC
        SdKeyScp03Kvn32AesDek SCP03-KVN32-AES-DEK
        SdKeyScp03Kvn32AesEnc SCP03-KVN32-AES-ENC
        SdKeyScp03Kvn32AesMac SCP03-KVN32-AES-MAC
        SdKeyScp80Kvn01AesDek SCP80-KVN01-AES-DEK
        SdKeyScp80Kvn01AesEnc SCP80-KVN01-AES-ENC
        SdKeyScp80Kvn01AesMac SCP80-KVN01-AES-MAC
        SdKeyScp80Kvn01DesDek SCP80-KVN01-DES-DEK
        SdKeyScp80Kvn01DesEnc SCP80-KVN01-DES-ENC
        SdKeyScp80Kvn01DesMac SCP80-KVN01-DES-MAC
        SdKeyScp80Kvn02AesDek SCP80-KVN02-AES-DEK
        SdKeyScp80Kvn02AesEnc SCP80-KVN02-AES-ENC
        SdKeyScp80Kvn02AesMac SCP80-KVN02-AES-MAC
        SdKeyScp80Kvn02DesDek SCP80-KVN02-DES-DEK
        SdKeyScp80Kvn02DesEnc SCP80-KVN02-DES-ENC
        SdKeyScp80Kvn02DesMac SCP80-KVN02-DES-MAC
        SdKeyScp80Kvn03AesDek SCP80-KVN03-AES-DEK
        SdKeyScp80Kvn03AesEnc SCP80-KVN03-AES-ENC
        SdKeyScp80Kvn03AesMac SCP80-KVN03-AES-MAC
        SdKeyScp80Kvn03DesDek SCP80-KVN03-DES-DEK
        SdKeyScp80Kvn03DesEnc SCP80-KVN03-DES-ENC
        SdKeyScp80Kvn03DesMac SCP80-KVN03-DES-MAC
        SdKeyScp81Kvn40Dek    SCP81-KVN40-DEK
        SdKeyScp81Kvn40Tlspsk SCP81-KVN40-TLSPSK
        SdKeyScp81Kvn41Dek    SCP81-KVN41-DEK
        SdKeyScp81Kvn41Tlspsk SCP81-KVN41-TLSPSK
        SdKeyScp81Kvn42Dek    SCP81-KVN42-DEK
        SdKeyScp81Kvn42Tlspsk SCP81-KVN42-TLSPSK
        '''

        SdKey.all_implementations = []

        transitional_name_mapping = {
            'SCP02-KVN20-AES-DEK': 'SCP02-20-AES-DEK',
            'SCP02-KVN20-AES-ENC': 'SCP02-20-AES-ENC',
            'SCP02-KVN20-AES-MAC': 'SCP02-20-AES-MAC',
            'SCP02-KVN21-AES-DEK': 'SCP02-21-AES-DEK',
            'SCP02-KVN21-AES-ENC': 'SCP02-21-AES-ENC',
            'SCP02-KVN21-AES-MAC': 'SCP02-21-AES-MAC',
            'SCP02-KVN22-AES-DEK': 'SCP02-22-AES-DEK',
            'SCP02-KVN22-AES-ENC': 'SCP02-22-AES-ENC',
            'SCP02-KVN22-AES-MAC': 'SCP02-22-AES-MAC',
            'SCP02-KVNff-AES-DEK': 'SCP02-ff-AES-DEK',
            'SCP02-KVNff-AES-ENC': 'SCP02-ff-AES-ENC',
            'SCP02-KVNff-AES-MAC': 'SCP02-ff-AES-MAC',
            'SCP03-KVN30-AES-DEK': 'SCP03-30-AES-DEK',
            'SCP03-KVN30-AES-ENC': 'SCP03-30-AES-ENC',
            'SCP03-KVN30-AES-MAC': 'SCP03-30-AES-MAC',
            'SCP03-KVN31-AES-DEK': 'SCP03-31-AES-DEK',
            'SCP03-KVN31-AES-ENC': 'SCP03-31-AES-ENC',
            'SCP03-KVN31-AES-MAC': 'SCP03-31-AES-MAC',
            'SCP03-KVN32-AES-DEK': 'SCP03-32-AES-DEK',
            'SCP03-KVN32-AES-ENC': 'SCP03-32-AES-ENC',
            'SCP03-KVN32-AES-MAC': 'SCP03-32-AES-MAC',
        }

        def camel(s):
            return s[:1].upper() + s[1:].lower()

        def do_variants(name, kvn, remaining_variants, labels=[], attrs={}):
            'recurse to unfold as many variants as there may be'
            if remaining_variants:
                # not a leaf node, collect more labels and attrs
                variants = remaining_variants[0]
                remaining_variants = remaining_variants[1:]

                for label, valdict in variants:
                    # pass copies to recursion
                    inner_labels = list(labels)
                    inner_attrs = dict(attrs)

                    inner_labels.append(label)
                    inner_attrs.update(valdict)
                    do_variants(name, kvn, remaining_variants,
                                labels=inner_labels,
                                attrs=inner_attrs)
                return

            # leaf node. create a new class with all the accumulated vals
            parts = [name, f'KVN{kvn:02x}',] + labels
            cls_label = '-'.join(p for p in parts if p)

            parts = ['Sd', 'Key', name, f'Kvn{kvn:02x}'] + labels
            clsname = ''.join(camel(p) for p in parts)

            max_key_len = attrs.get('allow_len')[-1]

            cls_label = transitional_name_mapping.get(cls_label, cls_label)

            attrs.update({
                'name' : cls_label,
                'kvn': kvn,
                'example_input': f'00*{max_key_len}',
                })

            # below line is like
            # class SdKeyScpNNKvnXXYyyZzz(SdKey):
            #     <set attrs>
            cls_def = type(clsname, (cls,), attrs)

            # for some unknown reason, subclassing from abc.ABC makes cls_def.__module__ == 'abc',
            # but we don't want 'abc.SdKeyScp03Kvn32AesEnc'.
            # Make sure it is 'pySim.esim.saip.personalization.SdKeyScp03Kvn32AesEnc'
            cls_def.__module__ = __name__

            globals()[clsname] = cls_def
            SdKey.all_implementations.append(cls_def)


        for items in sd_key_defs:
            name, kvns = items[:2]
            variants = items[2:]
            for kvn in kvns:
                do_variants(name, kvn, variants)

# this creates all of the classes named like SdKeyScp02Kvn20AesDek to be published in this python module:
SdKey.generate_sd_key_classes()

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
    example_input = f'0*{allow_len}'
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
    example_input = f'0*{max_len}'
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
    name = 'PIN1'
    example_input = '0*4'  # PIN are usually 4 digits
    keyReference = 0x01

class Pin2(Pin1):
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
    name = 'ADM1'
    keyReference = 0x0A

class Adm2(Adm1):
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
            if len(algoConfiguration) < 2:
                continue
            if algoConfiguration[0] != 'algoParameter':
                continue
            if not algoConfiguration[1]:
                continue
            val = algoConfiguration[1].get(cls.algo_config_key, None)
            if val is None:
                continue
            if isinstance(val, bytes):
                val = b2h(val)
            # if it is an int (algorithmID), just pass thru as int
            yield { cls.name: val }

class AlgorithmID(EnumParam, AlgoConfig):
    '''use validate_val() from EnumParam, and apply_val() from AlgoConfig.
    In get_values_from_pes(), return enum value names, not raw values.'''
    name = "Algorithm"

    # as in pySim/esim/asn1/saip/PE_Definitions-3.3.1.asn
    value_map = {
            "Milenage" : 1,
            "TUAK" : 2,
            "usim-test" : 3,
        }
    example_input = "Milenage"
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
    name = 'K'
    algo_config_key = 'key'
    allow_len = (128 // 8, 256 // 8) # length in bytes (from BinaryParam); TUAK also allows 256 bit
    example_input = f'00*{allow_len[0]}'

class Opc(K):
    name = 'OPc'
    algo_config_key = 'opc'

class MilenageRotationConstants(BinaryParam, AlgoConfig):
    """rotation constants r1,r2,r3,r4,r5 of Milenage, Range 0..127. See 3GPP TS 35.206 Sections 2.3 + 5.3.
    Provided as octet-string concatenation of all 5 constants.  Expects a bytes-like object of length 5, with
    each byte in the range of 0..127.  The default value by 3GPP is '4000204060' (hex notation)"""
    name = 'MilenageRotation'
    algo_config_key = 'rotationConstants'
    allow_len = 5 # length in bytes (from BinaryParam)
    example_input = '40 00 20 40 60'
    default_source = param_source.ConstantSource

    @classmethod
    def validate_val(cls, val):
        "allow_len checks the length, this in addition checks the value range"
        val = super().validate_val(val)
        assert isinstance(val, bytes)
        if any(r > 127 for r in val):
            raise ValueError('r values must be in the range 0..127')
        return val

class MilenageXoringConstants(BinaryParam, AlgoConfig):
    """XOR-ing constants c1,c2,c3,c4,c5 of Milenage, 128bit each. See 3GPP TS 35.206 Sections 2.3 + 5.3.
    Provided as octet-string concatenation of all 5 constants. The default value by 3GPP is the concetenation
    of::

     00000000000000000000000000000000
     00000000000000000000000000000001
     00000000000000000000000000000002
     00000000000000000000000000000004
     00000000000000000000000000000008

    """
    name = 'MilenageXOR'
    algo_config_key = 'xoringConstants'
    allow_len = 80 # length in bytes (from BinaryParam)
    example_input = ('00000000000000000000000000000000'
                     ' 00000000000000000000000000000001'
                     ' 00000000000000000000000000000002'
                     ' 00000000000000000000000000000004'
                     ' 00000000000000000000000000000008')
    default_source = param_source.ConstantSource

class TuakNumberOfKeccak(IntegerParam, AlgoConfig):
    """Number of iterations of Keccak-f[1600] permutation as recomended by Section 7.2 of 3GPP TS 35.231"""
    name = 'KECCAK-N'
    algo_config_key = 'numberOfKeccak'
    min_val = 1
    max_val = 255
    example_input = '1'
    default_source = param_source.ConstantSource
