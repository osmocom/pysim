# -*- coding: utf-8 -*-

""" pySim: various utilities
"""

import json
import abc
import string
import datetime
import argparse
from io import BytesIO
from typing import Optional, List, Dict, Any, Tuple, NewType, Union
from osmocom.utils import *
from osmocom.tlv import bertlv_encode_tag, bertlv_encode_len

# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2021 Harald Welte <laforge@osmocom.org>
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
#

# IMSI encoded format:
# For IMSI 0123456789ABCDE:
#
# |     byte 1      | 2 upper | 2 lower  | 3 upper | 3 lower | ... | 9 upper | 9 lower |
# | length in bytes |    0    | odd/even |    2    |    1    | ... |    E    |    D    |
#
# If the IMSI is less than 15 characters, it should be padded with 'f' from the end.
#
# The length is the total number of bytes used to encoded the IMSI. This includes the odd/even
# parity bit. E.g. an IMSI of length 14 is 8 bytes long, not 7, as it uses bytes 2 to 9 to
# encode itself.
#
# Because of this, an odd length IMSI fits exactly into len(imsi) + 1 // 2 bytes, whereas an
# even length IMSI only uses half of the last byte.

SwHexstr = NewType('SwHexstr', str)
SwMatchstr = NewType('SwMatchstr', str)
ResTuple = Tuple[Hexstr, SwHexstr]

def enc_imsi(imsi: str):
    """Converts a string IMSI into the encoded value of the EF"""
    l = half_round_up(
        len(imsi) + 1)  # Required bytes - include space for odd/even indicator
    oe = len(imsi) & 1			# Odd (1) / Even (0)
    ei = '%02x' % l + swap_nibbles('%01x%s' % ((oe << 3) | 1, rpad(imsi, 15)))
    return ei


def dec_imsi(ef: Hexstr) -> Optional[str]:
    """Converts an EF value to the IMSI string representation"""
    if len(ef) < 4:
        return None
    l = int(ef[0:2], 16) * 2		# Length of the IMSI string
    l = l - 1						# Encoded length byte includes oe nibble
    swapped = swap_nibbles(ef[2:]).rstrip('f')
    if len(swapped) < 1:
        return None
    oe = (int(swapped[0]) >> 3) & 1  # Odd (1) / Even (0)
    if not oe:
        # if even, only half of last byte was used
        l = l-1
    if l != len(swapped) - 1:
        return None
    imsi = swapped[1:]
    return imsi


def dec_iccid(ef: Hexstr) -> str:
    return swap_nibbles(ef).strip('f')


def enc_iccid(iccid: str) -> Hexstr:
    return swap_nibbles(rpad(iccid, 20))

def sanitize_iccid(iccid: Union[int, str]) -> str:
    iccid = str(iccid)
    if len(iccid) < 18:
        raise ValueError('ICCID input value must be at least 18 digits')
    if len(iccid) > 20:
        raise ValueError('ICCID input value must be at most 20 digits')
    if len(iccid) == 18:
        # 18 digits means we must add a luhn check digit to reach 19 digits
        iccid += str(calculate_luhn(iccid))
    if len(iccid) == 20:
        # 20 digits means we're actually exceeding E.118 by one digit, and
        # the luhn check digit must already be included
        verify_luhn(iccid)
    if len(iccid) == 19:
        # 19 digits means that it's either an in-spec 19-digits ICCID with
        # its luhn check digit already present, or it's an out-of-spec 20-digit
        # ICCID without that check digit...
        try:
            verify_luhn(iccid)
        except ValueError:
            # 19th digit was not luhn check digit; we must add it
            iccid += str(calculate_luhn(iccid))
    return iccid


def enc_plmn(mcc: Hexstr, mnc: Hexstr) -> Hexstr:
    """Converts integer MCC/MNC into 3 bytes for EF"""

    # Make sure there are no excess whitespaces in the input
    # parameters
    mcc = mcc.strip()
    mnc = mnc.strip()

    # Make sure that MCC/MNC are correctly padded with leading
    # zeros or 'F', depending on the length.
    if len(mnc) == 0:
        mnc = "FFF"
    elif len(mnc) == 1:
        mnc = "0" + mnc + "F"
    elif len(mnc) == 2:
        mnc += "F"

    if len(mcc) == 0:
        mcc = "FFF"
    elif len(mcc) == 1:
        mcc = "00" + mcc
    elif len(mcc) == 2:
        mcc = "0" + mcc

    return (mcc[1] + mcc[0]) + (mnc[2] + mcc[2]) + (mnc[1] + mnc[0])


def dec_plmn(threehexbytes: Hexstr) -> dict:
    res = {'mcc': "0", 'mnc': "0"}
    dec_mcc_from_plmn_str(threehexbytes)
    res['mcc'] = dec_mcc_from_plmn_str(threehexbytes)
    res['mnc'] = dec_mnc_from_plmn_str(threehexbytes)
    return res


# Accepts hex string representing three bytes


def dec_mcc_from_plmn(plmn: Hexstr) -> int:
    ia = h2i(plmn)
    digit1 = ia[0] & 0x0F		# 1st byte, LSB
    digit2 = (ia[0] & 0xF0) >> 4  # 1st byte, MSB
    digit3 = ia[1] & 0x0F		# 2nd byte, LSB
    if digit3 == 0xF and digit2 == 0xF and digit1 == 0xF:
        return 0xFFF  # 4095
    return derive_mcc(digit1, digit2, digit3)


def dec_mcc_from_plmn_str(plmn: Hexstr) -> str:
    digit1 = plmn[1]  # 1st byte, LSB
    digit2 = plmn[0]  # 1st byte, MSB
    digit3 = plmn[3]  # 2nd byte, LSB
    res = digit1 + digit2 + digit3
    return res.upper().strip("F")


def dec_mnc_from_plmn(plmn: Hexstr) -> int:
    ia = h2i(plmn)
    digit1 = ia[2] & 0x0F		# 3rd byte, LSB
    digit2 = (ia[2] & 0xF0) >> 4  # 3rd byte, MSB
    digit3 = (ia[1] & 0xF0) >> 4  # 2nd byte, MSB
    if digit3 == 0xF and digit2 == 0xF and digit1 == 0xF:
        return 0xFFF  # 4095
    return derive_mnc(digit1, digit2, digit3)


def dec_mnc_from_plmn_str(plmn: Hexstr) -> str:
    digit1 = plmn[5]  # 3rd byte, LSB
    digit2 = plmn[4]  # 3rd byte, MSB
    digit3 = plmn[2]  # 2nd byte, MSB
    res = digit1 + digit2 + digit3
    return res.upper().strip("F")


def dec_act(twohexbytes: Hexstr) -> List[str]:
    act_list = [
        {'bit': 15, 'name': "UTRAN"},
        {'bit': 11, 'name': "NG-RAN"},
        {'bit':  6, 'name': "GSM COMPACT"},
        {'bit':  5, 'name': "cdma2000 HRPD"},
        {'bit':  4, 'name': "cdma2000 1xRTT"},
    ]
    ia = h2i(twohexbytes)
    u16t = (ia[0] << 8) | ia[1]
    sel = set()
    # only the simple single-bit ones
    for a in act_list:
        if u16t & (1 << a['bit']):
            sel.add(a['name'])
    # TS 31.102 Section 4.2.5 Table 4.2.5.1
    eutran_bits = u16t & 0x7000
    if eutran_bits in [0x4000, 0x7000]:
        sel.add("E-UTRAN WB-S1")
        sel.add("E-UTRAN NB-S1")
    elif eutran_bits == 0x5000:
        sel.add("E-UTRAN NB-S1")
    elif eutran_bits == 0x6000:
        sel.add("E-UTRAN WB-S1")
    # TS 31.102 Section 4.2.5 Table 4.2.5.2
    gsm_bits = u16t & 0x008C
    if gsm_bits in [0x0080, 0x008C]:
        sel.add("GSM")
        sel.add("EC-GSM-IoT")
    elif u16t & 0x008C == 0x0084:
        sel.add("GSM")
    elif u16t & 0x008C == 0x0086:
        sel.add("EC-GSM-IoT")
    return sorted(list(sel))


def dec_xplmn_w_act(fivehexbytes: Hexstr) -> Dict[str, Any]:
    res = {'mcc': "0", 'mnc': "0", 'act': []}
    plmn_chars = 6
    act_chars = 4
    # first three bytes (six ascii hex chars)
    plmn_str = fivehexbytes[:plmn_chars]
    # two bytes after first three bytes
    act_str = fivehexbytes[plmn_chars:plmn_chars + act_chars]
    res['mcc'] = dec_mcc_from_plmn_str(plmn_str)
    res['mnc'] = dec_mnc_from_plmn_str(plmn_str)
    res['act'] = dec_act(act_str)
    return res


def dec_xplmn(threehexbytes: Hexstr) -> dict:
    res = {'mcc': 0, 'mnc': 0, 'act': []}
    plmn_chars = 6
    # first three bytes (six ascii hex chars)
    plmn_str = threehexbytes[:plmn_chars]
    res['mcc'] = dec_mcc_from_plmn_str(plmn_str)
    res['mnc'] = dec_mnc_from_plmn_str(plmn_str)
    return res


def derive_milenage_opc(ki_hex: Hexstr, op_hex: Hexstr) -> Hexstr:
    """
    Run the milenage algorithm to calculate OPC from Ki and OP
    """
    from Cryptodome.Cipher import AES
    # pylint: disable=no-name-in-module
    from Cryptodome.Util.strxor import strxor

    # We pass in hex string and now need to work on bytes
    ki_bytes = bytes(h2b(ki_hex))
    op_bytes = bytes(h2b(op_hex))
    aes = AES.new(ki_bytes, AES.MODE_ECB)
    opc_bytes = aes.encrypt(op_bytes)
    return b2h(strxor(opc_bytes, op_bytes))


def calculate_luhn(cc) -> int:
    """
    Calculate Luhn checksum used in e.g. ICCID and IMEI
    """
    num = list(map(int, str(cc)))
    check_digit = 10 - sum(num[-2::-2] + [sum(divmod(d * 2, 10))
                           for d in num[::-2]]) % 10
    return 0 if check_digit == 10 else check_digit

def verify_luhn(digits: str):
    """Verify the Luhn check digit; raises ValueError if it is incorrect."""
    cd = calculate_luhn(digits[:-1])
    if str(cd) != digits[-1]:
        raise ValueError('Luhn check digit mismatch: should be %s but is %s' % (str(cd), digits[-1]))

def mcc_from_imsi(imsi: str) -> Optional[str]:
    """
    Derive the MCC (Mobile Country Code) from the first three digits of an IMSI
    """
    if imsi is None:
        return None

    if len(imsi) > 3:
        return imsi[:3]
    else:
        return None


def mnc_from_imsi(imsi: str, long: bool = False) -> Optional[str]:
    """
    Derive the MNC (Mobile Country Code) from the 4th to 6th digit of an IMSI
    """
    if imsi is None:
        return None

    if len(imsi) > 3:
        if long:
            return imsi[3:6]
        else:
            return imsi[3:5]
    else:
        return None


def derive_mcc(digit1: int, digit2: int, digit3: int) -> int:
    """
    Derive decimal representation of the MCC (Mobile Country Code)
    from three given digits.
    """

    mcc = 0

    if digit1 != 0x0f:
        mcc += digit1 * 100
    if digit2 != 0x0f:
        mcc += digit2 * 10
    if digit3 != 0x0f:
        mcc += digit3

    return mcc


def derive_mnc(digit1: int, digit2: int, digit3: int = 0x0f) -> int:
    """
    Derive decimal representation of the MNC (Mobile Network Code)
    from two or (optionally) three given digits.
    """

    mnc = 0

    # 3-rd digit is optional for the MNC. If present
    # the algorythm is the same as for the MCC.
    if digit3 != 0x0f:
        return derive_mcc(digit1, digit2, digit3)

    if digit1 != 0x0f:
        mnc += digit1 * 10
    if digit2 != 0x0f:
        mnc += digit2

    return mnc

def sanitize_pin_adm(pin_adm, pin_adm_hex=None) -> Hexstr:
    """
    The ADM pin can be supplied either in its hexadecimal form or as
    ascii string. This function checks the supplied opts parameter and
    returns the pin_adm as hex encoded string, regardless in which form
    it was originally supplied by the user
    """

    if pin_adm is not None:
        if len(pin_adm) <= 8:
            pin_adm = ''.join(['%02x' % (ord(x)) for x in pin_adm])
            pin_adm = rpad(pin_adm, 16)

        else:
            raise ValueError("PIN-ADM needs to be <=8 digits (ascii)")

    if pin_adm_hex is not None:
        if len(pin_adm_hex) == 16:
            pin_adm = pin_adm_hex
            # Ensure that it's hex-encoded
            try:
                try_encode = h2b(pin_adm)
            except ValueError as exc:
                raise ValueError("PIN-ADM needs to be hex encoded using this option") from exc
        else:
            raise ValueError("PIN-ADM needs to be exactly 16 digits (hex encoded)")

    return pin_adm


def get_addr_type(addr):
    """
    Validates the given address and returns it's type (FQDN or IPv4 or IPv6)
    Return: 0x00 (FQDN), 0x01 (IPv4), 0x02 (IPv6), None (Bad address argument given)

    TODO: Handle IPv6
    """

    # Empty address string
    if len(addr) == 0:
        return None

    addr_list = addr.split('.')

    # Check for IPv4/IPv6
    try:
        import ipaddress
        # Throws ValueError if addr is not correct
        ipa = ipaddress.ip_address(addr)

        if ipa.version == 4:
            return 0x01
        elif ipa.version == 6:
            return 0x02
    except Exception:
        invalid_ipv4 = True
        for i in addr_list:
            # Invalid IPv4 may qualify for a valid FQDN, so make check here
            # e.g. 172.24.15.300
            import re
            if not re.match('^[0-9_]+$', i):
                invalid_ipv4 = False
                break

        if invalid_ipv4:
            return None

    fqdn_flag = True
    for i in addr_list:
        # Only Alpha-numeric characters and hyphen - RFC 1035
        import re
        if not re.match("^[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)?$", i):
            fqdn_flag = False
            break

    # FQDN
    if fqdn_flag:
        return 0x00

    return None


def sw_match(sw: str, pattern: str) -> bool:
    """Match given SW against given pattern."""
    # Create a masked version of the returned status word
    sw_lower = sw.lower()
    sw_masked = ""
    for i in range(0, 4):
        if pattern[i] == '?':
            sw_masked = sw_masked + '?'
        elif pattern[i] == 'x':
            sw_masked = sw_masked + 'x'
        else:
            sw_masked = sw_masked + sw_lower[i]
    # Compare the masked version against the pattern
    return sw_masked == pattern


def tabulate_str_list(str_list, width: int = 79, hspace: int = 2, lspace: int = 1,
                      align_left: bool = True) -> str:
    """Pretty print a list of strings into a tabulated form.

    Args:
            width : total width in characters per line
            space : horizontal space between cells
            lspace : number of spaces before row
            align_lef : Align text to the left side
    Returns:
            multi-line string containing formatted table
    """
    if str_list is None:
        return ""
    if len(str_list) <= 0:
        return ""
    longest_str = max(str_list, key=len)
    cellwith = len(longest_str) + hspace
    cols = width // cellwith
    rows = (len(str_list) - 1) // cols + 1
    table = []
    for i in iter(range(rows)):
        str_list_row = str_list[i::rows]
        if align_left:
            format_str_cell = '%%-%ds'
        else:
            format_str_cell = '%%%ds'
        format_str_row = (format_str_cell % cellwith) * len(str_list_row)
        format_str_row = (" " * lspace) + format_str_row
        table.append(format_str_row % tuple(str_list_row))
    return '\n'.join(table)


def expand_hex(hexstring, length):
    """Expand a given hexstring to a specified length by replacing "." or ".."
       with a filler that is derived from the neighboring nibbles respective
       bytes. Usually this will be the nibble respective byte before "." or
       "..", execpt when the string begins with "." or "..", then the nibble
       respective byte after "." or ".." is used.". In case the string cannot
       be expanded for some reason, the input string is returned unmodified.

    Args:
            hexstring : hexstring to expand
            length : desired length of the resulting hexstring.
    Returns:
            expanded hexstring
    """

    # expand digit aligned
    if hexstring.count(".") == 1:
        pos = hexstring.index(".")
        if pos > 0:
            filler = hexstring[pos - 1]
        else:
            filler = hexstring[pos + 1]

        missing = length * 2 - (len(hexstring) - 1)
        if missing <= 0:
            return hexstring

        return hexstring.replace(".", filler * missing)

    # expand byte aligned
    elif hexstring.count("..") == 1:
        if len(hexstring) % 2:
            return hexstring

        pos = hexstring.index("..")

        if pos % 2:
            return hexstring

        if pos > 1:
            filler = hexstring[pos - 2:pos]
        else:
            filler = hexstring[pos + 2:pos+4]

        missing = length * 2 - (len(hexstring) - 2)
        if missing <= 0:
            return hexstring

        return hexstring.replace("..", filler * (missing // 2))

    # no change
    return hexstring


def boxed_heading_str(heading, width=80):
    """Generate a string that contains a boxed heading."""
    # Auto-enlarge box if heading exceeds length
    if len(heading) > width - 4:
        width = len(heading) + 4

    res = "#" * width
    fstr = "\n# %-" + str(width - 4) + "s #\n"
    res += fstr % (heading)
    res += "#" * width
    return res


class DataObject(abc.ABC):
    """A DataObject (DO) in the sense of ISO 7816-4.  Contrary to 'normal' TLVs where one
    simply has any number of different TLVs that may occur in any order at any point, ISO 7816
    has the habit of specifying TLV data but with very spcific ordering, or specific choices of
    tags at specific points in a stream.  This class tries to represent this."""

    def __init__(self, name: str, desc: Optional[str] = None, tag: Optional[int] = None):
        """
        Args:
            name: A brief, all-lowercase, underscore separated string identifier
            desc: A human-readable description of what this DO represents
            tag : The tag associated with this DO
        """
        self.name = name
        self.desc = desc
        self.tag = tag
        self.decoded = None
        self.encoded = None

    def __str__(self):
        return self.name

    def __repr__(self) -> str:
        return '%s(%s)' % (self.__class__, self.name)

    def __or__(self, other) -> 'DataObjectChoice':
        """OR-ing DataObjects together renders a DataObjectChoice."""
        if isinstance(other, DataObject):
            # DataObject | DataObject = DataObjectChoice
            return DataObjectChoice(None, members=[self, other])
        else:
            raise TypeError

    def __add__(self, other) -> 'DataObjectCollection':
        """ADD-ing DataObjects together renders a DataObjectCollection."""
        if isinstance(other, DataObject):
            # DataObject + DataObject = DataObjectCollectin
            return DataObjectCollection(None, members=[self, other])
        else:
            raise TypeError

    def _compute_tag(self) -> int:
        """Compute the tag (sometimes the tag encodes part of the value)."""
        return self.tag

    def to_dict(self) -> dict:
        """Return a dict in form "name: decoded_value" """
        return {self.name: self.decoded}

    @abc.abstractmethod
    def from_bytes(self, do: bytes):
        """Parse the value part of the DO into the internal state of this instance.
        Args:
            do : binary encoded bytes
        """

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        """Encode the internal state of this instance into the TLV value part.
        Returns:
            binary bytes encoding the internal state
        """

    def from_tlv(self, do: bytes) -> bytes:
        """Parse binary TLV representation into internal state.  The resulting decoded
        representation is _not_ returned, but just internalized in the object instance!
        Args:
            do : input bytes containing TLV-encoded representation
        Returns:
            bytes remaining at end of 'do' after parsing one TLV/DO.
        """
        if do[0] != self.tag:
            raise ValueError('%s: Can only decode tag 0x%02x' %
                             (self, self.tag))
        length = do[1]
        val = do[2:2+length]
        self.from_bytes(val)
        # return remaining bytes
        return do[2+length:]

    def to_tlv(self) -> bytes:
        """Encode internal representation to binary TLV.
        Returns:
            bytes encoded in TLV format.
        """
        val = self.to_bytes()
        return bertlv_encode_tag(self._compute_tag()) + bertlv_encode_len(len(val)) + val

    # 'codec' interface
    def decode(self, binary: bytes) -> Tuple[dict, bytes]:
        """Decode a single DOs from the input data.
        Args:
            binary : binary bytes of encoded data
        Returns:
            tuple of (decoded_result, binary_remainder)
        """
        tag = binary[0]
        if tag != self.tag:
            raise ValueError('%s: Unknown Tag 0x%02x in %s; expected 0x%02x' %
                             (self, tag, binary, self.tag))
        remainder = self.from_tlv(binary)
        return (self.to_dict(), remainder)

    # 'codec' interface
    def encode(self) -> bytes:
        return self.to_tlv()


class TL0_DataObject(DataObject):
    """Data Object that has Tag, Len=0 and no Value part."""

    def __init__(self, name: str, desc: str, tag: int, val=None):
        super().__init__(name, desc, tag)
        self.val = val

    def from_bytes(self, binary: bytes):
        if len(binary) != 0:
            raise ValueError
        self.decoded = self.val

    def to_bytes(self) -> bytes:
        return b''


class DataObjectCollection:
    """A DataObjectCollection consits of multiple Data Objects identified by their tags.
    A given encoded DO may contain any of them in any order, and may contain multiple instances
    of each DO."""

    def __init__(self, name: str, desc: Optional[str] = None, members=None):
        self.name = name
        self.desc = desc
        self.members = members or []
        self.members_by_tag = {}
        self.members_by_name = {}
        self.members_by_tag = {m.tag: m for m in members}
        self.members_by_name = {m.name: m for m in members}

    def __str__(self) -> str:
        member_strs = [str(x) for x in self.members]
        return '%s(%s)' % (self.name, ','.join(member_strs))

    def __repr__(self) -> str:
        member_strs = [repr(x) for x in self.members]
        return '%s(%s)' % (self.__class__, ','.join(member_strs))

    def __add__(self, other) -> 'DataObjectCollection':
        """Extending DataCollections with other DataCollections or DataObjects."""
        if isinstance(other, DataObjectCollection):
            # adding one collection to another
            members = self.members + other.members
            return DataObjectCollection(self.name, self.desc, members)
        elif isinstance(other, DataObject):
            # adding a member to a collection
            return DataObjectCollection(self.name, self.desc, self.members + [other])
        else:
            raise TypeError

    # 'codec' interface
    def decode(self, binary: bytes) -> Tuple[List, bytes]:
        """Decode any number of DOs from the collection until the end of the input data,
        or uninitialized memory (0xFF) is found.
        Args:
            binary : binary bytes of encoded data
        Returns:
            tuple of (decoded_result, binary_remainder)
        """
        res = []
        remainder = binary
        # iterate until no binary trailer is left
        while len(remainder):
            tag = remainder[0]
            if tag == 0xff:  # uninitialized memory at the end?
                return (res, remainder)
            if not tag in self.members_by_tag:
                raise ValueError('%s: Unknown Tag 0x%02x in %s; expected %s' %
                                 (self, tag, remainder, self.members_by_tag.keys()))
            obj = self.members_by_tag[tag]
            # DO from_tlv returns remainder of binary
            remainder = obj.from_tlv(remainder)
            # collect our results
            res.append(obj.to_dict())
        return (res, remainder)

    # 'codec' interface
    def encode(self, decoded) -> bytes:
        res = bytearray()
        for i in decoded:
            obj = self.members_by_name(i[0])
            res.append(obj.to_tlv())
        return res


class DataObjectChoice(DataObjectCollection):
    """One Data Object from within a choice, identified by its tag.
    This means that exactly one member of the choice must occur, and which one occurs depends
    on the tag."""

    def __add__(self, other):
        """We overload the add operator here to avoid inheriting it from DataObjecCollection."""
        raise TypeError

    def __or__(self, other) -> 'DataObjectChoice':
        """OR-ing a Choice to another choice extends the choice, as does OR-ing a DataObject."""
        if isinstance(other, DataObjectChoice):
            # adding one collection to another
            members = self.members + other.members
            return DataObjectChoice(self.name, self.desc, members)
        elif isinstance(other, DataObject):
            # adding a member to a collection
            return DataObjectChoice(self.name, self.desc, self.members + [other])
        else:
            raise TypeError

    # 'codec' interface
    def decode(self, binary: bytes) -> Tuple[dict, bytes]:
        """Decode a single DOs from the choice based on the tag.
        Args:
            binary : binary bytes of encoded data
        Returns:
            tuple of (decoded_result, binary_remainder)
        """
        tag = binary[0]
        if tag == 0xff:
            return (None, binary)
        if not tag in self.members_by_tag:
            raise ValueError('%s: Unknown Tag 0x%02x in %s; expected %s' %
                             (self, tag, binary, self.members_by_tag.keys()))
        obj = self.members_by_tag[tag]
        remainder = obj.from_tlv(binary)
        return (obj.to_dict(), remainder)

    # 'codec' interface
    def encode(self, decoded) -> bytes:
        obj = self.members_by_name[list(decoded)[0]]
        obj.decoded = list(decoded.values())[0]
        return obj.to_tlv()


class DataObjectSequence:
    """A sequence of DataObjects or DataObjectChoices. This allows us to express a certain
       ordered sequence of DOs or choices of DOs that have to appear as per the specification.
       By wrapping them into this formal DataObjectSequence, we can offer convenience methods
       for encoding or decoding an entire sequence."""

    def __init__(self, name: str, desc: Optional[str] = None, sequence=None):
        self.sequence = sequence or []
        self.name = name
        self.desc = desc

    def __str__(self) -> str:
        member_strs = [str(x) for x in self.sequence]
        return '%s(%s)' % (self.name, ','.join(member_strs))

    def __repr__(self) -> str:
        member_strs = [repr(x) for x in self.sequence]
        return '%s(%s)' % (self.__class__, ','.join(member_strs))

    def __add__(self, other) -> 'DataObjectSequence':
        """Add (append) a DataObject or DataObjectChoice to the sequence."""
        if isinstance(other, 'DataObject'):
            return DataObjectSequence(self.name, self.desc, self.sequence + [other])
        elif isinstance(other, 'DataObjectChoice'):
            return DataObjectSequence(self.name, self.desc, self.sequence + [other])
        elif isinstance(other, 'DataObjectSequence'):
            return DataObjectSequence(self.name, self.desc, self.sequence + other.sequence)

    # 'codec' interface
    def decode(self, binary: bytes) -> Tuple[list, bytes]:
        """Decode a sequence by calling the decoder of each element in the sequence.
        Args:
            binary : binary bytes of encoded data
        Returns:
            tuple of (decoded_result, binary_remainder)
        """
        remainder = binary
        res = []
        for e in self.sequence:
            (r, remainder) = e.decode(remainder)
            if r:
                res.append(r)
        return (res, remainder)

    # 'codec' interface
    def decode_multi(self, do: bytes) -> Tuple[list, bytes]:
        """Decode multiple occurrences of the sequence from the binary input data.
        Args:
            do : binary input data to be decoded
        Returns:
            list of results of the decoder of this sequences
        """
        remainder = do
        res = []
        while len(remainder):
            (r, remainder2) = self.decode(remainder)
            if r:
                res.append(r)
            if len(remainder2) < len(remainder):
                remainder = remainder2
            else:
                remainder = remainder2
                break
        return (res, remainder)

    # 'codec' interface
    def encode(self, decoded) -> bytes:
        """Encode a sequence by calling the encoder of each element in the sequence."""
        encoded = bytearray()
        i = 0
        for e in self.sequence:
            encoded += e.encode(decoded[i])
            i += 1
        return encoded

    def encode_multi(self, decoded) -> bytes:
        """Encode multiple occurrences of the sequence from the decoded input data.
        Args:
            decoded : list of json-serializable input data; one sequence per list item
        Returns:
            binary encoded output data
        """
        encoded = bytearray()
        for d in decoded:
            encoded += self.encode(d)
        return encoded


class CardCommand:
    """A single card command / instruction."""

    def __init__(self, name, ins, cla_list=None, desc=None):
        self.name = name
        self.ins = ins
        self.cla_list = cla_list or []
        self.cla_list = [x.lower() for x in self.cla_list]
        self.desc = desc

    def __str__(self):
        return self.name

    def __repr__(self):
        return '%s(INS=%02x,CLA=%s)' % (self.name, self.ins, self.cla_list)

    def match_cla(self, cla):
        """Does the given CLA match the CLA list of the command?."""
        if not isinstance(cla, str):
            cla = '%02u' % cla
        cla = cla.lower()
        for cla_match in self.cla_list:
            cla_masked = ""
            for i in range(0, 2):
                if cla_match[i] == 'x':
                    cla_masked += 'x'
                else:
                    cla_masked += cla[i]
            if cla_masked == cla_match:
                return True
        return False


class CardCommandSet:
    """A set of card instructions, typically specified within one spec."""

    def __init__(self, name, cmds=[]):
        self.name = name
        self.cmds = {c.ins: c for c in cmds}

    def __str__(self):
        return self.name

    def __getitem__(self, idx):
        return self.cmds[idx]

    def __add__(self, other):
        if isinstance(other, CardCommand):
            if other.ins in self.cmds:
                raise ValueError('%s: INS 0x%02x already defined: %s' %
                                 (self, other.ins, self.cmds[other.ins]))
            self.cmds[other.ins] = other
        elif isinstance(other, CardCommandSet):
            for c in other.cmds.keys():
                self.cmds[c] = other.cmds[c]
        else:
            raise ValueError(
                '%s: Unsupported type to add operator: %s' % (self, other))

    def lookup(self, ins, cla=None):
        """look-up the command within the CommandSet."""
        ins = int(ins)
        if not ins in self.cmds:
            return None
        cmd = self.cmds[ins]
        if cla and not cmd.match_cla(cla):
            return None
        return cmd
