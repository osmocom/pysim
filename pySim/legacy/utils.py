# -*- coding: utf-8 -*-

""" pySim: various utilities only used by legacy tools (pySim-{prog,read})
"""

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

from typing import Optional, Tuple
from pySim.utils import Hexstr, rpad, enc_plmn, h2i, i2s, s2h
from pySim.utils import dec_xplmn_w_act, dec_xplmn, dec_mcc_from_plmn, dec_mnc_from_plmn
from osmocom.utils import swap_nibbles, h2b, b2h

def hexstr_to_Nbytearr(s, nbytes):
    return [s[i:i+(nbytes*2)] for i in range(0, len(s), (nbytes*2))]

def format_xplmn_w_act(hexstr):
    s = ""
    for rec_data in hexstr_to_Nbytearr(hexstr, 5):
        rec_info = dec_xplmn_w_act(rec_data)
        if rec_info['mcc'] == "" and rec_info['mnc'] == "":
            rec_str = "unused"
        else:
            rec_str = "MCC: %s MNC: %s AcT: %s" % (
                rec_info['mcc'], rec_info['mnc'], ", ".join(rec_info['act']))
        s += "\t%s # %s\n" % (rec_data, rec_str)
    return s


def format_xplmn(hexstr: Hexstr) -> str:
    s = ""
    for rec_data in hexstr_to_Nbytearr(hexstr, 3):
        rec_info = dec_xplmn(rec_data)
        if not rec_info['mcc'] and not rec_info['mnc']:
            rec_str = "unused"
        else:
            rec_str = "MCC: %s MNC: %s" % (rec_info['mcc'], rec_info['mnc'])
        s += "\t%s # %s\n" % (rec_data, rec_str)
    return s


def format_ePDGSelection(hexstr):
    ePDGSelection_info_tag_chars = 2
    ePDGSelection_info_tag_str = hexstr[:2]
    s = ""
    # Minimum length
    len_chars = 2
    # TODO: Need to determine length properly - definite length support only
    # Inconsistency in spec: 3GPP TS 31.102 version 15.2.0 Release 15, 4.2.104
    # As per spec, length is 5n, n - number of PLMNs
    # But, each PLMN entry is made of PLMN (3 Bytes) + ePDG Priority (2 Bytes) + ePDG FQDN format (1 Byte)
    # Totalling to 6 Bytes, maybe length should be 6n
    len_str = hexstr[ePDGSelection_info_tag_chars:ePDGSelection_info_tag_chars+len_chars]

    # Not programmed scenario
    if int(len_str, 16) == 255 or int(ePDGSelection_info_tag_str, 16) == 255:
        len_chars = 0
        ePDGSelection_info_tag_chars = 0
    if len_str[0] == '8':
        # The bits 7 to 1 denotes the number of length octets if length > 127
        if int(len_str[1]) > 0:
            # Update number of length octets
            len_chars = len_chars * int(len_str[1])
            len_str = hexstr[ePDGSelection_info_tag_chars:len_chars]

    content_str = hexstr[ePDGSelection_info_tag_chars+len_chars:]
    # Right pad to prevent index out of range - multiple of 6 bytes
    content_str = rpad(content_str, len(content_str) +
                       (12 - (len(content_str) % 12)))
    for rec_data in hexstr_to_Nbytearr(content_str, 6):
        rec_info = dec_ePDGSelection(rec_data)
        if rec_info['mcc'] == 0xFFF and rec_info['mnc'] == 0xFFF:
            rec_str = "unused"
        else:
            rec_str = "MCC: %03d MNC: %03d ePDG Priority: %s ePDG FQDN format: %s" % \
                (rec_info['mcc'], rec_info['mnc'],
                 rec_info['epdg_priority'], rec_info['epdg_fqdn_format'])
        s += "\t%s # %s\n" % (rec_data, rec_str)
    return s

def enc_st(st, service, state=1):
    """
    Encodes the EF S/U/IST/EST and returns the updated Service Table

    Parameters:
            st - Current value of SIM/USIM/ISIM Service Table
            service - Service Number to encode as activated/de-activated
            state - 1 mean activate, 0 means de-activate

    Returns:
            s - Modified value of SIM/USIM/ISIM Service Table

    Default values:
            - state: 1 - Sets the particular Service bit to 1
    """
    st_bytes = [st[i:i+2] for i in range(0, len(st), 2)]

    s = ""
    # Check whether the requested service is present in each byte
    for i in range(0, len(st_bytes)):
        # Byte i contains info about Services num (8i+1) to num (8i+8)
        if service in range((8*i) + 1, (8*i) + 9):
            byte = int(st_bytes[i], 16)
            # Services in each byte are in order MSB to LSB
            # MSB - Service (8i+8)
            # LSB - Service (8i+1)
            mod_byte = 0x00
            # Copy bit by bit contents of byte to mod_byte with modified bit
            # for requested service
            for j in range(1, 9):
                mod_byte = mod_byte >> 1
                if service == (8*i) + j:
                    mod_byte = state == 1 and mod_byte | 0x80 or mod_byte & 0x7f
                else:
                    mod_byte = byte & 0x01 == 0x01 and mod_byte | 0x80 or mod_byte & 0x7f
                byte = byte >> 1

            s += ('%02x' % (mod_byte))
        else:
            s += st_bytes[i]

    return s


def dec_st(st, table="sim") -> str:
    """
    Parses the EF S/U/IST and prints the list of available services in EF S/U/IST
    """

    if table == "isim":
        from pySim.ts_31_103 import EF_IST_map
        lookup_map = EF_IST_map
    elif table == "usim":
        from pySim.ts_31_102 import EF_UST_map
        lookup_map = EF_UST_map
    else:
        from pySim.ts_51_011 import EF_SST_map
        lookup_map = EF_SST_map

    st_bytes = [st[i:i+2] for i in range(0, len(st), 2)]

    avail_st = ""
    # Get each byte and check for available services
    for i in range(0, len(st_bytes)):
        # Byte i contains info about Services num (8i+1) to num (8i+8)
        byte = int(st_bytes[i], 16)
        # Services in each byte are in order MSB to LSB
        # MSB - Service (8i+8)
        # LSB - Service (8i+1)
        for j in range(1, 9):
            if byte & 0x01 == 0x01 and ((8*i) + j in lookup_map):
                # Byte X contains info about Services num (8X-7) to num (8X)
                # bit = 1: service available
                # bit = 0: service not available
                avail_st += '\tService %d - %s\n' % (
                    (8*i) + j, lookup_map[(8*i) + j])
            byte = byte >> 1
    return avail_st


def enc_ePDGSelection(hexstr, mcc, mnc, epdg_priority='0001', epdg_fqdn_format='00'):
    """
    Encode ePDGSelection so it can be stored at EF.ePDGSelection or EF.ePDGSelectionEm.
    See 3GPP TS 31.102 version 15.2.0 Release 15, section 4.2.104 and 4.2.106.

    Default values:
            - epdg_priority: '0001' - 1st Priority
            - epdg_fqdn_format: '00' - Operator Identifier FQDN
    """

    plmn1 = enc_plmn(mcc, mnc) + epdg_priority + epdg_fqdn_format
    # TODO: Handle encoding of Length field for length more than 127 Bytes
    content = '80' + ('%02x' % (len(plmn1)//2)) + plmn1
    content = rpad(content, len(hexstr))
    return content


def dec_ePDGSelection(sixhexbytes):
    """
    Decode ePDGSelection to get EF.ePDGSelection or EF.ePDGSelectionEm.
    See 3GPP TS 31.102 version 15.2.0 Release 15, section 4.2.104 and 4.2.106.
    """

    res = {'mcc': 0, 'mnc': 0, 'epdg_priority': 0, 'epdg_fqdn_format': ''}
    plmn_chars = 6
    epdg_priority_chars = 4
    epdg_fqdn_format_chars = 2
    # first three bytes (six ascii hex chars)
    plmn_str = sixhexbytes[:plmn_chars]
    # two bytes after first three bytes
    epdg_priority_str = sixhexbytes[plmn_chars:plmn_chars +
                                    epdg_priority_chars]
    # one byte after first five bytes
    epdg_fqdn_format_str = sixhexbytes[plmn_chars +
                                       epdg_priority_chars:plmn_chars + epdg_priority_chars + epdg_fqdn_format_chars]
    res['mcc'] = dec_mcc_from_plmn(plmn_str)
    res['mnc'] = dec_mnc_from_plmn(plmn_str)
    res['epdg_priority'] = epdg_priority_str
    res['epdg_fqdn_format'] = epdg_fqdn_format_str == '00' and 'Operator Identifier FQDN' or 'Location based FQDN'
    return res


def first_TLV_parser(bytelist):
    '''
    first_TLV_parser([0xAA, 0x02, 0xAB, 0xCD, 0xFF, 0x00]) -> (170, 2, [171, 205])

    parses first TLV format record in a list of bytelist
    returns a 3-Tuple: Tag, Length, Value
    Value is a list of bytes
    parsing of length is ETSI'style 101.220
    '''
    Tag = bytelist[0]
    if bytelist[1] == 0xFF:
        Len = bytelist[2]*256 + bytelist[3]
        Val = bytelist[4:4+Len]
    else:
        Len = bytelist[1]
        Val = bytelist[2:2+Len]
    return (Tag, Len, Val)


def TLV_parser(bytelist):
    '''
    TLV_parser([0xAA, ..., 0xFF]) -> [(T, L, [V]), (T, L, [V]), ...]

    loops on the input list of bytes with the "first_TLV_parser()" function
    returns a list of 3-Tuples
    '''
    ret = []
    while len(bytelist) > 0:
        T, L, V = first_TLV_parser(bytelist)
        if T == 0xFF:
            # padding bytes
            break
        ret.append((T, L, V))
        # need to manage length of L
        if L > 0xFE:
            bytelist = bytelist[L+4:]
        else:
            bytelist = bytelist[L+2:]
    return ret


def dec_addr_tlv(hexstr):
    """
    Decode hex string to get EF.P-CSCF Address or EF.ePDGId or EF.ePDGIdEm.
    See 3GPP TS 31.102 version 13.4.0 Release 13, section 4.2.8, 4.2.102 and 4.2.104.
    """

    # Convert from hex str to int bytes list
    addr_tlv_bytes = h2i(hexstr)

    # Get list of tuples containing parsed TLVs
    tlvs = TLV_parser(addr_tlv_bytes)

    for tlv in tlvs:
        # tlv = (T, L, [V])
        # T = Tag
        # L = Length
        # [V] = List of value

        # Invalid Tag value scenario
        if tlv[0] != 0x80:
            continue

        # Empty field - Zero length
        if tlv[1] == 0:
            continue

        # Uninitialized field
        if all([v == 0xff for v in tlv[2]]):
            continue

        # First byte in the value has the address type
        addr_type = tlv[2][0]
        # TODO: Support parsing of IPv6
        # Address Type: 0x00 (FQDN), 0x01 (IPv4), 0x02 (IPv6), other (Reserved)
        if addr_type == 0x00:  # FQDN
            # Skip address tye byte i.e. first byte in value list
            content = tlv[2][1:]
            return (i2s(content), '00')

        elif addr_type == 0x01:  # IPv4
            # Skip address tye byte i.e. first byte in value list
            # Skip the unused byte in Octect 4 after address type byte as per 3GPP TS 31.102
            ipv4 = tlv[2][2:]
            content = '.'.join(str(x) for x in ipv4)
            return (content, '01')
        else:
            raise ValueError("Invalid address type")

    return (None, None)


def enc_addr_tlv(addr, addr_type='00'):
    """
    Encode address TLV object used in EF.P-CSCF Address, EF.ePDGId and EF.ePDGIdEm.
    See 3GPP TS 31.102 version 13.4.0 Release 13, section 4.2.8, 4.2.102 and 4.2.104.

    Default values:
      - addr_type: 00 - FQDN format of Address
    """

    s = ""

    # TODO: Encoding of IPv6 address
    if addr_type == '00':  # FQDN
        hex_str = s2h(addr)
        s += '80' + ('%02x' % ((len(hex_str)//2)+1)) + '00' + hex_str
    elif addr_type == '01':  # IPv4
        ipv4_list = addr.split('.')
        ipv4_str = ""
        for i in ipv4_list:
            ipv4_str += ('%02x' % (int(i)))

        # Unused bytes shall be set to 'ff'. i.e 4th Octet after Address Type is not used
        # IPv4 Address is in octet 5 to octet 8 of the TLV data object
        s += '80' + ('%02x' % ((len(ipv4_str)//2)+2)) + '01' + 'ff' + ipv4_str

    return s


def dec_msisdn(ef_msisdn: Hexstr) -> Optional[Tuple[int, int, Optional[str]]]:
    """
    Decode MSISDN from EF.MSISDN or EF.ADN (same structure).
    See 3GPP TS 31.102, section 4.2.26 and 4.4.2.3.
    """

    # Convert from str to (kind of) 'bytes'
    ef_msisdn = h2b(ef_msisdn)

    # Make sure mandatory fields are present
    if len(ef_msisdn) < 14:
        raise ValueError("EF.MSISDN is too short")

    # Skip optional Alpha Identifier
    xlen = len(ef_msisdn) - 14
    msisdn_lhv = ef_msisdn[xlen:]

    # Parse the length (in bytes) of the BCD encoded number
    bcd_len = msisdn_lhv[0]
    # BCD length = length of dial num (max. 10 bytes) + 1 byte ToN and NPI
    if bcd_len == 0xff:
        return None
    elif bcd_len > 11 or bcd_len < 1:
        raise ValueError(
            "Length of MSISDN (%d bytes) is out of range" % bcd_len)

    # Parse ToN / NPI
    ton = (msisdn_lhv[1] >> 4) & 0x07
    npi = msisdn_lhv[1] & 0x0f
    bcd_len -= 1

    # No MSISDN?
    if not bcd_len:
        return (npi, ton, None)

    msisdn = swap_nibbles(b2h(msisdn_lhv[2:][:bcd_len])).rstrip('f')
    # International number 10.5.118/3GPP TS 24.008
    if ton == 0x01:
        msisdn = '+' + msisdn

    return (npi, ton, msisdn)


def enc_msisdn(msisdn: str, npi: int = 0x01, ton: int = 0x03) -> Hexstr:
    """
    Encode MSISDN as LHV so it can be stored to EF.MSISDN.
    See 3GPP TS 31.102, section 4.2.26 and 4.4.2.3. (The result
    will not contain the optional Alpha Identifier at the beginning.)

    Default NPI / ToN values:
      - NPI: ISDN / telephony numbering plan (E.164 / E.163),
      - ToN: network specific or international number (if starts with '+').
    """

    # If no MSISDN is supplied then encode the file contents as all "ff"
    if msisdn in ["", "+"]:
        return "ff" * 14

    # Leading '+' indicates International Number
    if msisdn[0] == '+':
        msisdn = msisdn[1:]
        ton = 0x01

    # An MSISDN must not exceed 20 digits
    if len(msisdn) > 20:
        raise ValueError("msisdn must not be longer than 20 digits")

    # Append 'f' padding if number of digits is odd
    if len(msisdn) % 2 > 0:
        msisdn += 'f'

    # BCD length also includes NPI/ToN header
    bcd_len = len(msisdn) // 2 + 1
    npi_ton = (npi & 0x0f) | ((ton & 0x07) << 4) | 0x80
    bcd = rpad(swap_nibbles(msisdn), 10 * 2)  # pad to 10 octets

    return ('%02x' % bcd_len) + ('%02x' % npi_ton) + bcd + ("ff" * 2)
