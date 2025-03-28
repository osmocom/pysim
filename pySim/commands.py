# -*- coding: utf-8 -*-

""" pySim: SIM Card commands according to ISO 7816-4 and TS 11.11
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2010-2024  Harald Welte <laforge@gnumonks.org>
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

from typing import List, Tuple
import typing # construct also has a Union, so we do typing.Union below
from construct import Construct, Struct, Const, Select
from construct import Optional as COptional
from osmocom.construct import LV, filter_dict
from osmocom.utils import rpad, lpad, b2h, h2b, h2i, i2h, str_sanitize, Hexstr
from osmocom.tlv import bertlv_encode_len

from pySim.utils import sw_match, expand_hex, SwHexstr, ResTuple, SwMatchstr
from pySim.exceptions import SwMatchError
from pySim.transport import LinkBase

# A path can be either just a FID or a list of FID
Path = typing.Union[Hexstr, List[Hexstr]]

def lchan_nr_to_cla(cla: int, lchan_nr: int) -> int:
    """Embed a logical channel number into the CLA byte."""
    # TS 102 221 10.1.1 Coding of Class Byte
    if lchan_nr < 4:
        # standard logical channel number
        if cla >> 4 in [0x0, 0xA, 0x8]:
            return (cla & 0xFC) | (lchan_nr & 3)
        else:
            raise ValueError('Undefined how to use CLA %2X with logical channel %u' % (cla, lchan_nr))
    elif lchan_nr < 16:
        # extended logical channel number
        if cla >> 6 in [1, 3]:
            return (cla & 0xF0) | ((lchan_nr - 4) & 0x0F)
        else:
            raise ValueError('Undefined how to use CLA %2X with logical channel %u' % (cla, lchan_nr))
    else:
        raise ValueError('logical channel outside of range 0 .. 15')

def cla_with_lchan(cla_byte: Hexstr, lchan_nr: int) -> Hexstr:
    """Embed a logical channel number into the hex-string encoded CLA value."""
    cla_int = h2i(cla_byte)[0]
    return i2h([lchan_nr_to_cla(cla_int, lchan_nr)])

class SimCardCommands:
    """Class providing methods for various card-specific commands such as SELECT, READ BINARY, etc.
    Historically one instance exists below CardBase, but with the introduction of multiple logical
    channels there can be multiple instances.  The lchan number will then be patched into the CLA
    byte by the respective instance. """
    def __init__(self, transport: LinkBase, lchan_nr: int = 0):
        self._tp = transport
        self.sel_ctrl = "0000"
        self.lchan_nr = lchan_nr
        # invokes the setter below
        self.cla_byte = "a0"
        self.scp = None # Secure Channel Protocol

    def fork_lchan(self, lchan_nr: int) -> 'SimCardCommands':
        """Fork a per-lchan specific SimCardCommands instance off the current instance."""
        ret = SimCardCommands(transport = self._tp, lchan_nr = lchan_nr)
        ret.cla_byte = self.cla_byte
        ret.sel_ctrl = self.sel_ctrl
        return ret

    @property
    def max_cmd_len(self) -> int:
        """Maximum length of the command apdu data section. Depends on secure channel protocol used."""
        if self.scp:
            return 255 - self.scp.overhead
        else:
            return 255

    def send_apdu(self, pdu: Hexstr, apply_lchan:bool = True) -> ResTuple:
        """Sends an APDU and auto fetch response data

        Args:
           pdu : string of hexadecimal characters (ex. "A0A40000023F00")
           apply_lchan : apply the currently selected lchan to the CLA byte before sending
        Returns:
           tuple(data, sw), where
                        data : string (in hex) of returned data (ex. "074F4EFFFF")
                        sw   : string (in hex) of status word (ex. "9000")
        """
        if apply_lchan:
            pdu = cla_with_lchan(pdu[0:2], self.lchan_nr) + pdu[2:]
        if self.scp:
            return self.scp.send_apdu_wrapper(self._tp.send_apdu, pdu)
        else:
            return self._tp.send_apdu(pdu)

    def send_apdu_checksw(self, pdu: Hexstr, sw: SwMatchstr = "9000", apply_lchan:bool = True) -> ResTuple:
        """Sends an APDU and check returned SW

        Args:
           pdu : string of hexadecimal characters (ex. "A0A40000023F00")
           sw : string of 4 hexadecimal characters (ex. "9000"). The user may mask out certain
                digits using a '?' to add some ambiguity if needed.
           apply_lchan : apply the currently selected lchan to the CLA byte before sending
        Returns:
                tuple(data, sw), where
                        data : string (in hex) of returned data (ex. "074F4EFFFF")
                        sw   : string (in hex) of status word (ex. "9000")
        """
        if apply_lchan:
            pdu = cla_with_lchan(pdu[0:2], self.lchan_nr) + pdu[2:]
        if self.scp:
            return self.scp.send_apdu_wrapper(self._tp.send_apdu_checksw, pdu, sw)
        else:
            return self._tp.send_apdu_checksw(pdu, sw)

    def send_apdu_constr(self, cla: Hexstr, ins: Hexstr, p1: Hexstr, p2: Hexstr, cmd_constr: Construct,
                         cmd_data: Hexstr, resp_constr: Construct, apply_lchan:bool = True) -> Tuple[dict, SwHexstr]:
        """Build and sends an APDU using a 'construct' definition; parses response.

        Args:
                cla : string (in hex) ISO 7816 class byte
                ins : string (in hex) ISO 7816 instruction byte
                p1 : string (in hex) ISO 7116 Parameter 1 byte
                p2 : string (in hex) ISO 7116 Parameter 2 byte
                cmd_cosntr : defining how to generate binary APDU command data
                cmd_data : command data passed to cmd_constr
                resp_cosntr : defining how to decode binary APDU response data
                apply_lchan : apply the currently selected lchan to the CLA byte before sending
        Returns:
                Tuple of (decoded_data, sw)
        """
        cmd = cmd_constr.build(cmd_data) if cmd_data else ''
        lc = i2h([len(cmd)]) if cmd_data else ''
        le = '00' if resp_constr else ''
        pdu = ''.join([cla, ins, p1, p2, lc, b2h(cmd), le])
        (data, sw) = self.send_apdu(pdu, apply_lchan = apply_lchan)
        if data:
            # filter the resulting dict to avoid '_io' members inside
            rsp = filter_dict(resp_constr.parse(h2b(data)))
        else:
            rsp = None
        return (rsp, sw)

    def send_apdu_constr_checksw(self, cla: Hexstr, ins: Hexstr, p1: Hexstr, p2: Hexstr,
                                 cmd_constr: Construct, cmd_data: Hexstr, resp_constr: Construct,
                                 sw_exp: SwMatchstr="9000", apply_lchan:bool = True) -> Tuple[dict, SwHexstr]:
        """Build and sends an APDU using a 'construct' definition; parses response.

        Args:
                cla : string (in hex) ISO 7816 class byte
                ins : string (in hex) ISO 7816 instruction byte
                p1 : string (in hex) ISO 7116 Parameter 1 byte
                p2 : string (in hex) ISO 7116 Parameter 2 byte
                cmd_cosntr : defining how to generate binary APDU command data
                cmd_data : command data passed to cmd_constr
                resp_cosntr : defining how to decode  binary APDU response data
                exp_sw : string (in hex) of status word (ex. "9000")
        Returns:
                Tuple of (decoded_data, sw)
        """
        (rsp, sw) = self.send_apdu_constr(cla, ins, p1, p2, cmd_constr, cmd_data, resp_constr,
                                          apply_lchan = apply_lchan)
        if not sw_match(sw, sw_exp):
            raise SwMatchError(sw, sw_exp.lower(), self._tp.sw_interpreter)
        return (rsp, sw)

    # Extract a single FCP item from TLV
    def __parse_fcp(self, fcp: Hexstr):
        # see also: ETSI TS 102 221, chapter 11.1.1.3.1 Response for MF,
        # DF or ADF
        from pytlv.TLV import TLV
        tlvparser = TLV(['82', '83', '84', 'a5', '8a', '8b',
                        '8c', '80', 'ab', 'c6', '81', '88'])

        # pytlv is case sensitive!
        fcp = fcp.lower()

        if fcp[0:2] != '62':
            raise ValueError(
                'Tag of the FCP template does not match, expected 62 but got %s' % fcp[0:2])

        # Unfortunately the spec is not very clear if the FCP length is
        # coded as one or two byte vale, so we have to try it out by
        # checking if the length of the remaining TLV string matches
        # what we get in the length field.
        # See also ETSI TS 102 221, chapter 11.1.1.3.0 Base coding.
        # TODO: this likely just is normal BER-TLV ("All data objects are BER-TLV except if otherwise # defined.")
        exp_tlv_len = int(fcp[2:4], 16)
        if len(fcp[4:]) // 2 == exp_tlv_len:
            skip = 4
        else:
            exp_tlv_len = int(fcp[2:6], 16)
            if len(fcp[4:]) // 2 == exp_tlv_len:
                skip = 6
            raise ValueError('Cannot determine length of TLV-length')

        # Skip FCP tag and length
        tlv = fcp[skip:]
        return tlvparser.parse(tlv)

    # Tell the length of a record by the card response
    # USIMs respond with an FCP template, which is different
    # from what SIMs responds. See also:
    # USIM: ETSI TS 102 221, chapter 11.1.1.3 Response Data
    # SIM: GSM 11.11, chapter 9.2.1 SELECT
    def __record_len(self, r) -> int:
        if self.sel_ctrl == "0004":
            tlv_parsed = self.__parse_fcp(r[-1])
            file_descriptor = tlv_parsed['82']
            # See also ETSI TS 102 221, chapter 11.1.1.4.3 File Descriptor
            return int(file_descriptor[4:8], 16)
        else:
            return int(r[-1][28:30], 16)

    # Tell the length of a binary file. See also comment
    # above.
    def __len(self, r) -> int:
        if self.sel_ctrl == "0004":
            tlv_parsed = self.__parse_fcp(r[-1])
            return int(tlv_parsed['80'], 16)
        else:
            return int(r[-1][4:8], 16)

    def get_atr(self) -> Hexstr:
        """Return the ATR of the currently inserted card."""
        return self._tp.get_atr()

    def try_select_path(self, dir_list: List[Hexstr]) -> List[ResTuple]:
        """ Try to select a specified path

        Args:
                dir_list : list of hex-string FIDs
        """

        rv = []
        if not isinstance(dir_list, list):
            dir_list = [dir_list]
        for i in dir_list:
            data, sw = self.send_apdu(self.cla_byte + "a4" + self.sel_ctrl + "02" + i + "00")
            rv.append((data, sw))
            if sw != '9000':
                return rv
        return rv

    def select_path(self, dir_list: Path) -> List[Hexstr]:
        """Execute SELECT for an entire list/path of FIDs.

        Args:
                dir_list: list of FIDs representing the path to select

        Returns:
                list of return values (FCP in hex encoding) for each element of the path
        """
        rv = []
        if not isinstance(dir_list, list):
            dir_list = [dir_list]
        for i in dir_list:
            data, _sw = self.select_file(i)
            rv.append(data)
        return rv

    def select_file(self, fid: Hexstr) -> ResTuple:
        """Execute SELECT a given file by FID.

        Args:
                fid : file identifier as hex string
        """

        return self.send_apdu_checksw(self.cla_byte + "a4" + self.sel_ctrl + "02" + fid + "00")

    def select_parent_df(self) -> ResTuple:
        """Execute SELECT to switch to the parent DF """
        return self.send_apdu_checksw(self.cla_byte + "a40304")

    def select_adf(self, aid: Hexstr) -> ResTuple:
        """Execute SELECT a given Applicaiton ADF.

        Args:
                aid : application identifier as hex string
        """

        aidlen = ("0" + format(len(aid) // 2, 'x'))[-2:]
        return self.send_apdu_checksw(self.cla_byte + "a4" + "0404" + aidlen + aid + "00")

    def read_binary(self, ef: Path, length: int = None, offset: int = 0) -> ResTuple:
        """Execute READD BINARY.

        Args:
                ef : string or list of strings indicating name or path of transparent EF
                length : number of bytes to read
                offset : byte offset in file from which to start reading
        """
        r = self.select_path(ef)
        if len(r[-1]) == 0:
            return (None, None)
        if length is None:
            length = self.__len(r) - offset
        if length < 0:
            return (None, None)

        total_data = ''
        chunk_offset = 0
        while chunk_offset < length:
            chunk_len = min(self.max_cmd_len, length-chunk_offset)
            pdu = self.cla_byte + \
                'b0%04x%02x' % (offset + chunk_offset, chunk_len)
            try:
                data, sw = self.send_apdu_checksw(pdu)
            except Exception as e:
                e.add_note('failed to read (offset %d)' % offset)
                raise e
            total_data += data
            chunk_offset += chunk_len
        return total_data, sw

    def __verify_binary(self, ef, data: str, offset: int = 0):
        """Verify contents of transparent EF.

        Args:
                ef : string or list of strings indicating name or path of transparent EF
                data : hex string of expected data
                offset : byte offset in file from which to start verifying
        """
        res = self.read_binary(ef, len(data) // 2, offset)
        if res[0].lower() != data.lower():
            raise ValueError('Binary verification failed (expected %s, got %s)' % (
                data.lower(), res[0].lower()))

    def update_binary(self, ef: Path, data: Hexstr, offset: int = 0, verify: bool = False,
                      conserve: bool = False) -> ResTuple:
        """Execute UPDATE BINARY.

        Args:
                ef : string or list of strings indicating name or path of transparent EF
                data : hex string of data to be written
                offset : byte offset in file from which to start writing
                verify : Whether or not to verify data after write
        """

        file_len = self.binary_size(ef)
        data = expand_hex(data, file_len)

        data_length = len(data) // 2

        # Save write cycles by reading+comparing before write
        if conserve:
            try:
                data_current, sw = self.read_binary(ef, data_length, offset)
                if data_current == data:
                    return None, sw
            except Exception:
                # cannot read data. This is not a fatal error, as reading is just done to
                # conserve the amount of smart card writes.  The access conditions of the file
                # may well permit us to UPDATE but not permit us to READ.  So let's ignore
                # any such exception during READ.
                pass

        self.select_path(ef)
        total_data = ''
        chunk_offset = 0
        while chunk_offset < data_length:
            chunk_len = min(self.max_cmd_len, data_length - chunk_offset)
            # chunk_offset is bytes, but data slicing is hex chars, so we need to multiply by 2
            pdu = self.cla_byte + \
                'd6%04x%02x' % (offset + chunk_offset, chunk_len) + \
                data[chunk_offset*2: (chunk_offset+chunk_len)*2]
            try:
                chunk_data, chunk_sw = self.send_apdu_checksw(pdu)
            except Exception as e:
                e.add_note('failed to write chunk (chunk_offset %d, chunk_len %d)' % (chunk_offset, chunk_len))
                raise e
            total_data += data
            chunk_offset += chunk_len
        if verify:
            self.__verify_binary(ef, data, offset)
        return total_data, chunk_sw

    def read_record(self, ef: Path, rec_no: int) -> ResTuple:
        """Execute READ RECORD.

        Args:
                ef : string or list of strings indicating name or path of linear fixed EF
                rec_no : record number to read
        """
        r = self.select_path(ef)
        rec_length = self.__record_len(r)
        pdu = self.cla_byte + 'b2%02x04%02x' % (rec_no, rec_length)
        return self.send_apdu_checksw(pdu)

    def __verify_record(self, ef: Path, rec_no: int, data: str):
        """Verify record against given data

        Args:
                ef : string or list of strings indicating name or path of linear fixed EF
                rec_no : record number to read
                data : hex string of data to be verified
        """
        res = self.read_record(ef, rec_no)
        if res[0].lower() != data.lower():
            raise ValueError('Record verification failed (expected %s, got %s)' % (
                data.lower(), res[0].lower()))

    def update_record(self, ef: Path, rec_no: int, data: Hexstr, force_len: bool = False,
                      verify: bool = False, conserve: bool = False, leftpad: bool = False) -> ResTuple:
        """Execute UPDATE RECORD.

        Args:
                ef : string or list of strings indicating name or path of linear fixed EF
                rec_no : record number to read
                data : hex string of data to be written
                force_len : enforce record length by using the actual data length
                verify : verify data by re-reading the record
                conserve : read record and compare it with data, skip write on match
                leftpad : apply 0xff padding from the left instead from the right side.
        """

        res = self.select_path(ef)
        rec_length = self.__record_len(res)
        data = expand_hex(data, rec_length)

        if force_len:
            # enforce the record length by the actual length of the given data input
            rec_length = len(data) // 2
        else:
            # make sure the input data is padded to the record length using 0xFF.
            # In cases where the input data exceed we throw an exception.
            if len(data) // 2 > rec_length:
                raise ValueError('Data length exceeds record length (expected max %d, got %d)' % (
                    rec_length, len(data) // 2))
            elif len(data) // 2 < rec_length:
                if leftpad:
                    data = lpad(data, rec_length * 2)
                else:
                    data = rpad(data, rec_length * 2)

        # Save write cycles by reading+comparing before write
        if conserve:
            try:
                data_current, sw = self.read_record(ef, rec_no)
                data_current = data_current[0:rec_length*2]
                if data_current == data:
                    return None, sw
            except Exception:
                # cannot read data. This is not a fatal error, as reading is just done to
                # conserve the amount of smart card writes.  The access conditions of the file
                # may well permit us to UPDATE but not permit us to READ.  So let's ignore
                # any such exception during READ.
                pass

        pdu = (self.cla_byte + 'dc%02x04%02x' % (rec_no, rec_length)) + data
        res = self.send_apdu_checksw(pdu)
        if verify:
            self.__verify_record(ef, rec_no, data)
        return res

    def record_size(self, ef: Path) -> int:
        """Determine the record size of given file.

        Args:
                ef : string or list of strings indicating name or path of linear fixed EF
        """
        r = self.select_path(ef)
        return self.__record_len(r)

    def record_count(self, ef: Path) -> int:
        """Determine the number of records in given file.

        Args:
                ef : string or list of strings indicating name or path of linear fixed EF
        """
        r = self.select_path(ef)
        return self.__len(r) // self.__record_len(r)

    def binary_size(self, ef: Path) -> int:
        """Determine the size of given transparent file.

        Args:
                ef : string or list of strings indicating name or path of transparent EF
        """
        r = self.select_path(ef)
        return self.__len(r)

    # TS 102 221 Section 11.3.1 low-level helper
    def _retrieve_data(self, tag: int, first: bool = True) -> ResTuple:
        if first:
            pdu = '80cb008001%02x00' % (tag)
        else:
            pdu = '80cb0000'
        return self.send_apdu_checksw(pdu)

    def retrieve_data(self, ef: Path, tag: int) -> ResTuple:
        """Execute RETRIEVE DATA, see also TS 102 221 Section 11.3.1.

        Args
                ef : string or list of strings indicating name or path of transparent EF
                tag : BER-TLV Tag of value to be retrieved
        """
        r = self.select_path(ef)
        if len(r[-1]) == 0:
            return (None, None)
        total_data = ''
        # retrieve first block
        data, sw = self._retrieve_data(tag, first=True)
        total_data += data
        while sw in ['62f1', '62f2']:
            data, sw = self._retrieve_data(tag, first=False)
            total_data += data
        return total_data, sw

    # TS 102 221 Section 11.3.2 low-level helper
    def _set_data(self, data: Hexstr, first: bool = True) -> ResTuple:
        if first:
            p1 = 0x80
        else:
            p1 = 0x00
        if isinstance(data, (bytes, bytearray)):
            data = b2h(data)
        pdu = '80db00%02x%02x%s' % (p1, len(data)//2, data)
        return self.send_apdu_checksw(pdu)

    def set_data(self, ef, tag: int, value: str, verify: bool = False, conserve: bool = False) -> ResTuple:
        """Execute SET DATA.

        Args
                ef : string or list of strings indicating name or path of transparent EF
                tag : BER-TLV Tag of value to be stored
                value : BER-TLV value to be stored
        """
        r = self.select_path(ef)
        if len(r[-1]) == 0:
            return (None, None)

        # in case of deleting the data, we only have 'tag' but no 'value'
        if not value:
            return self._set_data('%02x' % tag, first=True)

        # FIXME: proper BER-TLV encode
        tl = '%02x%s' % (tag, b2h(bertlv_encode_len(len(value)//2)))
        tlv = tl + value
        tlv_bin = h2b(tlv)

        first = True
        total_len = len(tlv_bin)
        remaining = tlv_bin
        while len(remaining) > 0:
            fragment = remaining[:self.max_cmd_len]
            rdata, sw = self._set_data(fragment, first=first)
            first = False
            remaining = remaining[self.max_cmd_len:]
        return rdata, sw

    def run_gsm(self, rand: Hexstr) -> ResTuple:
        """Execute RUN GSM ALGORITHM.

        Args:
                rand : 16 byte random data as hex string (RAND)
        """
        if len(rand) != 32:
            raise ValueError('Invalid rand')
        self.select_path(['3f00', '7f20'])
        return self.send_apdu_checksw('a088000010' + rand + '00', sw='9000')

    def authenticate(self, rand: Hexstr, autn: Hexstr, context: str = '3g') -> ResTuple:
        """Execute AUTHENTICATE (USIM/ISIM).

        Args:
                rand : 16 byte random data as hex string (RAND)
                autn : 8 byte Autentication Token (AUTN)
                context : 16 byte random data ('3g' or 'gsm')
        """
        # 3GPP TS 31.102 Section 7.1.2.1
        AuthCmd3G = Struct('rand'/LV, 'autn'/COptional(LV))
        AuthResp3GSyncFail = Struct(Const(b'\xDC'), 'auts'/LV)
        AuthResp3GSuccess = Struct(Const(b'\xDB'), 'res'/LV, 'ck'/LV, 'ik'/LV, 'kc'/COptional(LV))
        AuthResp3G = Select(AuthResp3GSyncFail, AuthResp3GSuccess)
        # build parameters
        cmd_data = {'rand': rand, 'autn': autn}
        if context == '3g':
            p2 = '81'
        elif context == 'gsm':
            p2 = '80'
        else:
            raise ValueError("Unsupported context '%s'" % context)
        (data, sw) = self.send_apdu_constr_checksw(
            self.cla_byte, '88', '00', p2, AuthCmd3G, cmd_data, AuthResp3G)
        if 'auts' in data:
            ret = {'synchronisation_failure': data}
        else:
            ret = {'successful_3g_authentication': data}
        return (ret, sw)

    def status(self) -> ResTuple:
        """Execute a STATUS command as per TS 102 221 Section 11.1.2."""
        return self.send_apdu_checksw('80F20000')

    def deactivate_file(self) -> ResTuple:
        """Execute DECATIVATE FILE command as per TS 102 221 Section 11.1.14."""
        return self.send_apdu_constr_checksw(self.cla_byte, '04', '00', '00', None, None, None)

    def activate_file(self, fid: Hexstr) -> ResTuple:
        """Execute ACTIVATE FILE command as per TS 102 221 Section 11.1.15.

        Args:
                fid : file identifier as hex string
        """
        return self.send_apdu_checksw(self.cla_byte + '44000002' + fid)

    def create_file(self, payload: Hexstr) -> ResTuple:
        """Execute CREATE FILE command as per TS 102 222 Section 6.3"""
        return self.send_apdu_checksw(self.cla_byte + 'e00000%02x%s' % (len(payload)//2, payload))

    def resize_file(self, payload: Hexstr) -> ResTuple:
        """Execute RESIZE FILE command as per TS 102 222 Section 6.10"""
        return self.send_apdu_checksw('80d40000%02x%s' % (len(payload)//2, payload))

    def delete_file(self, fid: Hexstr) -> ResTuple:
        """Execute DELETE FILE command as per TS 102 222 Section 6.4"""
        return self.send_apdu_checksw(self.cla_byte + 'e4000002' + fid)

    def terminate_df(self, fid: Hexstr) -> ResTuple:
        """Execute TERMINATE DF command as per TS 102 222 Section 6.7"""
        return self.send_apdu_checksw(self.cla_byte + 'e6000002' + fid)

    def terminate_ef(self, fid: Hexstr) -> ResTuple:
        """Execute TERMINATE EF command as per TS 102 222 Section 6.8"""
        return self.send_apdu_checksw(self.cla_byte + 'e8000002' + fid)

    def terminate_card_usage(self) -> ResTuple:
        """Execute TERMINATE CARD USAGE command as per TS 102 222 Section 6.9"""
        return self.send_apdu_checksw(self.cla_byte + 'fe000000')

    def manage_channel(self, mode: str = 'open', lchan_nr: int =0) -> ResTuple:
        """Execute MANAGE CHANNEL command as per TS 102 221 Section 11.1.17.

        Args:
                mode : logical channel operation code ('open' or 'close')
                lchan_nr : logical channel number (1-19, 0=assigned by UICC)
        """
        if mode == 'close':
            p1 = 0x80
        else:
            p1 = 0x00
        pdu = self.cla_byte + '70%02x%02x' % (p1, lchan_nr)
        return self.send_apdu_checksw(pdu)

    def reset_card(self) -> Hexstr:
        """Physically reset the card"""
        return self._tp.reset_card()

    def _chv_process_sw(self, op_name: str, chv_no: int, pin_code: Hexstr, sw: SwHexstr):
        if sw_match(sw, '63cx'):
            raise RuntimeError('Failed to %s chv_no 0x%02X with code 0x%s, %i tries left.' %
                               (op_name, chv_no, b2h(pin_code).upper(), int(sw[3])))
        if sw != '9000':
            raise SwMatchError(sw, '9000', self._tp.sw_interpreter)

    def verify_chv(self, chv_no: int, code: Hexstr) -> ResTuple:
        """Verify a given CHV (Card Holder Verification == PIN)

        Args:
                chv_no : chv number (1=CHV1, 2=CHV2, ...)
                code : chv code as hex string
        """
        fc = rpad(b2h(code), 16)
        data, sw = self.send_apdu(self.cla_byte + '2000' + ('%02X' % chv_no) + '08' + fc)
        self._chv_process_sw('verify', chv_no, code, sw)
        return (data, sw)

    def unblock_chv(self, chv_no: int, puk_code: str, pin_code: str):
        """Unblock a given CHV (Card Holder Verification == PIN)

        Args:
                chv_no : chv number (1=CHV1, 2=CHV2, ...)
                puk_code : puk code as hex string
                pin_code : new chv code as hex string
        """
        fc = rpad(b2h(puk_code), 16) + rpad(b2h(pin_code), 16)
        data, sw = self.send_apdu(self.cla_byte + '2C00' + ('%02X' % chv_no) + '10' + fc)
        self._chv_process_sw('unblock', chv_no, pin_code, sw)
        return (data, sw)

    def change_chv(self, chv_no: int, pin_code: Hexstr, new_pin_code: Hexstr) -> ResTuple:
        """Change a given CHV (Card Holder Verification == PIN)

        Args:
                chv_no : chv number (1=CHV1, 2=CHV2, ...)
                pin_code : current chv code as hex string
                new_pin_code : new chv code as hex string
        """
        fc = rpad(b2h(pin_code), 16) + rpad(b2h(new_pin_code), 16)
        data, sw = self.send_apdu(self.cla_byte + '2400' + ('%02X' % chv_no) + '10' + fc)
        self._chv_process_sw('change', chv_no, pin_code, sw)
        return (data, sw)

    def disable_chv(self, chv_no: int, pin_code: Hexstr) -> ResTuple:
        """Disable a given CHV (Card Holder Verification == PIN)

        Args:
                chv_no : chv number (1=CHV1, 2=CHV2, ...)
                pin_code : current chv code as hex string
                new_pin_code : new chv code as hex string
        """
        fc = rpad(b2h(pin_code), 16)
        data, sw = self.send_apdu(self.cla_byte + '2600' + ('%02X' % chv_no) + '08' + fc)
        self._chv_process_sw('disable', chv_no, pin_code, sw)
        return (data, sw)

    def enable_chv(self, chv_no: int, pin_code: Hexstr) -> ResTuple:
        """Enable a given CHV (Card Holder Verification == PIN)

        Args:
                chv_no : chv number (1=CHV1, 2=CHV2, ...)
                pin_code : chv code as hex string
        """
        fc = rpad(b2h(pin_code), 16)
        data, sw = self.send_apdu(self.cla_byte + '2800' + ('%02X' % chv_no) + '08' + fc)
        self._chv_process_sw('enable', chv_no, pin_code, sw)
        return (data, sw)

    def envelope(self, payload: Hexstr) -> ResTuple:
        """Send one ENVELOPE command to the SIM

        Args:
                payload : payload as hex string
        """
        return self.send_apdu_checksw('80c20000%02x%s' % (len(payload)//2, payload) + "00", apply_lchan = False)

    def terminal_profile(self, payload: Hexstr) -> ResTuple:
        """Send TERMINAL PROFILE to card

        Args:
                payload : payload as hex string
        """
        data_length = len(payload) // 2
        data, sw = self.send_apdu_checksw(('80100000%02x' % data_length) + payload, apply_lchan = False)
        return (data, sw)

    # ETSI TS 102 221 11.1.22
    def suspend_uicc(self, min_len_secs: int = 60, max_len_secs: int = 43200) -> Tuple[int, Hexstr, SwHexstr]:
        """Send SUSPEND UICC to the card.

        Args:
                 min_len_secs : mimumum suspend time seconds
                 max_len_secs : maximum suspend time seconds
        """
        def encode_duration(secs: int) -> Hexstr:
            if secs >= 10*24*60*60:
                return '04%02x' % (secs // (10*24*60*60))
            if secs >= 24*60*60:
                return '03%02x' % (secs // (24*60*60))
            if secs >= 60*60:
                return '02%02x' % (secs // (60*60))
            if secs >= 60:
                return '01%02x' % (secs // 60)
            return '00%02x' % secs

        def decode_duration(enc: Hexstr) -> int:
            time_unit = enc[:2]
            length = h2i(enc[2:4])[0]
            if time_unit == '04':
                return length * 10*24*60*60
            if time_unit == '03':
                return length * 24*60*60
            if time_unit == '02':
                return length * 60*60
            if time_unit == '01':
                return length * 60
            if time_unit == '00':
                return length
            raise ValueError('Time unit must be 0x00..0x04')
        min_dur_enc = encode_duration(min_len_secs)
        max_dur_enc = encode_duration(max_len_secs)
        data, sw = self.send_apdu_checksw('8076000004' + min_dur_enc + max_dur_enc, apply_lchan = False)
        negotiated_duration_secs = decode_duration(data[:4])
        resume_token = data[4:]
        return (negotiated_duration_secs, resume_token, sw)

    # ETSI TS 102 221 11.1.22
    def resume_uicc(self, token: Hexstr) -> ResTuple:
        """Send SUSPEND UICC (resume) to the card."""
        if len(h2b(token)) != 8:
            raise ValueError("Token must be 8 bytes long")
        data, sw = self.send_apdu_checksw('8076010008' + token, apply_lchan = False)
        return (data, sw)

    # GPC_SPE_034 11.3
    def get_data(self, tag: int, cla: int = 0x00):
        data, sw = self.send_apdu_checksw('%02xca%04x00' % (cla, tag))
        return (data, sw)

    # TS 31.102 Section 7.5.2
    def get_identity(self, context: int) -> Tuple[Hexstr, SwHexstr]:
        data, sw = self.send_apdu_checksw('807800%02x00' % (context))
        return (data, sw)
