# coding=utf-8
"""APDU definitions/decoders of 3GPP TS 51.011, the classic SIM spec.

(C) 2022 by Harald Welte <laforge@osmocom.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import logging
from construct import GreedyRange, Struct
from pySim.construct import *
from pySim.filesystem import *
from pySim.runtime import RuntimeLchan
from pySim.apdu import ApduCommand, ApduCommandSet
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)

# TS 51.011 Section 9.2.1
class SimSelect(ApduCommand, n='SELECT', ins=0xA4, cla=['A0']):
    _apdu_case = 4

    def process_on_lchan(self, lchan: RuntimeLchan):
        path = [self.cmd_data[i:i+2] for i in range(0, len(self.cmd_data), 2)]
        for file in path:
            file_hex = b2h(file)
            sels = lchan.selected_file.get_selectables(['FIDS'])
            if file_hex in sels:
                if self.successful:
                    #print("\tSELECT %s" % sels[file_hex])
                    lchan.selected_file = sels[file_hex]
                else:
                    #print("\tSELECT %s FAILED" % sels[file_hex])
                    pass
                continue
        logger.warning('SELECT UNKNOWN FID %s (%s)' % (file_hex, '/'.join([b2h(x) for x in path])))
        if len(self.cmd_data) != 2:
            raise ValueError('Expecting a 2-byte FID')

        # decode the SELECT response
        if self.successful:
            self.file = lchan.selected_file
            if 'body' in self.rsp_dict:
                # not every SELECT is asking for the FCP in response...
                return lchan.selected_file.decode_select_response(self.rsp_dict['body'])
        return None


# TS 51.011 Section 9.2.2
class SimStatus(ApduCommand, n='STATUS', ins=0xF2, cla=['A0']):
    _apdu_case = 2

    def process_on_lchan(self, lchan):
        if self.successful:
            if 'body' in self.rsp_dict:
                return lchan.selected_file.decode_select_response(self.rsp_dict['body'])

def _decode_binary_p1p2(p1, p2) -> Dict:
    ret = {}
    if p1 & 0x80:
        ret['file'] = 'sfi'
        ret['sfi'] = p1 & 0x1f
        ret['offset'] = p2
    else:
        ret['file'] = 'currently_selected_ef'
        ret['offset'] = ((p1 & 0x7f) << 8) & p2
    return ret

# TS 51.011 Section 9.2.3 / 31.101
class ReadBinary(ApduCommand, n='READ BINARY', ins=0xB0, cla=['A0']):
    _apdu_case = 2
    def _decode_p1p2(self):
        return _decode_binary_p1p2(self.p1, self.p2)

    def process_on_lchan(self, lchan):
        self._determine_file(lchan)
        if not isinstance(self.file, TransparentEF):
            return b2h(self.rsp_data)
        # our decoders don't work for non-zero offsets / short reads
        if self.cmd_dict['offset'] != 0 or self.lr < self.file.size[0]:
            return b2h(self.rsp_data)
        method = getattr(self.file, 'decode_bin', None)
        if self.successful and callable(method):
            return method(self.rsp_data)

# TS 51.011 Section 9.2.4 / 31.101
class UpdateBinary(ApduCommand, n='UPDATE BINARY', ins=0xD6, cla=['A0']):
    _apdu_case = 3
    def _decode_p1p2(self):
        return _decode_binary_p1p2(self.p1, self.p2)

    def process_on_lchan(self, lchan):
        self._determine_file(lchan)
        if not isinstance(self.file, TransparentEF):
            return b2h(self.rsp_data)
        # our decoders don't work for non-zero offsets / short writes
        if self.cmd_dict['offset'] != 0 or self.lc < self.file.size[0]:
            return b2h(self.cmd_data)
        method = getattr(self.file, 'decode_bin', None)
        if self.successful and callable(method):
            return method(self.cmd_data)

def _decode_record_p1p2(p1, p2):
    ret = {}
    ret['record_number'] = p1
    if p2 >> 3 == 0:
        ret['file'] = 'currently_selected_ef'
    else:
        ret['file'] = 'sfi'
        ret['sfi'] = p2 >> 3
    mode = p2 & 0x7
    if mode == 2:
        ret['mode'] = 'next_record'
    elif mode == 3:
        ret['mode'] = 'previous_record'
    elif mode == 8:
        ret['mode'] = 'absolute_current'
    return ret

# TS 51.011 Section 9.2.5
class ReadRecord(ApduCommand, n='READ RECORD', ins=0xB2, cla=['A0']):
    _apdu_case = 2
    def _decode_p1p2(self):
        r = _decode_record_p1p2(self.p1, self.p2)
        self.col_id = '%02u' % r['record_number']
        return r

    def process_on_lchan(self, lchan):
        self._determine_file(lchan)
        if not isinstance(self.file, LinFixedEF):
            return b2h(self.rsp_data)
        method = getattr(self.file, 'decode_record_bin', None)
        if self.successful and callable(method):
            return method(self.rsp_data)

# TS 51.011 Section 9.2.6
class UpdateRecord(ApduCommand, n='UPDATE RECORD', ins=0xDC, cla=['A0']):
    _apdu_case = 3
    def _decode_p1p2(self):
        r = _decode_record_p1p2(self.p1, self.p2)
        self.col_id = '%02u' % r['record_number']
        return r

    def process_on_lchan(self, lchan):
        self._determine_file(lchan)
        if not isinstance(self.file, LinFixedEF):
            return b2h(self.cmd_data)
        method = getattr(self.file, 'decode_record_bin', None)
        if self.successful and callable(method):
            return method(self.cmd_data)

# TS 51.011 Section 9.2.7
class Seek(ApduCommand, n='SEEK', ins=0xA2, cla=['A0']):
    _apdu_case = 4
    _construct_rsp = GreedyRange(Int8ub)

    def _decode_p1p2(self):
        ret = {}
        sfi = self.p2 >> 3
        if sfi == 0:
            ret['file'] = 'currently_selected_ef'
        else:
            ret['file'] = 'sfi'
            ret['sfi'] = sfi
        mode = self.p2 & 0x7
        if mode in [0x4, 0x5]:
            if mode == 0x4:
                ret['mode'] = 'forward_search'
            else:
                ret['mode'] = 'backward_search'
            ret['record_number'] = self.p1
            self.col_id = '%02u' % ret['record_number']
        elif mode == 6:
            ret['mode'] = 'enhanced_search'
            # TODO: further decode
        elif mode == 7:
            ret['mode'] = 'proprietary_search'
        return ret

    def _decode_cmd(self):
        ret = self._decode_p1p2()
        if self.cmd_data:
            if ret['mode'] == 'enhanced_search':
                ret['search_indication'] = b2h(self.cmd_data[:2])
                ret['search_string'] = b2h(self.cmd_data[2:])
            else:
                ret['search_string'] = b2h(self.cmd_data)
        return ret

    def process_on_lchan(self, lchan):
        self._determine_file(lchan)
        return self.to_dict()

# TS 51.011 Section 9.2.8
class Increase(ApduCommand, n='INCREASE', ins=0x32, cla=['A0']):
    _apdu_case = 4

PinConstructP2 = BitStruct('scope'/Enum(Flag, global_mf=0, specific_df_adf=1),
                           BitsInteger(2), 'reference_data_nr'/BitsInteger(5))

# TS 51.011 Section 9.2.9
class VerifyChv(ApduCommand, n='VERIFY CHV', ins=0x20, cla=['A0']):
    _apdu_case = 3
    _construct_p2 = PinConstructP2

    @staticmethod
    def _pin_process(apdu):
        processed = {
            'scope': apdu.cmd_dict['p2']['scope'],
            'referenced_data_nr': apdu.cmd_dict['p2']['reference_data_nr'],
            }
        if apdu.lc == 0:
            # this is just a question on the counters remaining
            processed['mode'] = 'check_remaining_attempts'
        else:
            processed['pin'] = b2h(apdu.cmd_data)
        if apdu.sw[0] == 0x63:
            processed['remaining_attempts'] = apdu.sw[1] & 0xf
        return processed

    @staticmethod
    def _pin_is_success(sw):
        if sw[0] == 0x63:
            return True
        else:
            return False

    def process_on_lchan(self, lchan: RuntimeLchan):
        return VerifyChv._pin_process(self)

    def _is_success(self):
        return VerifyChv._pin_is_success(self.sw)


# TS 51.011 Section 9.2.10
class ChangeChv(ApduCommand, n='CHANGE CHV', ins=0x24, cla=['A0']):
    _apdu_case = 3
    _construct_p2 = PinConstructP2

    def process_on_lchan(self, lchan: RuntimeLchan):
        return VerifyChv._pin_process(self)

    def _is_success(self):
        return VerifyChv._pin_is_success(self.sw)


# TS 51.011 Section 9.2.11
class DisableChv(ApduCommand, n='DISABLE CHV', ins=0x26, cla=['A0']):
    _apdu_case = 3
    _construct_p2 = PinConstructP2

    def process_on_lchan(self, lchan: RuntimeLchan):
        return VerifyChv._pin_process(self)

    def _is_success(self):
        return VerifyChv._pin_is_success(self.sw)


# TS 51.011 Section 9.2.12
class EnableChv(ApduCommand, n='ENABLE CHV', ins=0x28, cla=['A0']):
    _apdu_case = 3
    _construct_p2 = PinConstructP2
    def process_on_lchan(self, lchan: RuntimeLchan):
        return VerifyChv._pin_process(self)

    def _is_success(self):
        return VerifyChv._pin_is_success(self.sw)


# TS 51.011 Section 9.2.13
class UnblockChv(ApduCommand, n='UNBLOCK CHV', ins=0x2C, cla=['A0']):
    _apdu_case = 3
    _construct_p2 = PinConstructP2

    def process_on_lchan(self, lchan: RuntimeLchan):
        return VerifyChv._pin_process(self)

    def _is_success(self):
        return VerifyChv._pin_is_success(self.sw)


# TS 51.011 Section 9.2.14
class Invalidate(ApduCommand, n='INVALIDATE', ins=0x04, cla=['A0']):
    _apdu_case = 1
    _construct_p1 = BitStruct(BitsInteger(4),
                              'select_mode'/Enum(BitsInteger(4), ef_by_file_id=0,
                                                 path_from_mf=8, path_from_current_df=9))

# TS 51.011 Section 9.2.15
class Rehabilitate(ApduCommand, n='REHABILITATE', ins=0x44, cla=['A0']):
    _apdu_case = 1
    _construct_p1 = Invalidate._construct_p1

# TS 51.011 Section 9.2.16
class RunGsmAlgorithm(ApduCommand, n='RUN GSM ALGORITHM', ins=0x88, cla=['A0']):
    _apdu_case = 4
    _construct = Struct('rand'/HexAdapter(Bytes(16)))
    _construct_rsp = Struct('sres'/HexAdapter(Bytes(4)), 'kc'/HexAdapter(Bytes(8)))

# TS 51.011 Section 9.2.17
class Sleep(ApduCommand, n='SLEEP', ins=0xFA, cla=['A0']):
    _apdu_case = 2

# TS 51.011 Section 9.2.18
class GetResponse(ApduCommand, n='GET RESPONSE', ins=0xC0, cla=['A0']):
    _apdu_case = 2

# TS 51.011 Section 9.2.19
class TerminalProfile(ApduCommand, n='TERMINAL PROFILE', ins=0x10, cla=['A0']):
    _apdu_case = 3

# TS 51.011 Section 9.2.20
class Envelope(ApduCommand, n='ENVELOPE', ins=0xC2, cla=['A0']):
    _apdu_case = 4

# TS 51.011 Section 9.2.21
class Fetch(ApduCommand, n='FETCH', ins=0x12, cla=['A0']):
    _apdu_case = 2

# TS 51.011 Section 9.2.22
class TerminalResponse(ApduCommand, n='TERMINAL RESPONSE', ins=0x14, cla=['A0']):
    _apdu_case = 3


ApduCommands = ApduCommandSet('TS 51.011', cmds=[SimSelect, SimStatus, ReadBinary, UpdateBinary, ReadRecord,
                              UpdateRecord, Seek, Increase, VerifyChv, ChangeChv, DisableChv,
                              EnableChv, UnblockChv, Invalidate, Rehabilitate, RunGsmAlgorithm,
                              Sleep, GetResponse, TerminalProfile, Envelope, Fetch, TerminalResponse])
