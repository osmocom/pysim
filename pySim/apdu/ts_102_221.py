# coding=utf-8
"""APDU definitions/decoders of ETSI TS 102 221, the core UICC spec.

(C) 2022-2024 by Harald Welte <laforge@osmocom.org>

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

from typing import Optional, Dict
import logging

from construct import GreedyRange, Struct

from osmocom.utils import i2h
from osmocom.construct import *

from pySim.filesystem import *
from pySim.runtime import RuntimeLchan
from pySim.apdu import ApduCommand, ApduCommandSet
from pySim import cat

logger = logging.getLogger(__name__)

# TS 102 221 Section 11.1.1
class UiccSelect(ApduCommand, n='SELECT', ins=0xA4, cla=['0X', '4X', '6X']):
    _apdu_case = 4
    _construct_p1 = Enum(Byte, df_ef_or_mf_by_file_id=0, child_df_of_current_df=1, parent_df_of_current_df=3,
                         df_name=4, path_from_mf=8, path_from_current_df=9)
    _construct_p2 = BitStruct(Flag,
                              'app_session_control'/Enum(BitsInteger(2), activation_reset=0, termination=2),
                              'return'/Enum(BitsInteger(3), fcp=1, no_data=3),
                              'aid_control'/Enum(BitsInteger(2), first_or_only=0, last=1, next=2, previous=3))

    @staticmethod
    def _find_aid_substr(selectables, aid) -> Optional[CardADF]:
        # full-length match
        if aid in selectables:
            return selectables[aid]
        # sub-string match
        for s in selectables.keys():
            if aid[:len(s)] == s:
                return selectables[s]
        return None

    def process_on_lchan(self, lchan: RuntimeLchan):
        mode = self.cmd_dict['p1']
        if mode in ['path_from_mf', 'path_from_current_df']:
            # rewind to MF, if needed
            if mode == 'path_from_mf':
                lchan.selected_file = lchan.rs.mf
            path = [self.cmd_data[i:i+2] for i in range(0, len(self.cmd_data), 2)]
            for file in path:
                file_hex = b2h(file)
                if file_hex == '7fff': # current application
                    if not lchan.selected_adf:
                        sels = lchan.rs.mf.get_app_selectables(['ANAMES'])
                        # HACK: Assume USIM
                        logger.warning('SELECT relative to current ADF, but no ADF selected. Assuming ADF.USIM')
                        lchan.selected_adf = sels['ADF.USIM']
                    lchan.selected_file = lchan.selected_adf
                    #print("\tSELECT CUR_ADF %s" % lchan.selected_file)
                    # iterate to next element in path
                    continue
                else:
                    sels = lchan.selected_file.get_selectables(['FIDS','MF','PARENT','SELF'])
                    if file_hex in sels:
                        if self.successful:
                            #print("\tSELECT %s" % sels[file_hex])
                            lchan.selected_file = sels[file_hex]
                        else:
                            #print("\tSELECT %s FAILED" % sels[file_hex])
                            pass
                        # iterate to next element in path
                        continue
                logger.warning('SELECT UNKNOWN FID %s (%s)', file_hex, '/'.join([b2h(x) for x in path]))
        elif mode == 'df_ef_or_mf_by_file_id':
            if len(self.cmd_data) != 2:
                raise ValueError('Expecting a 2-byte FID')
            sels = lchan.selected_file.get_selectables(['FIDS','MF','PARENT','SELF'])
            file_hex = b2h(self.cmd_data)
            if file_hex in sels:
                if self.successful:
                    #print("\tSELECT %s" % sels[file_hex])
                    lchan.selected_file = sels[file_hex]
                else:
                    #print("\tSELECT %s FAILED" % sels[file_hex])
                    pass
            else:
                logger.warning('SELECT UNKNOWN FID %s', file_hex)
        elif mode == 'df_name':
            # Select by AID (can be sub-string!)
            aid = b2h(self.cmd_dict['body'])
            sels = lchan.rs.mf.get_app_selectables(['AIDS'])
            adf = self._find_aid_substr(sels, aid)
            if adf:
                lchan.selected_adf = adf
                lchan.selected_file = lchan.selected_adf
                #print("\tSELECT AID %s" % adf)
            else:
                logger.warning('SELECT UNKNOWN AID %s', aid)
        else:
            raise ValueError('Select Mode %s not implemented' % mode)
        # decode the SELECT response
        if self.successful:
            self.file = lchan.selected_file
            if 'body' in self.rsp_dict:
                # not every SELECT is asking for the FCP in response...
                return lchan.selected_file.decode_select_response(b2h(self.rsp_dict['body']))
        return None



# TS 102 221 Section 11.1.2
class UiccStatus(ApduCommand, n='STATUS', ins=0xF2, cla=['8X', 'CX', 'EX']):
    _apdu_case = 2
    _construct_p1 = Enum(Byte, no_indication=0, current_app_is_initialized=1, terminal_will_terminate_current_app=2)
    _construct_p2 = Enum(Byte, response_like_select=0, response_df_name_tlv=1, response_no_data=0x0c)

    def process_on_lchan(self, lchan):
        if self.cmd_dict['p2'] == 'response_like_select':
            return lchan.selected_file.decode_select_response(b2h(self.rsp_dict['body']))

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

# TS 102 221 Section 11.1.3
class ReadBinary(ApduCommand, n='READ BINARY', ins=0xB0, cla=['0X', '4X', '6X']):
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

# TS 102 221 Section 11.1.4
class UpdateBinary(ApduCommand, n='UPDATE BINARY', ins=0xD6, cla=['0X', '4X', '6X']):
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

# TS 102 221 Section 11.1.5
class ReadRecord(ApduCommand, n='READ RECORD', ins=0xB2, cla=['0X', '4X', '6X']):
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
            return method(self.rsp_data, self.cmd_dict['record_number'])

# TS 102 221 Section 11.1.6
class UpdateRecord(ApduCommand, n='UPDATE RECORD', ins=0xDC, cla=['0X', '4X', '6X']):
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
            return method(self.cmd_data, self.cmd_dict['record_number'])

# TS 102 221 Section 11.1.7
class SearchRecord(ApduCommand, n='SEARCH RECORD', ins=0xA2, cla=['0X', '4X', '6X']):
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

# TS 102 221 Section 11.1.8
class Increase(ApduCommand, n='INCREASE', ins=0x32, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

PinConstructP2 = BitStruct('scope'/Enum(Flag, global_mf=0, specific_df_adf=1),
                           BitsInteger(2), 'reference_data_nr'/BitsInteger(5))
# TS 102 221 Section 11.1.9
class VerifyPin(ApduCommand, n='VERIFY PIN', ins=0x20, cla=['0X', '4X', '6X']):
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
        return bool(sw[0] == 0x63)

    def process_on_lchan(self, _lchan: RuntimeLchan):
        return VerifyPin._pin_process(self)

    def _is_success(self):
        return VerifyPin._pin_is_success(self.sw)


# TS 102 221 Section 11.1.10
class ChangePin(ApduCommand, n='CHANGE PIN', ins=0x24, cla=['0X', '4X', '6X']):
    _apdu_case = 3
    _construct_p2 = PinConstructP2

    def process_on_lchan(self, _lchan: RuntimeLchan):
        return VerifyPin._pin_process(self)

    def _is_success(self):
        return VerifyPin._pin_is_success(self.sw)


# TS 102 221 Section 11.1.11
class DisablePin(ApduCommand, n='DISABLE PIN', ins=0x26, cla=['0X', '4X', '6X']):
    _apdu_case = 3
    _construct_p2 = PinConstructP2

    def process_on_lchan(self, _lchan: RuntimeLchan):
        return VerifyPin._pin_process(self)

    def _is_success(self):
        return VerifyPin._pin_is_success(self.sw)


# TS 102 221 Section 11.1.12
class EnablePin(ApduCommand, n='ENABLE PIN', ins=0x28, cla=['0X', '4X', '6X']):
    _apdu_case = 3
    _construct_p2 = PinConstructP2
    def process_on_lchan(self, _lchan: RuntimeLchan):
        return VerifyPin._pin_process(self)

    def _is_success(self):
        return VerifyPin._pin_is_success(self.sw)


# TS 102 221 Section 11.1.13
class UnblockPin(ApduCommand, n='UNBLOCK PIN', ins=0x2C, cla=['0X', '4X', '6X']):
    _apdu_case = 3
    _construct_p2 = PinConstructP2

    def process_on_lchan(self, _lchan: RuntimeLchan):
        return VerifyPin._pin_process(self)

    def _is_success(self):
        return VerifyPin._pin_is_success(self.sw)


# TS 102 221 Section 11.1.14
class DeactivateFile(ApduCommand, n='DEACTIVATE FILE', ins=0x04, cla=['0X', '4X', '6X']):
    _apdu_case = 1
    _construct_p1 = BitStruct(BitsInteger(4),
                              'select_mode'/Enum(BitsInteger(4), ef_by_file_id=0,
                                                 path_from_mf=8, path_from_current_df=9))

# TS 102 221 Section 11.1.15
class ActivateFile(ApduCommand, n='ACTIVATE FILE', ins=0x44, cla=['0X', '4X', '6X']):
    _apdu_case = 1
    _construct_p1 = DeactivateFile._construct_p1

# TS 102 221 Section 11.1.16
auth_p2_construct = BitStruct('scope'/Enum(Flag, mf=0, df_adf_specific=1),
                              BitsInteger(2),
                              'reference_data_nr'/BitsInteger(5))
class Authenticate88(ApduCommand, n='AUTHENTICATE', ins=0x88, cla=['0X', '4X', '6X']):
    _apdu_case = 4
    _construct_p2 = auth_p2_construct

# TS 102 221 Section 11.1.16
class Authenticate89(ApduCommand, n='AUTHENTICATE', ins=0x89, cla=['0X', '4X', '6X']):
    _apdu_case = 4
    _construct_p2 = auth_p2_construct

# TS 102 221 Section 11.1.17
class ManageChannel(ApduCommand, n='MANAGE CHANNEL', ins=0x70, cla=['0X', '4X', '6X']):
    _apdu_case = 2
    _construct_p1 = Enum(Flag, open_channel=0, close_channel=1)
    _construct_p2 = Struct('logical_channel_number'/Int8ub)
    _construct_rsp = Struct('logical_channel_number'/Int8ub)

    def process_global(self, rs):
        if not self.successful:
            return
        mode = self.cmd_dict['p1']
        if mode == 'open_channel':
            created_channel_nr = self.cmd_dict['p2']['logical_channel_number']
            if created_channel_nr == 0:
                # auto-assignment by UICC
                # pylint: disable=unsubscriptable-object
                created_channel_nr = self.rsp_data[0]
            manage_channel = rs.get_lchan_by_cla(self.cla)
            manage_channel.add_lchan(created_channel_nr)
            self.col_id = '%02u' % created_channel_nr
            return {'mode': mode, 'created_channel': created_channel_nr }
        if mode == 'close_channel':
            closed_channel_nr = self.cmd_dict['p2']['logical_channel_number']
            rs.del_lchan(closed_channel_nr)
            self.col_id = '%02u' % closed_channel_nr
            return {'mode': mode, 'closed_channel': closed_channel_nr }
        raise ValueError('Unsupported MANAGE CHANNEL P1=%02X' % self.p1)

# TS 102 221 Section 11.1.18
class GetChallenge(ApduCommand, n='GET CHALLENGE', ins=0x84, cla=['0X', '4X', '6X']):
    _apdu_case = 2

# TS 102 221 Section 11.1.19
class TerminalCapability(ApduCommand, n='TERMINAL CAPABILITY', ins=0xAA, cla=['8X', 'CX', 'EX']):
    _apdu_case = 3

# TS 102 221 Section 11.1.20
class ManageSecureChannel(ApduCommand, n='MANAGE SECURE CHANNEL', ins=0x73, cla=['0X', '4X', '6X']):
    @classmethod
    def _get_apdu_case(cls, hdr:bytes) -> int:
        p1 = hdr[2]
        p2 = hdr[3]
        if p1 & 0x7 == 0:   # retrieve UICC Endpoints
            return 2
        if p1 & 0xf in [1,2,3]:   # establish sa, start secure channel SA
            p2_cmd = p2 >> 5
            if p2_cmd in [0,2,4]:   # command data
                return 3
            if p2_cmd in [1,3,5]: # response data
                return 2
        if p1 & 0xf == 4:         # terminate secure channel SA
            return 3
        raise ValueError('%s: Unable to detect APDU case for %s' % (cls.__name__, b2h(hdr)))

# TS 102 221 Section 11.1.21
class TransactData(ApduCommand, n='TRANSACT DATA', ins=0x75, cla=['0X', '4X', '6X']):
    @classmethod
    def _get_apdu_case(cls, hdr:bytes) -> int:
        p1 = hdr[2]
        if p1 & 0x04:
            return 3
        return 2

# TS 102 221 Section 11.1.22
class SuspendUicc(ApduCommand, n='SUSPEND UICC', ins=0x76, cla=['80']):
    _apdu_case = 4
    _construct_p1 = BitStruct('rfu'/BitsInteger(7), 'mode'/Enum(Flag, suspend=0, resume=1))

# TS 102 221 Section 11.1.23
class GetIdentity(ApduCommand, n='GET IDENTITY', ins=0x78, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4
    _construct_p2 = BitStruct('scope'/Enum(Flag, mf=0, df_adf_specific=1), BitsInteger(7))

# TS 102 221 Section 11.1.24
class ExchangeCapabilities(ApduCommand, n='EXCHANGE CAPABILITIES', ins=0x7A, cla=['80']):
    _apdu_case = 4

# TS 102 221 Section 11.2.1
class TerminalProfile(ApduCommand, n='TERMINAL PROFILE', ins=0x10, cla=['80']):
    _apdu_case = 3

# TS 102 221 Section 11.2.2 / TS 102 223
class Envelope(ApduCommand, n='ENVELOPE', ins=0xC2, cla=['80']):
    _apdu_case = 4
    _tlv = cat.EventCollection

# TS 102 221 Section 11.2.3 / TS 102 223
class Fetch(ApduCommand, n='FETCH', ins=0x12, cla=['80']):
    _apdu_case = 2
    _tlv_rsp = cat.ProactiveCommand

# TS 102 221 Section 11.2.3 / TS 102 223
class TerminalResponse(ApduCommand, n='TERMINAL RESPONSE', ins=0x14, cla=['80']):
    _apdu_case = 3
    _tlv = cat.TerminalResponse

# TS 102 221 Section 11.3.1
class RetrieveData(ApduCommand, n='RETRIEVE DATA', ins=0xCB, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

    @staticmethod
    def _tlv_decode_cmd(self : ApduCommand) -> Dict:
        c = {}
        if self.p2 & 0xc0 == 0x80:
            c['mode'] = 'first_block'
            sfi = self.p2 & 0x1f
            if sfi == 0:
                c['file'] = 'currently_selected_ef'
            else:
                c['file'] = 'sfi'
                c['sfi'] = sfi
            c['tag'] = i2h([self.cmd_data[0]])
        elif self.p2 & 0xdf == 0x00:
            c['mode'] = 'next_block'
        elif self.p2 & 0xdf == 0x40:
            c['mode'] = 'retransmit_previous_block'
        else:
            logger.warning('%s: invalid P2=%02x', self, self.p2)
        return c

    def _decode_cmd(self):
        return RetrieveData._tlv_decode_cmd(self)

    def _decode_rsp(self):
        # TODO: parse tag/len/val?
        return b2h(self.rsp_data)


# TS 102 221 Section 11.3.2
class SetData(ApduCommand, n='SET DATA', ins=0xDB, cla=['8X', 'CX', 'EX']):
    _apdu_case = 3

    def _decode_cmd(self):
        c = RetrieveData._tlv_decode_cmd(self)
        if c['mode'] == 'first_block':
            if len(self.cmd_data) == 0:
                c['delete'] = True
        # TODO: parse tag/len/val?
        c['data'] = b2h(self.cmd_data)
        return c


# TS 102 221 Section 12.1.1
class GetResponse(ApduCommand, n='GET RESPONSE', ins=0xC0, cla=['0X', '4X', '6X']):
    _apdu_case = 2

ApduCommands = ApduCommandSet('TS 102 221', cmds=[UiccSelect, UiccStatus, ReadBinary, UpdateBinary, ReadRecord,
                              UpdateRecord, SearchRecord, Increase, VerifyPin, ChangePin, DisablePin,
                              EnablePin, UnblockPin, DeactivateFile, ActivateFile, Authenticate88,
                              Authenticate89, ManageChannel, GetChallenge, TerminalCapability,
                              ManageSecureChannel, TransactData, SuspendUicc, GetIdentity,
                              ExchangeCapabilities, TerminalProfile, Envelope, Fetch, TerminalResponse,
                              RetrieveData, SetData, GetResponse])
