"""Code related to SIM/UICC OTA according to TS 102 225 + TS 31.115."""

# (C) 2021-2024 by Harald Welte <laforge@osmocom.org>
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

import zlib
import abc
import struct
from typing import Optional, Tuple, List, Union
from construct import ConstructError, Enum, Int8ub, Int16ub, Struct, BitsInteger, BitStruct
from construct import Flag, Padding, Switch, this, PrefixedArray, GreedyRange
from construct import Const, Prefixed, Select, Construct, SizeofError, stream_read, stream_write
from osmocom.construct import *
from osmocom.tlv import bertlv_encode_len
from osmocom.utils import b2h

from pySim.sms import UserDataHeader

# ETS TS 102 225 gives the general command structure and the dialects for CAT_TP, TCP/IP and HTTPS
# 3GPP TS 31.115 gives the dialects for SMS-PP, SMS-CB, USSD and HTTP

# CPI CPL CHI CHL SPI KIc KID TAR CNTR PCNTR RC/CC/DS data

#                                           CAT_TP  TCP/IP          SMS
# CPI                                       0x01    0x01            =IEIa=70,len=0
# CHI                                       NULL    NULL            NULL
# CPI, CPL and CHL included in RC/CC/DS     true    true
# RPI                                       0x02    0x02            =IEIa=71,len=0
# RHI                                       NULL    NULL
# RPI, RPL and RHL included in RC/CC/DS     true    true
# packet-id                             0-bf,ff     0-bf,ff
# identification packet                     false   102 225 tbl 6

# KVN 1..f; KI1=KIc, KI2=KID, KI3=DEK

# ETSI TS 102 225 Table 5 + 3GPP TS 31.115 Section 7
ResponseStatus = Enum(Int8ub, por_ok=0, rc_cc_ds_failed=1, cntr_low=2, cntr_high=3,
                      cntr_blocked=4, ciphering_error=5, undefined_security_error=6,
                      insufficient_memory=7, more_time_needed=8, tar_unknown=9,
                      insufficient_security_level=0x0A,
                      actual_response_sms_submit=0x0B,
                      actual_response_ussd=0x0C)

# ETSI TS 102 226 Section 5.1.2
CompactRemoteResp = Struct('number_of_commands'/Int8ub,
                           'last_status_word'/HexAdapter(Bytes(2)),
                           'last_response_data'/HexAdapter(GreedyBytes))

######################################################################
# Expanded Remote Application data format, ETSI TS 102 226 V19.0.0 (2025-11) Section 5.2
#   5.2.1   Expanded Remote command structure
#   5.2.1.1 C-APDU TLV
#   5.2.1.2 Immediate Action TLV
#   5.2.1.3 Error Action TLV
#   5.2.1.4 Script Chaining TLV
#   5.2.2   Expanded Remote response structure (tables 5.10 .. 5.16)
#
# definite length coding and indefinite length coding are supported.
#
# BER-TLV tag values from ETSI TS 101 220 V19.0.0 tables 7.18, 7.19, 7.20
# C-APDU / R-APDU ETSI TS 102 223 Section 8.35 + 8.36
# inside these the CR flag of the tag is 0 (TS 101 220 tables 7.19/7.20),
# so tag bytes are 22 and 23 and not A2/A3.
#
# This layer sits above the TS 102 225 security layer.
######################################################################

class BerTlvLength(Construct):
    """A definite-length BER-TLV length field used by the "expanded remote
    application data format" from ISO/IEC 8825-1 referenced by TS 102 226 5.2

    - short form (0..127 -> single octet)
    - long form (128.. -> 0x8N followed by N length octets)
    Indefinite length coding (first octet 0x80, TS 102 226 tables 5.2a/5.10a)
    is omitted here because it is only recommended for HTTPS/CoAP transport, not SMS."""
    def _parse(self, stream, context, path):
        first = stream_read(stream, 1, path)[0]
        if first < 0x80:
            return first
        num_octets = first & 0x7f
        if num_octets == 0:
            raise NotImplementedError('indefinite coding is not supported')
        return int.from_bytes(stream_read(stream, num_octets, path), 'big')

    def _build(self, obj, stream, context, path):
        encoded = bertlv_encode_len(obj)
        stream_write(stream, encoded, len(encoded), path)
        return obj

    def _sizeof(self, context, path):
        raise SizeofError('BER-TLV length has a variable size?!')

BerTlvLen = BerTlvLength()

class _RApduValueAdapter(Adapter):
    """Split/join value of R-APDU COMPREHENSION-TLV TS 102 223 8.36
      [R-APDU data (x-2 bytes)] SW1 SW2."""
    def _decode(self, obj, context, path):
        raw = bytes(obj)
        return Container(response_data=b2h(raw[:-2]), status_word=b2h(raw[-2:]))

    def _encode(self, obj, context, path):
        return h2b(obj['response_data']) + h2b(obj['status_word'])

#### Command Scripting template TS 102 226 tables 5.2 / 5.2a, TS 101 220 tables 7.18/7.19
#
# The two TS 101 220 table 7.18 length codings use different template tags:
# - definite tag AA
# - indefinite AE
# In both codings the inner Command TLVs use definite length coding, only the
# surrounding template differs.

# TS 102 223 8.35
ExpandedC_APDU = Struct('_tag'/Const(b'\x22'),
                        'c_apdu'/Prefixed(BerTlvLen, HexAdapter(GreedyBytes)))

# shared by both length codings.
ExpandedCmdItems = GreedyRange(ExpandedC_APDU)

# TS 102 226 table 5.2: Command Scripting template, definite length coding only
ExpandedCmd = Struct('_tag'/Const(b'\xaa'),
                     'commands'/Prefixed(BerTlvLen, ExpandedCmdItems))

# TS 102 226 table 5.2a: indefinite length coding, 'AE 80 <C-APDU TLVs> 00 00'. GreedyRange
# stops at the first octet that is not a C-APDU tag, which is the end-of-contents marker.
ExpandedCmdIndef = Struct('_tag'/Const(b'\xae'), '_indef'/Const(b'\x80'),
                          'commands'/ExpandedCmdItems, '_eoc'/Const(b'\x00\x00'))

#### Response Scripting template TS 102 226 5.2.2, tables 5.10-5.16, TS 101 220 table 7.20

# TS 102 223 8.36
ExpandedR_APDU = Struct('_tag'/Const(b'\x23'),
                        'r_apdu'/Prefixed(BerTlvLen, _RApduValueAdapter(GreedyBytes)))

# TS 102 226 table 5.11
# Value is an integer per ISO/IEC 8825-1, likely just one octet.
ExpandedNumExecuted = Struct('_tag'/Const(b'\x80'),
                             'number_of_commands'/Prefixed(BerTlvLen, GreedyInteger()))

# TS 102 226 table 5.12
ExpandedBadFormat = Struct('_tag'/Const(b'\x90'),
                           'bad_format'/Prefixed(BerTlvLen,
                               Enum(Int8ub, unknown_tag=1, wrong_length=2, length_not_found=3)))

# TS 102 226 table 5.14
ExpandedImmediateActionResp = Struct('_tag'/Const(b'\x81'),
                                     'immediate_action_response'/Prefixed(BerTlvLen,
                                         Enum(Int8ub, suspension_error=1)))

# TS 102 226 table 5.16
ExpandedScriptChainingResp = Struct('_tag'/Const(b'\x83'),
                                    'script_chaining_response'/Prefixed(BerTlvLen,
                                        Enum(Int8ub, no_previous_script=1,
                                             not_supported=2, unable_to_process=3)))

# response TLVs shared by the def and indef Response Scripting templates
ExpandedRespItems = GreedyRange(Select(ExpandedR_APDU,
                                       ExpandedBadFormat,
                                       ExpandedImmediateActionResp,
                                       ExpandedScriptChainingResp))

# - starts with the "Number of executed command TLV objects" (table 5.10/5.13/5.15)
# - followed by a sequence of R-APDU TLVs
# - and/or one of the error # response TLVs
ExpandedRemoteResp = Struct('_tag'/Const(b'\xab'),
                            'body'/Prefixed(BerTlvLen, Struct(
                                'num_executed'/ExpandedNumExecuted,
                                'responses'/ExpandedRespItems)))

# TS 102 226 table 5.10a: indefinite length coding, no "number of executed" TLV
ExpandedRemoteRespIndef = Struct('_tag'/Const(b'\xaf'), '_indef'/Const(b'\x80'),
                                 'responses'/ExpandedRespItems, '_eoc'/Const(b'\x00\x00'))


def encode_expanded_cmd(apdus: Union[bytes, List[bytes]],
                        length_coding: str = 'definite') -> bytes:
    """builds the Command Scripting template, TS 102 226 5.2.1

    Args:
        apdus: single C-APDU bytes or list of C-APDUs bytes. Each
               C-APDU is wrapped into a C-APDU TLV- This function does not add
               or modify Le.
        length_coding: 'definite' (the default, tag 'AA', table 5.2) or
               'indefinite' (tag 'AE', table 5.2a: 'AE 80 <cmd TLVs> 00 00').
               Inner C-APDU TLVs use definite length coding in both cases.
    Returns:
        encoded Command Scripting template as bytes
    """
    if isinstance(apdus, (bytes, bytearray)):
        apdus = [apdus]
    commands = [{'c_apdu': b2h(a)} for a in apdus]
    if length_coding == 'definite':
        return ExpandedCmd.build({'commands': commands})
    if length_coding == 'indefinite':
        return ExpandedCmdIndef.build({'commands': commands})
    raise ValueError("Invalid length_coding: %r" % length_coding)


def decode_expanded_resp(data: bytes) -> Container:
    """Decode a Response Scripting template, TS 102 226 5.2.2 def and indef length
    coding

    returned Container has:
        number_of_commands   -- "number of executed command TLV objects" table 5.11
                                 for definite coding. indefinite coding does not have
                                 this TLV, so report the number of returned R-APDUs instead.
        commands             -- list of Containers, one per R-APDU TLV, each
                                with 'response_data' and 'status_word' hexstr
        last_response_data   -- response_data of the last R-APDU or ''
        last_status_word     -- status_word of the last R-APDU or None
        truncated            -- True if any R-APDU has SW 62F1.
                                5.2.1.1 states card sets that status when it had to truncate
                                C-APDU response data, and "this shall terminate the
                                processing of the command list".
                                so the response is short AND the remaining commands never ran.
        bad_format           -- error type of a trailing Bad format TLV if present
        immediate_action_response -- Immediate Action Response TLV, if there was a suspension error
        script_chaining_response  -- Script Chaining Response TLV, if there was a chaining error

    The 'last_response_data'/'last_status_word'/'number_of_commands' keys are compatible with
    CompactRemoteResp so existing callers keep working."""
    if isinstance(data, str):
        data = h2b(data)
    try:
        if data[:1] == b'\xaf':
            responses = ExpandedRemoteRespIndef.parse(data)['responses']
            num_executed = None
        else:
            parsed = ExpandedRemoteResp.parse(data)
            responses = parsed['body']['responses']
            num_executed = parsed['body']['num_executed']['number_of_commands']
    except ConstructError as e:
        raise ValueError('malformed Response Scripting template: %s' % e) from e

    commands = []
    bad_format = None
    immediate_action_response = None
    script_chaining_response = None
    for item in responses:
        if 'r_apdu' in item:
            commands.append(Container(response_data=item['r_apdu']['response_data'],
                                      status_word=item['r_apdu']['status_word']))
        elif 'bad_format' in item:
            bad_format = item['bad_format']
        elif 'immediate_action_response' in item:
            immediate_action_response = item['immediate_action_response']
        elif 'script_chaining_response' in item:
            script_chaining_response = item['script_chaining_response']
    # TS 102 226 5.2.1.1: 62F1 means response of a C-APDU was truncated, processing terminated
    truncated = any(c['status_word'].lower() == '62f1' for c in commands)
    return Container(number_of_commands=num_executed if num_executed is not None else len(commands),
                     commands=commands,
                     last_response_data=commands[-1]['response_data'] if commands else '',
                     last_status_word=commands[-1]['status_word'] if commands else None,
                     truncated=truncated,
                     bad_format=bad_format,
                     immediate_action_response=immediate_action_response,
                     script_chaining_response=script_chaining_response)

RC_CC_DS = Enum(BitsInteger(2), no_rc_cc_ds=0, rc=1, cc=2, ds=3)
CNTR_REQ = Enum(BitsInteger(2), no_counter=0, counter_no_replay_or_seq=1, counter_must_be_higher=2, counter_must_be_lower=3)
POR_REQ = Enum(BitsInteger(2), no_por=0, por_required=1, por_only_when_error=2)

# TS 102 225 Section 5.1.1 + TS 31.115 Section 4.2
SPI = BitStruct(  # first octet
    Padding(3),
    'counter'/CNTR_REQ,
    'ciphering'/Flag,
    'rc_cc_ds'/RC_CC_DS,
    # second octet
    Padding(2),
    'por_in_submit'/Flag,
    'por_shall_be_ciphered'/Flag,
    'por_rc_cc_ds'/RC_CC_DS,
    'por'/POR_REQ
)

# TS 102 225 Section 5.1.2
KIC = BitStruct('key'/BitsInteger(4),
                'algo'/Enum(BitsInteger(4), implicit=0, single_des=1, triple_des_cbc2=5, triple_des_cbc3=9,
                            aes_cbc=2)
                )

# TS 102 225 Section 5.1.3.1
KID_CC = BitStruct('key'/BitsInteger(4),
                   'algo'/Enum(BitsInteger(4), implicit=0, single_des=1, triple_des_cbc2=5, triple_des_cbc3=9,
                               aes_cmac=2)
                   )

# TS 102 225 Section 5.1.3.2
KID_RC = BitStruct('key'/BitsInteger(4),
                   'algo'/Enum(BitsInteger(4), implicit=0, crc16=1, crc32=5, proprietary=3)
                   )

SmsCommandPacket = Struct('cmd_pkt_len'/Int16ub,
                          'cmd_hdr_len'/Int8ub,
                          'spi'/SPI,
                          'kic'/KIC,
                          'kid'/Switch(this.spi.rc_cc_ds, {'cc': KID_CC, 'rc': KID_RC }),
                          'tar'/Bytes(3),
                          'secured_data'/GreedyBytes)

# TS 102 226 Section 8.2.1.3.2.1
SimFileAccessAndToolkitAppSpecParams = Struct('access_domain'/Prefixed(Int8ub, GreedyBytes),
                                              'prio_level_of_tk_app_inst'/Int8ub,
                                              'max_num_of_timers'/Int8ub,
                                              'max_text_length_for_menu_entry'/Int8ub,
                                              'menu_entries'/PrefixedArray(Int8ub, Struct('id'/Int8ub,
                                                                                          'pos'/Int8ub)),
                                              'max_num_of_channels'/Int8ub,
                                              'msl'/Prefixed(Int8ub, GreedyBytes),
                                              'tar_values'/Prefixed(Int8ub, GreedyRange(Bytes(3))))

class OtaKeyset:
    """The OTA related data (key material, counter) to be used in encrypt/decrypt."""
    def __init__(self, algo_crypt: str, kic_idx: int, kic: bytes,
                 algo_auth: str, kid_idx: int, kid: bytes, cntr: int = 0):
        self.algo_crypt = algo_crypt
        self.kic = bytes(kic)
        self.kic_idx = kic_idx
        self.algo_auth = algo_auth
        self.kid = bytes(kid)
        self.kid_idx = kid_idx
        self.cntr = cntr

    @property
    def auth(self):
        """Return an instance of the matching OtaAlgoAuth."""
        return OtaAlgoAuth.from_keyset(self)

    @property
    def crypt(self):
        """Return an instance of the matching OtaAlgoCrypt."""
        return OtaAlgoCrypt.from_keyset(self)

class OtaCheckError(Exception):
    pass

class OtaDialect(abc.ABC):
    """Base Class for OTA dialects such as SMS, BIP, ..."""

    def _compute_sig_len(self, spi:SPI):
        if spi['rc_cc_ds'] == 'no_rc_cc_ds':
            return 0
        if spi['rc_cc_ds'] == 'rc': # CRC-32
            return 4
        if spi['rc_cc_ds'] == 'cc': # Cryptographic Checksum (CC)
            # TODO: this is not entirely correct, as in AES case it could be 4 or 8
            return 8
        raise ValueError("Invalid rc_cc_ds: %s" % spi['rc_cc_ds'])

    @abc.abstractmethod
    def encode_cmd(self, otak: OtaKeyset, tar: bytes, spi: dict,
                   apdu: Union[bytes, List[bytes]], remote_format: str = 'compact') -> bytes:
        """Encode a command for a format.

        remote_format:
        'compact' TS 102 226 5.1, DEFAULT assumes apdus are opaque already-concatenated command strings
        'expanded' TS 102 226 5.2 wraps a single C-APDU or list of C-APDUs in a Command Scripting template."""
        pass

    @abc.abstractmethod
    def decode_resp(self, otak: OtaKeyset, spi: dict, apdu: bytes,
                    remote_format: str = 'compact') -> (object, Optional[object]):
        """Decode response into response packet + a decoded response if por_ok.

        remote_format:
        'compact' -> DEFAULT TS 102 226 5.1.2 CompactRemoteResp2
        'expanded' -> container returned by decode_expanded_resp(), TS 102 226 5.2.2

        The response packet's common characteristics are not fully determined,
        and (so far) completely proprietary per dialect."""


from Cryptodome.Cipher import DES, DES3, AES
from Cryptodome.Hash import CMAC

class OtaAlgo(abc.ABC):
    iv = property(lambda self: bytes([0] * self.blocksize))
    blocksize = None
    enum_name = None

    @staticmethod
    def _get_padding(in_len: int, multiple: int, padding: int = 0):
        """Return padding bytes towards multiple of N."""
        if in_len % multiple == 0:
            return b''
        pad_cnt = multiple - (in_len % multiple)
        return b'\x00' * pad_cnt

    @staticmethod
    def _pad_to_multiple(indat: bytes, multiple: int, padding: int = 0):
        """Pad input bytes to multiple of N."""
        return indat + OtaAlgo._get_padding(len(indat), multiple, padding)

    def pad_to_blocksize(self, indat: bytes, padding: int = 0):
        """Pad the given input data to multiple of the cipher block size."""
        return self._pad_to_multiple(indat, self.blocksize, padding)

    def __init__(self, otak: OtaKeyset):
        self.otak = otak

    def __str__(self):
        return self.__class__.__name__

class OtaAlgoCrypt(OtaAlgo, abc.ABC):
    def __init__(self, otak: OtaKeyset):
        if self.enum_name != otak.algo_crypt:
            raise ValueError('Cannot use algorithm %s with key for %s' % (self.enum_name, otak.algo_crypt))
        super().__init__(otak)

    def encrypt(self, data:bytes) -> bytes:
        """Encrypt given input bytes using the key material given in constructor."""
        padded_data = self.pad_to_blocksize(data)
        return self._encrypt(padded_data)

    def decrypt(self, data:bytes) -> bytes:
        """Decrypt given input bytes using the key material given in constructor."""
        return self._decrypt(data)

    @abc.abstractmethod
    def _encrypt(self, data:bytes) -> bytes:
        """Actual implementation, to be implemented by derived class."""

    @abc.abstractmethod
    def _decrypt(self, data:bytes) -> bytes:
        """Actual implementation, to be implemented by derived class."""

    @classmethod
    def from_keyset(cls, otak: OtaKeyset) -> 'OtaAlgoCrypt':
        """Resolve the class for the encryption algorithm of otak and instantiate it."""
        for subc in cls.__subclasses__():
            if subc.enum_name == otak.algo_crypt:
                return subc(otak)
        raise ValueError('No implementation for crypt algorithm %s' % otak.algo_crypt)

class OtaAlgoAuth(OtaAlgo, abc.ABC):
    def __init__(self, otak: OtaKeyset):
        if self.enum_name != otak.algo_auth:
            raise ValueError('Cannot use algorithm %s with key for %s' % (self.enum_name, otak.algo_auth))
        super().__init__(otak)

    def sign(self, data:bytes) -> bytes:
        """Compute the CC/CR check bytes for the input data using key material
        given in constructor."""
        padded_data = self.pad_to_blocksize(data)
        sig = self._sign(padded_data)
        return sig

    def check_sig(self, data:bytes, cc_received:bytes):
        """Compute the CC/CR check bytes for the input data and compare against cc_received."""
        cc = self.sign(data)
        if cc_received != cc:
            raise OtaCheckError('Received CC (%s) != Computed CC (%s)' % (b2h(cc_received), b2h(cc)))

    @abc.abstractmethod
    def _sign(self, data:bytes) -> bytes:
        """Actual implementation, to be implemented by derived class."""
        pass

    @classmethod
    def from_keyset(cls, otak: OtaKeyset) -> 'OtaAlgoAuth':
        """Resolve the class for the authentication algorithm of otak and instantiate it."""
        for subc in cls.__subclasses__():
            if subc.enum_name == otak.algo_auth:
                return subc(otak)
        raise ValueError('No implementation for auth algorithm %s' % otak.algo_auth)

class OtaAlgoCryptDES(OtaAlgoCrypt):
    """DES is insecure.  For backwards compatibility with pre-Rel8"""
    name = 'DES'
    enum_name = 'single_des'
    blocksize = 8
    def _encrypt(self, data:bytes) -> bytes:
        cipher = DES.new(self.otak.kic, DES.MODE_CBC, self.iv)
        return cipher.encrypt(data)

    def _decrypt(self, data:bytes) -> bytes:
        cipher = DES.new(self.otak.kic, DES.MODE_CBC, self.iv)
        return cipher.decrypt(data)

class OtaAlgoAuthDES(OtaAlgoAuth):
    """DES is insecure.  For backwards compatibility with pre-Rel8"""
    name = 'DES'
    enum_name = 'single_des'
    blocksize = 8
    def _sign(self, data:bytes) -> bytes:
        cipher = DES.new(self.otak.kid, DES.MODE_CBC, self.iv)
        ciph = cipher.encrypt(data)
        return ciph[len(ciph) - 8:]

class OtaAlgoCryptDES3(OtaAlgoCrypt):
    name = '3DES'
    enum_name = 'triple_des_cbc2'
    blocksize = 8
    def _encrypt(self, data:bytes) -> bytes:
        cipher = DES3.new(self.otak.kic, DES3.MODE_CBC, self.iv)
        return cipher.encrypt(data)

    def _decrypt(self, data:bytes) -> bytes:
        cipher = DES3.new(self.otak.kic, DES3.MODE_CBC, self.iv)
        return cipher.decrypt(data)

class OtaAlgoAuthDES3(OtaAlgoAuth):
    name = '3DES'
    enum_name = 'triple_des_cbc2'
    blocksize = 8
    def _sign(self, data:bytes) -> bytes:
        cipher = DES3.new(self.otak.kid, DES3.MODE_CBC, self.iv)
        ciph = cipher.encrypt(data)
        return ciph[len(ciph) - 8:]

class OtaAlgoCryptAES(OtaAlgoCrypt):
    name = 'AES'
    enum_name = 'aes_cbc'
    blocksize = 16 # TODO: is this needed?
    def _encrypt(self, data:bytes) -> bytes:
        cipher = AES.new(self.otak.kic, AES.MODE_CBC, self.iv)
        return cipher.encrypt(data)

    def _decrypt(self, data:bytes) -> bytes:
        cipher = AES.new(self.otak.kic, AES.MODE_CBC, self.iv)
        return cipher.decrypt(data)

class OtaAlgoAuthAES(OtaAlgoAuth):
    name = 'AES'
    enum_name = 'aes_cmac'
    blocksize = 1 # AES CMAC doesn't need any padding by us
    def _sign(self, data:bytes) -> bytes:
        cmac = CMAC.new(self.otak.kid, ciphermod=AES, mac_len=8)
        cmac.update(data)
        ciph = cmac.digest()
        return ciph[len(ciph) - 8:]



class OtaDialectSms(OtaDialect):
    """OTA dialect for SMS based transport, as described in 3GPP TS 31.115."""
    SmsResponsePacket = Struct('rpl'/Int16ub,
                               'rhl'/Int8ub,
                               'tar'/Bytes(3),
                               'cntr'/Bytes(5),
                               'pcntr'/Int8ub,
                               'response_status'/ResponseStatus,
                               'cc_rc'/Bytes(this.rhl-10),
                               'secured_data'/GreedyBytes)
    hdr_construct = Struct('chl'/Int8ub, 'spi'/SPI, 'kic'/KIC, 'kid'/KID_CC, 'tar'/Bytes(3))

    def encode_cmd(self, otak: OtaKeyset, tar: bytes, spi: dict,
                   apdu: Union[bytes, List[bytes]], remote_format: str = 'compact') -> bytes:
        # as above:
        # expanded format is a Command Scripting template wrapping the C-APDU(s)
        # compact format passes already concatenated command string
        if remote_format == 'expanded':
            apdu = encode_expanded_cmd(apdu)
        elif remote_format != 'compact':
            raise ValueError("Invalid remote_format: %s" % remote_format)

        # length of signature in octets
        len_sig = self._compute_sig_len(spi)
        pad_cnt = 0
        if spi['ciphering']: # ciphering is requested
            # append padding bytes to end up with blocksize
            len_cipher = 6 + len_sig + len(apdu)
            padding = otak.crypt._get_padding(len_cipher, otak.crypt.blocksize)
            pad_cnt = len(padding)
            apdu = bytes(apdu) # make a copy so we don't modify the input data
            apdu += padding

        kic = {'key': otak.kic_idx, 'algo': otak.algo_crypt}
        kid = {'key': otak.kid_idx, 'algo': otak.algo_auth}

        # CHL = number of octets from (and including) SPI to the end of RC/CC/DS
        # 13 == SPI(2) + KIc(1) + KId(1) + TAR(3) + CNTR(5) + PCNTR(1)
        chl = 13 + len_sig

        # CHL + SPI (+ KIC + KID)
        part_head = self.hdr_construct.build({'chl': chl, 'spi':spi, 'kic':kic, 'kid':kid, 'tar':tar})
        #print("part_head: %s" % b2h(part_head))

        # CNTR + PCNTR (CNTR not used)
        part_cnt = otak.cntr.to_bytes(5, 'big') + pad_cnt.to_bytes(1, 'big')
        #print("part_cnt: %s" % b2h(part_cnt))

        envelope_data = part_head + part_cnt + apdu
        #print("envelope_data: %s" % b2h(envelope_data))

        # 2-byte CPL. CPL is part of RC/CC/CPI to end of secured data, including any padding for ciphering
        # CPL from and including CPI to end of secured data, including any padding for ciphering
        cpl = len(envelope_data) + len_sig
        envelope_data = cpl.to_bytes(2, 'big') + envelope_data
        #print("envelope_data with cpl: %s" % b2h(envelope_data))

        if spi['rc_cc_ds'] == 'cc':
            cc = otak.auth.sign(envelope_data)
            envelope_data = part_cnt + cc + apdu
        elif spi['rc_cc_ds'] == 'rc':
            # CRC32
            crc32 = zlib.crc32(envelope_data) & 0xffffffff
            envelope_data = part_cnt + crc32.to_bytes(4, 'big') + apdu
        elif spi['rc_cc_ds'] == 'no_rc_cc_ds':
            envelope_data = part_cnt + apdu
        else:
            raise ValueError("Invalid rc_cc_ds: %s" % spi['rc_cc_ds'])

        #print("envelope_data with sig: %s" % b2h(envelope_data))

        # encrypt as needed
        if spi['ciphering']: # ciphering is requested
            ciph = otak.crypt.encrypt(envelope_data)
            envelope_data = part_head + ciph
            # prefix with another CPL
            cpl = len(envelope_data)
            envelope_data = cpl.to_bytes(2, 'big') + envelope_data
        else:
            envelope_data = part_head + envelope_data

        #print("envelope_data: %s" % b2h(envelope_data))

        if len(envelope_data) > 140:
            raise ValueError('Cannot encode command in a single SMS; Fragmentation not implemented')

        return envelope_data

    def decode_cmd(self, otak: OtaKeyset, encoded: bytes) -> Tuple[bytes, dict, bytes]:
        """Decode an encoded (encrypted, signed) OTA SMS Command-APDU."""
        if True: # TODO: how to decide?
            cpl = int.from_bytes(encoded[:2], 'big')
            part_head = encoded[2:2+8]
            ciph = encoded[2+8:]
            envelope_data = otak.crypt.decrypt(ciph)
        else:
            cpl = None # FIXME this line was just added to silence pylint possibly-used-before-assignment
            part_head = encoded[:8]
            envelope_data = encoded[8:]

        hdr_dec = self.hdr_construct.parse(part_head)

        # strip counter part from front of envelope_data
        part_cnt = envelope_data[:6]
        cntr = int.from_bytes(part_cnt[:5], 'big')
        pad_cnt = int.from_bytes(part_cnt[5:], 'big')
        envelope_data = envelope_data[6:]

        spi = hdr_dec['spi']
        if spi['rc_cc_ds'] == 'cc':
            # split cc from front of APDU
            cc = envelope_data[:8]
            apdu = envelope_data[8:]
            # verify CC
            temp_data = cpl.to_bytes(2, 'big') + part_head + part_cnt + apdu
            otak.auth.check_sig(temp_data, cc)
        elif spi['rc_cc_ds'] == 'rc':
            # CRC32
            crc32_rx = int.from_bytes(envelope_data[:4], 'big')
            # FIXME: crc32_computed = zlip.crc32(
            # FIXME: verify RC
            raise NotImplementedError
            apdu = envelope_data[4:]
        elif spi['rc_cc_ds'] == 'no_rc_cc_ds':
            apdu = envelope_data
        else:
            raise ValueError("Invalid rc_cc_ds: %s" % spi['rc_cc_ds'])

        apdu = apdu[:len(apdu)-pad_cnt]
        return hdr_dec['tar'], spi, apdu


    def decode_resp(self, otak: OtaKeyset, spi: dict, data: bytes,
                    remote_format: str = 'compact') -> ("OtaDialectSms.SmsResponsePacket", Optional[object]):
        if remote_format not in ('compact', 'expanded'):
            raise ValueError("Invalid remote_format: %s ?!" % remote_format)
        if isinstance(data, str):
            data = h2b(data)
        # plain-text POR:   027100000e0ab000110000000000000001612f
        # UDHL RPI IEDLa  RPL  RHL TAR    CNTR       PCNTR STS
        # 02   71  00     000e 0a  b00011 0000000000 00    00  01 612f
        # POR with CC:      027100001612b000110000000000000055f47118381175fb01612f
        # POR with CC+CIPH: 027100001c12b000119660ebdb81be189b5e4389e9e7ab2bc0954f963ad869ed7c
        if data[0] != 0x02:
            raise ValueError('Unexpected UDL=0x%02x' % data[0])
        udhd, remainder = UserDataHeader.from_bytes(data)
        if not udhd.has_ie(0x71):
            raise ValueError('RPI 0x71 not found in UDH')
        rph_rhl_tar = remainder[:6] # RPH+RHL+TAR; not ciphered
        res = self.SmsResponsePacket.parse(remainder)

        if spi['por_shall_be_ciphered']:
            # decrypt
            ciphered_part = remainder[6:]
            deciph = otak.crypt.decrypt(ciphered_part)
            temp_data = rph_rhl_tar + deciph
            res = self.SmsResponsePacket.parse(temp_data)
            # remove specified number of padding bytes, if any
            if res['pcntr'] != 0:
                # this conditional is needed as python [:-0] renders an empty return!
                res['secured_data'] = res['secured_data'][:-res['pcntr']]
            remainder = temp_data

        # is there a CC/RC present?
        len_sig = res['rhl'] - 10
        if spi['por_rc_cc_ds'] == 'no_rc_cc_ds':
            if len_sig:
                raise OtaCheckError('No RC/CC/DS requested, but len_sig=%u' % len_sig)
        elif spi['por_rc_cc_ds'] == 'cc':
            # verify signature
            # UDH is part of CC/RC!
            udh = data[:3]
            # RPL, RHL, TAR, CNTR, PCNTR and STSare part of CC/RC
            rpl_rhl_tar_cntr_pcntr_sts = remainder[:13]
            # remove the CC/RC bytes
            temp_data = udh + rpl_rhl_tar_cntr_pcntr_sts + remainder[13+len_sig:]
            otak.auth.check_sig(temp_data, res['cc_rc'])
        # TODO: CRC
        else:
            raise OtaCheckError('Unknown por_rc_cc_ds: %s' % spi['por_rc_cc_ds'])

        if res.response_status == 'por_ok' and len(res['secured_data']):
            if remote_format == 'expanded':
                dec = decode_expanded_resp(res['secured_data'])
            else:
                dec = CompactRemoteResp.parse(res['secured_data'])
        else:
            dec = None
        return (res, dec)
