# Global Platform SCP02 (Secure Channel Protocol) implementation
#
# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
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

import logging
from Cryptodome.Cipher import DES3, DES
from Cryptodome.Util.strxor import strxor
from construct import *
from pySim.utils import b2h
from pySim.secure_channel import SecureChannel

logger = logging.getLogger(__name__)

def scp02_key_derivation(constant: bytes, counter: int, base_key: bytes) -> bytes:
    assert(len(constant) == 2)
    assert(counter >= 0 and counter <= 65535)
    assert(len(base_key) == 16)

    derivation_data = constant + counter.to_bytes(2, 'big') + b'\x00' * 12
    cipher = DES3.new(base_key, DES.MODE_CBC, b'\x00' * 8)
    return cipher.encrypt(derivation_data)

# FIXME: overlap with BspAlgoCryptAES128
def pad80(s: bytes, BS=8) -> bytes:
    """ Pad bytestring s: add '\x80' and '\0'* so the result to be multiple of BS."""
    l = BS-1 - len(s) % BS
    return s + b'\x80' + b'\0'*l

class Scp02SessionKeys:
    """A single set of GlobalPlatform session keys."""
    DERIV_CONST_CMAC = b'\x01\x01'
    DERIV_CONST_RMAC = b'\x01\x02'
    DERIV_CONST_ENC = b'\x01\x82'
    DERIV_CONST_DENC = b'\x01\x81'

    def calc_mac_1des(self, data: bytes, reset_icv: bool = False) -> bytes:
        """Pad and calculate MAC according to B.1.2.2 - Single DES plus final 3DES"""
        e = DES.new(self.c_mac[:8], DES.MODE_ECB)
        d = DES.new(self.c_mac[8:], DES.MODE_ECB)
        padded_data = pad80(data, 8)
        q = len(padded_data) // 8
        icv = b'\x00' * 8 if reset_icv else self.icv
        h = icv
        for i in range(q):
            h = e.encrypt(strxor(h, bytes(padded_data[8*i:8*(i+1)])))
        h = d.decrypt(h)
        h = e.encrypt(h)
        logger.debug("mac_1des(%s,icv=%s) -> %s", b2h(data), b2h(icv), b2h(h))
        if self.des_icv_enc:
            self.icv = self.des_icv_enc.encrypt(h)
        else:
            self.icv = h
        return h

    def calc_mac_3des(self, data: bytes) -> bytes:
        e = DES3.new(self.enc, DES.MODE_ECB)
        padded_data = pad80(data, 8)
        q = len(padded_data) // 8
        h = b'\x00' * 8
        for i in range(q):
            h = e.encrypt(strxor(h, bytes(padded_data[8*i:8*(i+1)])))
        logger.debug("mac_3des(%s) -> %s", b2h(data), b2h(h))
        return h

    def __init__(self, counter: int, card_keys: 'GpCardKeyset', icv_encrypt=True):
        self.icv = None
        self.counter = counter
        self.card_keys = card_keys
        self.c_mac = scp02_key_derivation(self.DERIV_CONST_CMAC, self.counter, card_keys.mac)
        self.r_mac = scp02_key_derivation(self.DERIV_CONST_RMAC, self.counter, card_keys.mac)
        self.enc = scp02_key_derivation(self.DERIV_CONST_ENC, self.counter, card_keys.enc)
        self.data_enc = scp02_key_derivation(self.DERIV_CONST_DENC, self.counter, card_keys.dek)
        self.des_icv_enc = DES.new(self.c_mac[:8], DES.MODE_ECB) if icv_encrypt else None

    def __str__(self) -> str:
        return "%s(CTR=%u, ICV=%s, ENC=%s, D-ENC=%s, MAC-C=%s, MAC-R=%s)" % (
                self.__class__.__name__, self.counter, b2h(self.icv) if self.icv else "None",
                b2h(self.enc), b2h(self.data_enc), b2h(self.c_mac), b2h(self.r_mac))

INS_INIT_UPDATE = 0x50
INS_EXT_AUTH = 0x82
CLA_SM = 0x04

class SCP(SecureChannel):
    pass

class SCP02(SCP):
    """An instance of the GlobalPlatform SCP02 secure channel protocol."""

    constr_iur = Struct('key_div_data'/Bytes(10), 'key_ver'/Int8ub, Const(b'\x02'),
                        'seq_counter'/Int16ub, 'card_challenge'/Bytes(6), 'card_cryptogram'/Bytes(8))

    def __init__(self, card_keys: 'GpCardKeyset', lchan_nr: int = 0):
        self.lchan_nr = lchan_nr
        self.card_keys = card_keys
        self.sk = None
        self.mac_on_unmodified = False
        self.security_level = None

    def __str__(self) -> str:
        if self.security_level:
            return "%s[%02x]" % (self.__class__.__name__, self.security_level)
        else:
            return "%s[??]" % (self.__class__.__name__)

    def _cla(self, sm: bool = False, b8: bool = True) -> int:
        ret = 0x80 if b8 else 0x00
        if sm:
            ret = ret | CLA_SM
        return ret + self.lchan_nr

    def _compute_cryptograms(self, card_challenge: bytes, host_challenge: bytes):
        logger.debug("host_challenge(%s), card_challenge(%s)", b2h(host_challenge), b2h(card_challenge))
        self.host_cryptogram = self.sk.calc_mac_3des(self.sk.counter.to_bytes(2, 'big') + card_challenge + host_challenge)
        self.card_cryptogram = self.sk.calc_mac_3des(self.host_challenge + self.sk.counter.to_bytes(2, 'big') + card_challenge)
        logger.debug("host_cryptogram(%s), card_cryptogram(%s)", b2h(self.host_cryptogram), b2h(self.card_cryptogram))

    def gen_init_update_apdu(self, host_challenge: bytes = b'\x00'*8) -> bytes:
        """Generate INITIALIZE UPDATE APDU."""
        self.host_challenge = host_challenge
        return bytes([self._cla(), INS_INIT_UPDATE, self.card_keys.kvn, 0, 8]) + self.host_challenge

    def parse_init_update_resp(self, resp_bin: bytes):
        """Parse response to INITIALZIE UPDATE."""
        resp = self.constr_iur.parse(resp_bin)
        self.card_challenge = resp['card_challenge']
        self.sk = Scp02SessionKeys(resp['seq_counter'], self.card_keys)
        logger.debug(self.sk)
        self._compute_cryptograms(self.card_challenge, self.host_challenge)
        if self.card_cryptogram != resp['card_cryptogram']:
            raise ValueError("card cryptogram doesn't match")

    def gen_ext_auth_apdu(self, security_level: int = 0x01) -> bytes:
        """Generate EXTERNAL AUTHENTICATE APDU."""
        if security_level & 0xf0:
            raise NotImplementedError('R-MAC/R-ENC for SCP02 not implemented yet.')
        self.security_level = security_level
        if self.mac_on_unmodified:
            header = bytes([self._cla(), INS_EXT_AUTH, self.security_level, 0, 8])
        else:
            header = bytes([self._cla(True), INS_EXT_AUTH, self.security_level, 0, 16])
        #return self.wrap_cmd_apdu(header + self.host_cryptogram)
        mac = self.sk.calc_mac_1des(header + self.host_cryptogram, True)
        return bytes([self._cla(True), INS_EXT_AUTH, self.security_level, 0, 16]) + self.host_cryptogram + mac

    def wrap_cmd_apdu(self, apdu: bytes) -> bytes:
        """Wrap Command APDU for SCP02: calculate MAC and encrypt."""
        lc = len(apdu) - 5
        assert len(apdu) >= 5, "Wrong APDU length: %d" % len(apdu)
        assert len(apdu) == 5 or apdu[4] == lc, "Lc differs from length of data: %d vs %d" % (apdu[4], lc)

        logger.debug("wrap_cmd_apdu(%s)", b2h(apdu))

        cla = apdu[0]
        b8 = cla & 0x80
        if cla & 0x03 or cla & CLA_SM:
            # nonzero logical channel in APDU, check that are the same
            assert cla == self._cla(False, b8), "CLA mismatch"
        # CLA without log. channel can be 80 or 00 only
        if self.do_cmac:
            if self.mac_on_unmodified:
                mlc = lc
                clac = cla
            else:                      # CMAC on modified APDU
                mlc = lc + 8
                clac = cla | CLA_SM
            mac = self.sk.calc_mac_1des(bytes([clac]) + apdu[1:4] + bytes([mlc]) + apdu[5:])
            if self.do_cenc:
                k = DES3.new(self.sk.enc, DES.MODE_CBC, b'\x00'*8)
                data = k.encrypt(pad80(apdu[5:], 8))
                lc = len(data)
            else:
                data = apdu[5:]
            lc += 8
            apdu = bytes([self._cla(True, b8)]) + apdu[1:4] + bytes([lc]) + data + mac
        return apdu

    def unwrap_rsp_apdu(self, sw: bytes, apdu: bytes) -> bytes:
        # TODO: Implement R-MAC / R-ENC
        return apdu
