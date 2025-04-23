# Global Platform SCP02 + SCP03 (Secure Channel Protocol) implementation
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

import abc
import logging
from typing import Optional
from Cryptodome.Cipher import DES3, DES
from Cryptodome.Util.strxor import strxor
from construct import Struct, Int8ub, Int16ub, Const
from construct import Optional as COptional
from osmocom.construct import Bytes
from osmocom.utils import b2h
from osmocom.tlv import bertlv_parse_len, bertlv_encode_len
from pySim.utils import parse_command_apdu
from pySim.secure_channel import SecureChannel

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def scp02_key_derivation(constant: bytes, counter: int, base_key: bytes) -> bytes:
    assert len(constant) == 2
    assert(counter >= 0 and counter <= 65535)
    assert len(base_key) == 16

    derivation_data = constant + counter.to_bytes(2, 'big') + b'\x00' * 12
    cipher = DES3.new(base_key, DES.MODE_CBC, b'\x00' * 8)
    return cipher.encrypt(derivation_data)

# TODO: resolve duplication with BspAlgoCryptAES128
def pad80(s: bytes, BS=8) -> bytes:
    """ Pad bytestring s: add '\x80' and '\0'* so the result to be multiple of BS."""
    l = BS-1 - len(s) % BS
    return s + b'\x80' + b'\0'*l

# TODO: resolve duplication with BspAlgoCryptAES128
def unpad80(padded: bytes) -> bytes:
    """Remove the customary 80 00 00 ... padding used for AES."""
    # first remove any trailing zero bytes
    stripped = padded.rstrip(b'\0')
    # then remove the final 80
    assert stripped[-1] == 0x80
    return stripped[:-1]

class Scp02SessionKeys:
    """A single set of GlobalPlatform session keys."""
    DERIV_CONST_CMAC = b'\x01\x01'
    DERIV_CONST_RMAC = b'\x01\x02'
    DERIV_CONST_ENC = b'\x01\x82'
    DERIV_CONST_DENC = b'\x01\x81'
    blocksize = 8

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

class SCP(SecureChannel, abc.ABC):
    """Abstract base class containing some common interface + functionality for SCP protocols."""
    def __init__(self, card_keys: 'GpCardKeyset', lchan_nr: int = 0):

        # Spec references that explain KVN ranges:
        # TS 102 225 Annex A.1 states KVN 0x01..0x0F shall be used for SCP80
        # GPC_GUI_003 states
        #   * For the Issuer Security Domain, this is initially Key Version Number 'FF' which has been deliberately
        #     chosen to be outside of the allowable range ('01' to '7F') for a Key Version Number.
        #   * It is logical that the initial keys in the Issuer Security Domain be replaced by an initial issuer Key
        #     Version Number in the range '01' to '6F'.
        #   * Key Version Numbers '70' to '72' and '74' to '7F' are reserved for future use.
        #   * On an implementation supporting Supplementary Security Domains, the RSA public key with a Key Version
        #     Number '73' and a Key Identifier of '01' has the following functionality in a Supplementary Security
        #     Domain with the DAP Verification privilege [...]
        # GPC_GUI_010 V1.0.1 Section 6 states
        #   * Key Version number range ('20' to '2F') is reserved for SCP02
        #   * Key Version 'FF' is reserved for use by an Issuer Security Domain supporting SCP02, and cannot be used
        #     for SCP80. This initial key set shall be replaced by a key set with a Key Version Number in the
        #     ('20' to '2F') range.
        #   * Key Version number range ('01' to '0F') is reserved for SCP80
        #   * Key Version number '70' with Key Identifier '01' is reserved for the Token Key, which is either a RSA
        #     public key or a DES key
        #   * Key Version number '71' with Key Identifier '01' is reserved for the Receipt Key, which is a DES key
        #   * Key Version Number '11' is reserved for DAP as specified in ETSI TS 102 226 [2]
        #   * Key Version Number '73' with Key Identifier '01' is reserved for the DAP verification key as specified
        #     in sections 3.3.3 and 4 of [4], which is either an RSA public key or DES key
        #   * Key Version Number '74' is reserved for the CASD Keys (cf. section 9.2)
        #   * Key Version Number '75' with Key Identifier '01' is reserved for the key used to decipher the Ciphered
        #     Load File Data Block described in section 4.8 of [5].

        if card_keys.kvn == 0:
            # Key Version Number 0x00 refers to the first available key, so we won't carry out
            # a range check in this case. See also: GPC_SPE_034, section E.5.1.3
            pass
        elif hasattr(self, 'kvn_range'):
            if not card_keys.kvn in range(self.kvn_range[0], self.kvn_range[1]+1):
                raise ValueError('%s cannot be used with KVN outside range 0x%02x..0x%02x' %
                                 (self.__class__.__name__, self.kvn_range[0], self.kvn_range[1]))
        elif hasattr(self, 'kvn_ranges'):
            # pylint: disable=no-member
            if all([not card_keys.kvn in range(x[0], x[1]+1) for x in self.kvn_ranges]):
                raise ValueError('%s cannot be used with KVN outside permitted ranges %s' %
                                 (self.__class__.__name__, self.kvn_ranges))

        self.lchan_nr = lchan_nr
        self.card_keys = card_keys
        self.sk = None
        self.mac_on_unmodified = False
        self.security_level = 0x00

    @property
    def do_cmac(self) -> bool:
        """Should we perform C-MAC?"""
        return self.security_level & 0x01

    @property
    def do_rmac(self) -> bool:
        """Should we perform R-MAC?"""
        return self.security_level & 0x10

    @property
    def do_cenc(self) -> bool:
        """Should we perform C-ENC?"""
        return self.security_level & 0x02

    @property
    def do_renc(self) -> bool:
        """Should we perform R-ENC?"""
        return self.security_level & 0x20

    def __str__(self) -> str:
        return "%s[%02x]" % (self.__class__.__name__, self.security_level)

    def _cla(self, sm: bool = False, b8: bool = True) -> int:
        ret = 0x80 if b8 else 0x00
        if sm:
            ret = ret | CLA_SM
        return ret + self.lchan_nr

    def wrap_cmd_apdu(self, apdu: bytes, *args, **kwargs) -> bytes:
        # Generic handling of GlobalPlatform SCP, implements SecureChannel.wrap_cmd_apdu
        # only protect those APDUs that actually are global platform commands
        if apdu[0] & 0x80:
            return self._wrap_cmd_apdu(apdu, *args, **kwargs)
        return apdu

    @abc.abstractmethod
    def _wrap_cmd_apdu(self, apdu: bytes, *args, **kwargs) -> bytes:
        """Method implementation to be provided by derived class."""
        pass

    @abc.abstractmethod
    def gen_init_update_apdu(self, host_challenge: Optional[bytes]) -> bytes:
        pass

    @abc.abstractmethod
    def parse_init_update_resp(self, resp_bin: bytes):
        pass

    @abc.abstractmethod
    def gen_ext_auth_apdu(self, security_level: int = 0x01) -> bytes:
        pass

    def encrypt_key(self, key: bytes) -> bytes:
        """Encrypt a key with the DEK."""
        num_pad = len(key) % self.sk.blocksize
        if num_pad:
            return bertlv_encode_len(len(key)) + self.dek_encrypt(key + b'\x00'*num_pad)
        return self.dek_encrypt(key)

    def decrypt_key(self, encrypted_key:bytes) -> bytes:
        """Decrypt a key with the DEK."""
        if len(encrypted_key) % self.sk.blocksize:
            # If the length of the Key Component Block is not a multiple of the block size of the encryption #
            # algorithm (i.e. 8 bytes for DES, 16 bytes for AES), then it shall be assumed that the key
            # component value was right-padded prior to encryption and that the Key Component Block was
            # formatted as described in Table 11-70. In this case, the first byte(s) of the Key Component
            # Block provides the actual length of the key component value, which allows recovering the
            # clear-text key component value after decryption of the encrypted key component value and removal
            # of padding bytes.
            decrypted = self.dek_decrypt(encrypted_key)
            key_len, remainder = bertlv_parse_len(decrypted)
            return remainder[:key_len]
        else:
            # If the length of the Key Component Block is a multiple of the block size of the encryption
            # algorithm (i.e.  8 bytes for DES, 16 bytes for AES), then it shall be assumed that no padding
            # bytes were added before encrypting the key component value and that the Key Component Block is
            # only composed of the encrypted key component value (as shown in Table 11-71). In this case, the
            # clear-text key component value is simply recovered by decrypting the Key Component Block.
            return self.dek_decrypt(encrypted_key)

    @abc.abstractmethod
    def dek_encrypt(self, plaintext:bytes) -> bytes:
        pass

    @abc.abstractmethod
    def dek_decrypt(self, ciphertext:bytes) -> bytes:
        pass


class SCP02(SCP):
    """An instance of the GlobalPlatform SCP02 secure channel protocol."""

    constr_iur = Struct('key_div_data'/Bytes(10), 'key_ver'/Int8ub, Const(b'\x02'),
                        'seq_counter'/Int16ub, 'card_challenge'/Bytes(6), 'card_cryptogram'/Bytes(8))
    # Key Version Number 0x70 is a non-spec special-case of sysmoISIM-SJA2/SJA5 and possibly more sysmocom products
    # Key Version Number 0x01 is a non-spec special-case of sysmoUSIM-SJS1
    kvn_ranges = [[0x01, 0x01], [0x20, 0x2f], [0x70, 0x70]]

    def __init__(self, *args, **kwargs):
        self.overhead = 8
        super().__init__(*args, **kwargs)

    def dek_encrypt(self, plaintext:bytes) -> bytes:
        cipher = DES.new(self.card_keys.dek[:8], DES.MODE_ECB)
        return cipher.encrypt(plaintext)

    def dek_decrypt(self, ciphertext:bytes) -> bytes:
        cipher = DES.new(self.card_keys.dek[:8], DES.MODE_ECB)
        return cipher.decrypt(ciphertext)

    def _compute_cryptograms(self, card_challenge: bytes, host_challenge: bytes):
        logger.debug("host_challenge(%s), card_challenge(%s)", b2h(host_challenge), b2h(card_challenge))
        self.host_cryptogram = self.sk.calc_mac_3des(self.sk.counter.to_bytes(2, 'big') + card_challenge + host_challenge)
        self.card_cryptogram = self.sk.calc_mac_3des(self.host_challenge + self.sk.counter.to_bytes(2, 'big') + card_challenge)
        logger.debug("host_cryptogram(%s), card_cryptogram(%s)", b2h(self.host_cryptogram), b2h(self.card_cryptogram))

    def gen_init_update_apdu(self, host_challenge: bytes = b'\x00'*8) -> bytes:
        """Generate INITIALIZE UPDATE APDU."""
        self.host_challenge = host_challenge
        return bytes([self._cla(), INS_INIT_UPDATE, self.card_keys.kvn, 0, 8]) + self.host_challenge + b'\x00'

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

    def _wrap_cmd_apdu(self, apdu: bytes, *args, **kwargs) -> bytes:
        """Wrap Command APDU for SCP02: calculate MAC and encrypt."""
        logger.debug("wrap_cmd_apdu(%s)", b2h(apdu))

        if not self.do_cmac:
            return apdu

        (case, lc, le, data) = parse_command_apdu(apdu)

        # TODO: add support for extended length fields.
        assert lc <= 256
        assert le <= 256
        lc &= 0xFF
        le &= 0xFF

        # CLA without log. channel can be 80 or 00 only
        cla = apdu[0]
        b8 = cla & 0x80
        if cla & 0x03 or cla & CLA_SM:
            # nonzero logical channel in APDU, check that are the same
            assert cla == self._cla(False, b8), "CLA mismatch"

        if self.mac_on_unmodified:
            mlc = lc
            clac = cla
        else:
            # CMAC on modified APDU
            mlc = lc + 8
            clac = cla | CLA_SM
        mac = self.sk.calc_mac_1des(bytes([clac]) + apdu[1:4] + bytes([mlc]) + data)
        if self.do_cenc:
            k = DES3.new(self.sk.enc, DES.MODE_CBC, b'\x00'*8)
            data = k.encrypt(pad80(data, 8))
            lc = len(data)

        lc += 8
        apdu = bytes([self._cla(True, b8)]) + apdu[1:4] + bytes([lc]) + data + mac

        # Since we attach a signature, we will always send some data. This means that if the APDU is of case #4
        # or case #2, we must attach an additional Le byte to signal that we expect a response. It is technically
        # legal to use 0x00 (=256) as Le byte, even when the caller has specified a different value in the original
        # APDU. This is due to the fact that Le always describes the maximum expected length of the response
        # (see also ISO/IEC 7816-4, section 5.1). In addition to that, it should also important that depending on
        # the configuration of the SCP, the response may also contain a signature that makes the response larger
        # than specified in the Le field of the original APDU.
        if case == 4 or case == 2:
            apdu += b'\x00'

        return apdu

    def unwrap_rsp_apdu(self, sw: bytes, rsp_apdu: bytes) -> bytes:
        # TODO: Implement R-MAC / R-ENC
        return rsp_apdu



from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

def scp03_key_derivation(constant: bytes, context: bytes, base_key: bytes, l: Optional[int] = None) -> bytes:
    """SCP03 Key Derivation Function as specified in Annex D 4.1.5."""
    # Data derivation shall use KDF in counter mode as specified in NIST SP 800-108 ([NIST 800-108]). The PRF
    # used in the KDF shall be CMAC as specified in [NIST 800-38B], used with full 16-byte output length.
    def prf(key: bytes, data:bytes):
        return CMAC.new(key, data, AES).digest()

    if l is None:
        l = len(base_key) * 8

    logger.debug("scp03_kdf(constant=%s, context=%s, base_key=%s, l=%u)", b2h(constant), b2h(context), b2h(base_key), l)
    output_len = l // 8
    # SCP03 Section 4.1.5 defines a different parameter order than NIST SP 800-108, so we cannot use the
    # existing Cryptodome.Protocol.KDF.SP800_108_Counter function :(
    # A 12-byte “label” consisting of 11 bytes with value '00' followed by a 1-byte derivation constant
    assert len(constant) == 1
    label = b'\x00' *11 + constant
    i = 1
    dk = b''
    while len(dk) < output_len:
        # 12B label, 1B separation, 2B L, 1B i, Context
        info = label + b'\x00' + l.to_bytes(2, 'big') + bytes([i]) + context
        dk += prf(base_key, info)
        i += 1
        if i > 0xffff:
            raise ValueError("Overflow in SP800 108 counter")
    return dk[:output_len]


class Scp03SessionKeys:
    # GPC 2.3 Amendment D v1.2 Section 4.1.5 Table 4-1
    DERIV_CONST_AUTH_CGRAM_CARD = b'\x00'
    DERIV_CONST_AUTH_CGRAM_HOST = b'\x01'
    DERIV_CONST_CARD_CHLG_GEN = b'\x02'
    DERIV_CONST_KDERIV_S_ENC = b'\x04'
    DERIV_CONST_KDERIV_S_MAC = b'\x06'
    DERIV_CONST_KDERIV_S_RMAC = b'\x07'
    blocksize = 16

    def __init__(self, card_keys: 'GpCardKeyset', host_challenge: bytes, card_challenge: bytes):
        # GPC 2.3 Amendment D v1.2 Section 6.2.1
        context = host_challenge + card_challenge
        self.s_enc = scp03_key_derivation(self.DERIV_CONST_KDERIV_S_ENC, context, card_keys.enc)
        self.s_mac = scp03_key_derivation(self.DERIV_CONST_KDERIV_S_MAC, context, card_keys.mac)
        self.s_rmac = scp03_key_derivation(self.DERIV_CONST_KDERIV_S_RMAC, context, card_keys.mac)


        # The first MAC chaining value is set to 16 bytes '00'
        self.mac_chaining_value = b'\x00' * 16
        # The encryption counter’s start value shall be set to 1 (we set it immediately before generating ICV)
        self.block_nr = 0

    def calc_cmac(self, apdu: bytes):
        """Compute C-MAC for given to-be-transmitted APDU.
        Returns the full 16-byte MAC, caller must truncate it if needed for S8 mode."""
        cmac_input = self.mac_chaining_value + apdu
        cmac_val = CMAC.new(self.s_mac, cmac_input, ciphermod=AES).digest()
        self.mac_chaining_value = cmac_val
        return cmac_val

    def calc_rmac(self, rdata_and_sw: bytes):
        """Compute R-MAC for given received R-APDU data section.
        Returns the full 16-byte MAC, caller must truncate it if needed for S8 mode."""
        rmac_input = self.mac_chaining_value + rdata_and_sw
        return CMAC.new(self.s_rmac, rmac_input, ciphermod=AES).digest()

    def _get_icv(self, is_response: bool = False):
        """Obtain the ICV value computed as described in 6.2.6.
        This method has two modes:
            * is_response=False for computing the ICV for C-ENC. Will pre-increment the counter.
            * is_response=False for computing the ICV for R-DEC."""
        if not is_response:
            self.block_nr += 1
        # The binary value of this number SHALL be left padded with zeroes to form a full block.
        data = self.block_nr.to_bytes(self.blocksize, "big")
        if is_response:
            # Section 6.2.7: additional intermediate step: Before encryption, the most significant byte of
            # this block shall be set to '80'.
            data = b'\x80' + data[1:]
        iv = bytes([0] * self.blocksize)
        # This block SHALL be encrypted with S-ENC to produce the ICV for command encryption.
        cipher = AES.new(self.s_enc, AES.MODE_CBC, iv)
        icv = cipher.encrypt(data)
        logger.debug("_get_icv(data=%s, is_resp=%s) -> icv=%s", b2h(data), is_response, b2h(icv))
        return icv

    # TODO: Resolve duplication with pySim.esim.bsp.BspAlgoCryptAES128 which provides pad80-wrapping
    def _encrypt(self, data: bytes, is_response: bool = False) -> bytes:
        cipher = AES.new(self.s_enc, AES.MODE_CBC, self._get_icv(is_response))
        return cipher.encrypt(data)

    # TODO: Resolve duplication with pySim.esim.bsp.BspAlgoCryptAES128 which provides pad80-unwrapping
    def _decrypt(self, data: bytes, is_response: bool = True) -> bytes:
        cipher = AES.new(self.s_enc, AES.MODE_CBC, self._get_icv(is_response))
        return cipher.decrypt(data)


class SCP03(SCP):
    """Secure Channel Protocol (SCP) 03 as specified in GlobalPlatform v2.3 Amendment D."""

    # Section 7.1.1.6 / Table 7-3
    constr_iur = Struct('key_div_data'/Bytes(10), 'key_ver'/Int8ub, Const(b'\x03'), 'i_param'/Int8ub,
                        'card_challenge'/Bytes(lambda ctx: ctx._.s_mode),
                        'card_cryptogram'/Bytes(lambda ctx: ctx._.s_mode),
                        'sequence_counter'/COptional(Bytes(3)))
    kvn_range = [0x30, 0x3f]

    def __init__(self, *args, **kwargs):
        self.s_mode = kwargs.pop('s_mode', 8)
        self.overhead = self.s_mode
        super().__init__(*args, **kwargs)

    def dek_encrypt(self, plaintext:bytes) -> bytes:
        cipher = AES.new(self.card_keys.dek, AES.MODE_CBC, b'\x00'*16)
        return cipher.encrypt(plaintext)

    def dek_decrypt(self, ciphertext:bytes) -> bytes:
        cipher = AES.new(self.card_keys.dek, AES.MODE_CBC, b'\x00'*16)
        return cipher.decrypt(ciphertext)

    def _compute_cryptograms(self):
        logger.debug("host_challenge(%s), card_challenge(%s)", b2h(self.host_challenge), b2h(self.card_challenge))
        # Card + Host Authentication Cryptogram: Section 6.2.2.2 + 6.2.2.3
        context = self.host_challenge + self.card_challenge
        self.card_cryptogram = scp03_key_derivation(self.sk.DERIV_CONST_AUTH_CGRAM_CARD, context, self.sk.s_mac, l=self.s_mode*8)
        self.host_cryptogram = scp03_key_derivation(self.sk.DERIV_CONST_AUTH_CGRAM_HOST, context, self.sk.s_mac, l=self.s_mode*8)
        logger.debug("host_cryptogram(%s), card_cryptogram(%s)", b2h(self.host_cryptogram), b2h(self.card_cryptogram))

    def gen_init_update_apdu(self, host_challenge: Optional[bytes] = None) -> bytes:
        """Generate INITIALIZE UPDATE APDU."""
        if host_challenge is None:
            host_challenge = b'\x00' * self.s_mode
        if len(host_challenge) != self.s_mode:
            raise ValueError('Host Challenge must be %u bytes long' % self.s_mode)
        self.host_challenge = host_challenge
        return bytes([self._cla(), INS_INIT_UPDATE, self.card_keys.kvn, 0, len(host_challenge)]) + host_challenge + b'\x00'

    def parse_init_update_resp(self, resp_bin: bytes):
        """Parse response to INITIALIZE UPDATE."""
        if len(resp_bin) not in [10+3+8+8, 10+3+16+16, 10+3+8+8+3, 10+3+16+16+3]:
            raise ValueError('Invalid length of Initialize Update Response')
        resp = self.constr_iur.parse(resp_bin, s_mode=self.s_mode)
        self.card_challenge = resp['card_challenge']
        self.i_param = resp['i_param']
        # derive session keys and compute cryptograms
        self.sk = Scp03SessionKeys(self.card_keys, self.host_challenge, self.card_challenge)
        logger.debug(self.sk)
        self._compute_cryptograms()
        # verify computed cryptogram matches received cryptogram
        if self.card_cryptogram != resp['card_cryptogram']:
            raise ValueError("card cryptogram doesn't match")

    def gen_ext_auth_apdu(self, security_level: int = 0x01) -> bytes:
        """Generate EXTERNAL AUTHENTICATE APDU."""
        self.security_level = security_level
        header = bytes([self._cla(), INS_EXT_AUTH, self.security_level, 0, self.s_mode])
        # bypass encryption for EXTERNAL AUTHENTICATE
        return self.wrap_cmd_apdu(header + self.host_cryptogram, skip_cenc=True)

    def _wrap_cmd_apdu(self, apdu: bytes, skip_cenc: bool = False) -> bytes:
        """Wrap Command APDU for SCP03: calculate MAC and encrypt."""
        logger.debug("wrap_cmd_apdu(%s)", b2h(apdu))

        if not self.do_cmac:
            return apdu

        cla = apdu[0]
        ins = apdu[1]
        p1 = apdu[2]
        p2 = apdu[3]
        (case, lc, le, cmd_data) = parse_command_apdu(apdu)

        # TODO: add support for extended length fields.
        assert lc <= 256
        assert le <= 256
        lc &= 0xFF
        le &= 0xFF

        if self.do_cenc and not skip_cenc:
            if case <= 2:
                # No encryption shall be applied to a command where there is no command data field. In this
                # case, the encryption counter shall still be incremented
                self.sk.block_nr += 1
            else:
                # data shall be padded as defined in [GPCS] section B.2.3
                padded_data = pad80(cmd_data, 16)
                lc = len(padded_data)
                if lc >= 256:
                    raise ValueError('Modified Lc (%u) would exceed maximum when appending padding' % (lc))
                # perform AES-CBC with ICV + S_ENC
                cmd_data = self.sk._encrypt(padded_data)

        # The length of the command message (Lc) shall be incremented by 8 (in S8 mode) or 16 (in S16
        # mode) to indicate the inclusion of the C-MAC in the data field of the command message.
        mlc = lc + self.s_mode
        if mlc >= 256:
            raise ValueError('Modified Lc (%u) would exceed maximum when appending %u bytes of mac' % (mlc, self.s_mode))
        # The class byte shall be modified for the generation or verification of the C-MAC: The logical
        # channel number shall be set to zero, bit 4 shall be set to 0 and bit 3 shall be set to 1 to indicate
        # GlobalPlatform proprietary secure messaging.
        mcla = (cla & 0xF0) | CLA_SM
        apdu = bytes([mcla, ins, p1, p2, mlc]) + cmd_data
        cmac = self.sk.calc_cmac(apdu)
        apdu += cmac[:self.s_mode]

        # See comment in SCP03._wrap_cmd_apdu()
        if case == 4 or case == 2:
            apdu += b'\x00'

        return apdu

    def unwrap_rsp_apdu(self, sw: bytes, rsp_apdu: bytes) -> bytes:
        # No R-MAC shall be generated and no protection shall be applied to a response that includes an error
        # status word: in this case only the status word shall be returned in the response. All status words
        # except '9000' and warning status words (i.e. '62xx' and '63xx') shall be interpreted as error status
        # words.
        logger.debug("unwrap_rsp_apdu(sw=%s, rsp_apdu=%s)", sw, rsp_apdu)
        if not self.do_rmac:
            assert not self.do_renc
            return rsp_apdu

        if sw != b'\x90\x00' and sw[0] not in [0x62, 0x63]:
            return rsp_apdu
        response_data = rsp_apdu[:-self.s_mode]
        rmac = rsp_apdu[-self.s_mode:]
        rmac_exp = self.sk.calc_rmac(response_data + sw)[:self.s_mode]
        if rmac != rmac_exp:
            raise ValueError("R-MAC value not matching: received: %s, computed: %s" % (rmac, rmac_exp))

        if self.do_renc:
            # decrypt response data
            decrypted = self.sk._decrypt(response_data)
            logger.debug("decrypted: %s", b2h(decrypted))
            # remove padding
            response_data = unpad80(decrypted)
            logger.debug("response_data: %s", b2h(response_data))

        return response_data
