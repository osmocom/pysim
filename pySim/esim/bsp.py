"""Implementation of GSMA eSIM RSP (Remote SIM Provisioning BSP (BPP Protection Protocol),
where BPP is the Bound  Profile Package.  So the full expansion is the
"GSMA eSIM Remote SIM Provisioning Bound Profile Packate Protection Protocol"

Originally (SGP.22 v2.x) this was called SCP03t, but it has since been renamed to BSP."""

# (C) 2023 by Harald Welte <laforge@osmocom.org>
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

# SGP.22 v3.0 Section 2.5.3:
# That block of data is split into segments of a maximum size of 1020 bytes (including the tag, length field and MAC).

import abc
from typing import List
import logging

# for BSP key derivation
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

from osmocom.utils import b2h
from osmocom.tlv import bertlv_encode_len, bertlv_parse_one

# don't log by default
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

MAX_SEGMENT_SIZE = 1020

class BspAlgo(abc.ABC):
    """Base class representing a cryptographic algorithm within the BSP (BPP Security Protocol)."""
    blocksize: int

    def _get_padding(self, in_len: int, multiple: int, padding: int = 0) -> bytes:
        """Return padding bytes towards multiple of N."""
        if in_len % multiple == 0:
            return b''
        pad_cnt = multiple - (in_len % multiple)
        return bytes([padding]) * pad_cnt

    def _pad_to_multiple(self, indat: bytes, multiple: int, padding: int = 0) -> bytes:
        """Pad the input data to multiples of 'multiple'."""
        return indat + self._get_padding(len(indat), multiple, padding)

    def __str__(self):
        return self.__class__.__name__

class BspAlgoCrypt(BspAlgo, abc.ABC):
    """Base class representing an encryption/decryption algorithm within the BSP (BPP Security Protocol)."""

    def __init__(self, s_enc: bytes):
        self.s_enc = s_enc
        self.block_nr = 1

    def encrypt(self, data:bytes) -> bytes:
        """Encrypt given input bytes using the key material given in constructor."""
        padded_data = self._pad_to_multiple(data, self.blocksize)
        block_nr = self.block_nr
        ciphertext = self._encrypt(padded_data)
        logger.debug("encrypt(block_nr=%u, s_enc=%s, plaintext=%s, padded=%s) -> %s",
                     block_nr, b2h(self.s_enc), b2h(data), b2h(padded_data), b2h(ciphertext))
        return ciphertext

    def decrypt(self, data:bytes) -> bytes:
        """Decrypt given input bytes using the key material given in constructor."""
        return self._unpad(self._decrypt(data))

    @abc.abstractmethod
    def _unpad(self, padded: bytes) -> bytes:
        """Remove the padding from padded data."""

    @abc.abstractmethod
    def _encrypt(self, data:bytes) -> bytes:
        """Actual implementation, to be implemented by derived class."""

    @abc.abstractmethod
    def _decrypt(self, data:bytes) -> bytes:
        """Actual implementation, to be implemented by derived class."""

class BspAlgoCryptAES128(BspAlgoCrypt):
    """AES-CBC-128 implementation of the BPP Security Protocol for GSMA SGP.22 eSIM."""
    name = 'AES-CBC-128'
    blocksize = 16

    def _get_padding(self, in_len: int, multiple: int, padding: int = 0):
        # SGP.22 section 2.6.4.4
        # Append a byte with value '80' to the right of the data block;
        # Append 0 to 15 bytes with value '00' so that the length of the padded data block
        # is a multiple of 16 bytes.
        return b'\x80' + super()._get_padding(in_len + 1, multiple, padding)

    def _unpad(self, padded: bytes) -> bytes:
        """Remove the customary 80 00 00 ... padding used for AES."""
        # first remove any trailing zero bytes
        stripped = padded.rstrip(b'\0')
        # then remove the final 80
        assert stripped[-1] == 0x80
        return stripped[:-1]

    def _get_icv(self):
        # The binary value of this number SHALL be left padded with zeroes to form a full block.
        data = self.block_nr.to_bytes(self.blocksize, "big")
        #iv = bytes([0] * (self.blocksize-1)) + b'\x01'
        iv = bytes([0] * self.blocksize)
        # This block SHALL be encrypted with S-ENC to produce the ICV for command encryption.
        cipher = AES.new(self.s_enc, AES.MODE_CBC, iv)
        icv = cipher.encrypt(data)
        logger.debug("_get_icv(block_nr=%u, data=%s) -> icv=%s", self.block_nr, b2h(data), b2h(icv))
        self.block_nr = self.block_nr + 1
        return icv

    def _encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.s_enc, AES.MODE_CBC, self._get_icv())
        return cipher.encrypt(data)

    def _decrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.s_enc, AES.MODE_CBC, self._get_icv())
        return cipher.decrypt(data)


class BspAlgoMac(BspAlgo, abc.ABC):
    """Base class representing a message authentication code algorithm within the BSP (BPP Security Protocol)."""
    l_mac = 0 # must be overridden by derived class

    def __init__(self, s_mac: bytes, initial_mac_chaining_value: bytes):
        self.s_mac = s_mac
        self.mac_chain = initial_mac_chaining_value

    def auth(self, tag: int, data: bytes) -> bytes:
        assert tag in range (256)
        # The input data used for C-MAC computation comprises the MAC Chaining value, the tag, the final length and the result of step 2
        lcc = len(data) + self.l_mac
        tag_and_length = bytes([tag]) + bertlv_encode_len(lcc)
        temp_data = self.mac_chain + tag_and_length + data
        old_mcv = self.mac_chain
        c_mac = self._auth(temp_data)
        # The output data is computed by concatenating the following data: the tag, the final length, the result of step 2 and the C-MAC value.
        ret = tag_and_length + data + c_mac
        logger.debug("auth(tag=0x%x, mcv=%s, s_mac=%s, plaintext=%s, temp=%s) -> %s",
                     tag, b2h(old_mcv), b2h(self.s_mac), b2h(data), b2h(temp_data), b2h(ret))
        return ret

    def verify(self, ciphertext: bytes) -> bool:
        mac_stripped = ciphertext[0:-self.l_mac]
        mac_received = ciphertext[-self.l_mac:]
        temp_data = self.mac_chain + mac_stripped
        mac_computed = self._auth(temp_data)
        if mac_received != mac_computed:
            raise ValueError("MAC value not matching: received: %s, computed: %s" % (mac_received, mac_computed))
        return mac_stripped

    @abc.abstractmethod
    def _auth(self, temp_data: bytes) -> bytes:
        """To be implemented by algorithm specific derived class."""

class BspAlgoMacAES128(BspAlgoMac):
    """AES-CMAC-128 implementation of the BPP Security Protocol for GSMA SGP.22 eSIM."""
    name = 'AES-CMAC-128'
    l_mac = 8

    def _auth(self, temp_data: bytes) -> bytes:
        # The full MAC value is computed using the MACing algorithm as defined in table 4c.
        cmac = CMAC.new(self.s_mac, ciphermod=AES)
        cmac.update(temp_data)
        full_c_mac = cmac.digest()
        # Subsequent MAC chaining values are the full result of step 4 of the previous data block
        self.mac_chain = full_c_mac
        # If the algorithm is AES-CBC-128 or SM4-CBC, the C-MAC value is the 8 most significant bytes of the result of step 4
        return full_c_mac[0:8]



def bsp_key_derivation(shared_secret: bytes, key_type: int, key_length: int, host_id: bytes, eid, l : int = 16):
    """BSP protocol key derivation as per SGP.22 v3.0 Section 2.6.4.2"""
    assert key_type <= 255
    assert key_length <= 255

    host_id_lv = bertlv_encode_len(len(host_id)) + host_id
    eid_lv = bertlv_encode_len(len(eid)) + eid
    shared_info = bytes([key_type, key_length]) + host_id_lv + eid_lv
    logger.debug("kdf_shared_info: %s", b2h(shared_info))

    # X9.63 Key Derivation Function with SHA256
    xkdf = X963KDF(algorithm=hashes.SHA256(), length=l*3, sharedinfo=shared_info)
    out = xkdf.derive(shared_secret)
    logger.debug("kdf_out: %s", b2h(out))

    initial_mac_chaining_value = out[0:l]
    s_enc = out[l:2*l]
    s_mac = out[l*2:3*l]

    return s_enc, s_mac, initial_mac_chaining_value



class BspInstance:
    """An instance of the BSP crypto.  Initialized once with the key material via constructor,
    then the user can call any number of encrypt_and_mac cycles to protect plaintext and
    generate the respective ciphertext."""
    def __init__(self, s_enc: bytes, s_mac: bytes, initial_mcv: bytes):
        logger.debug("%s(s_enc=%s, s_mac=%s, initial_mcv=%s)", self.__class__.__name__, b2h(s_enc), b2h(s_mac), b2h(initial_mcv))
        self.c_algo = BspAlgoCryptAES128(s_enc)
        self.m_algo = BspAlgoMacAES128(s_mac, initial_mcv)

        TAG_LEN = 1
        length_len = len(bertlv_encode_len(MAX_SEGMENT_SIZE))
        self.max_payload_size = MAX_SEGMENT_SIZE - TAG_LEN - length_len - self.m_algo.l_mac

    @classmethod
    def from_kdf(cls, shared_secret: bytes, key_type: int, key_length: int, host_id: bytes, eid: bytes):
        """Convenience constructor for constructing an instance with keys from KDF."""
        s_enc, s_mac, initial_mcv = bsp_key_derivation(shared_secret, key_type, key_length, host_id, eid)
        return cls(s_enc, s_mac, initial_mcv)

    def encrypt_and_mac_one(self, tag: int, plaintext:bytes) -> bytes:
        """Encrypt + MAC a single plaintext TLV. Returns the protected ciphertext."""
        assert tag <= 255
        assert len(plaintext) <= self.max_payload_size
        logger.debug("encrypt_and_mac_one(tag=0x%x, plaintext=%s)", tag, b2h(plaintext))
        ciphered = self.c_algo.encrypt(plaintext)
        maced = self.m_algo.auth(tag, ciphered)
        return maced

    def encrypt_and_mac(self, tag: int, plaintext:bytes) -> List[bytes]:
        remainder = plaintext
        result = []
        while len(remainder):
            remaining_len = len(remainder)
            if remaining_len < self.max_payload_size:
                segment_len = remaining_len
                segment = remainder
                remainder = b''
            else:
                segment_len = self.max_payload_size
                segment = remainder[0:segment_len]
                remainder = remainder[segment_len:]
            result.append(self.encrypt_and_mac_one(tag, segment))
        return result

    def mac_only_one(self, tag: int, plaintext: bytes) -> bytes:
        """MAC a single plaintext TLV. Returns the protected ciphertext."""
        assert tag <= 255
        assert len(plaintext) < self.max_payload_size
        maced = self.m_algo.auth(tag, plaintext)
        # The data block counter for ICV calculation is incremented also for each segment with C-MAC only.
        self.c_algo.block_nr += 1
        return maced

    def mac_only(self, tag: int, plaintext:bytes) -> List[bytes]:
        remainder = plaintext
        result = []
        while len(remainder):
            remaining_len = len(remainder)
            if remaining_len < self.max_payload_size:
                segment_len = remaining_len
                segment = remainder
                remainder = b''
            else:
                segment_len = self.max_payload_size
                segment = remainder[0:segment_len]
                remainder = remainder[segment_len:]
            result.append(self.mac_only_one(tag, segment))
        return result

    def demac_and_decrypt_one(self, ciphertext: bytes) -> bytes:
        payload = self.m_algo.verify(ciphertext)
        tdict, l, val, remain = bertlv_parse_one(payload)
        logger.debug("tag=%s, l=%u, val=%s, remain=%s", tdict, l, b2h(val), b2h(remain))
        plaintext = self.c_algo.decrypt(val)
        return plaintext

    def demac_and_decrypt(self, ciphertext_list: List[bytes]) -> bytes:
        plaintext_list = [self.demac_and_decrypt_one(x) for x in ciphertext_list]
        return b''.join(plaintext_list)

    def demac_only_one(self, ciphertext: bytes) -> bytes:
        payload = self.m_algo.verify(ciphertext)
        _tdict, _l, val, _remain = bertlv_parse_one(payload)
        # The data block counter for ICV calculation is incremented also for each segment with C-MAC only.
        self.c_algo.block_nr += 1
        return val

    def demac_only(self, ciphertext_list: List[bytes]) -> bytes:
        plaintext_list = [self.demac_only_one(x) for x in ciphertext_list]
        return b''.join(plaintext_list)
