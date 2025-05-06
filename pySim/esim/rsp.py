"""Implementation of GSMA eSIM RSP (Remote SIM Provisioning) as per SGP22 v3.0"""

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


from typing import Optional
import shelve

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import x509
from osmocom.utils import b2h
from osmocom.tlv import bertlv_parse_one_rawtag, bertlv_return_one_rawtlv

from pySim.esim import compile_asn1_subdir

asn1 = compile_asn1_subdir('rsp')

class RspSessionState:
    """Encapsulates the state of a RSP session.  It is created during the initiateAuthentication
    and subsequently used by further API calls using the same transactionId.  The session state
    is removed either after cancelSession or after notification.
    TODO: add some kind of time based expiration / garbage collection."""
    def __init__(self, transactionId: str, serverChallenge: bytes, ci_cert_id: bytes):
        self.transactionId = transactionId
        self.serverChallenge = serverChallenge
        #  used at a later point between API calls
        self.ci_cert_id = ci_cert_id
        self.euicc_cert: Optional[x509.Certificate] = None
        self.eum_cert: Optional[x509.Certificate] = None
        self.eid: Optional[bytes] = None
        self.profileMetadata: Optional['ProfileMetadata'] = None
        self.smdpSignature2_do = None
        # really only needed while processing getBoundProfilePackage request?
        self.euicc_otpk: Optional[bytes] = None
        self.smdp_ot: Optional[ec.EllipticCurvePrivateKey] = None
        self.smdp_otpk: Optional[bytes] = None
        self.host_id: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None


    def __getstate__(self):
        """helper function called when pickling the object to persistent storage.  We must pickel all
        members that are not pickle-able."""
        state = self.__dict__.copy()
        # serialize eUICC certificate as DER
        if state.get('euicc_cert', None):
            state['_euicc_cert'] = self.euicc_cert.public_bytes(Encoding.DER)
            del state['euicc_cert']
        # serialize EUM certificate as DER
        if state.get('eum_cert', None):
            state['_eum_cert'] = self.eum_cert.public_bytes(Encoding.DER)
            del state['eum_cert']
        # serialize one-time SMDP private key to integer + curve
        if state.get('smdp_ot', None):
            state['_smdp_otsk'] = self.smdp_ot.private_numbers().private_value
            state['_smdp_ot_curve'] = self.smdp_ot.curve
            del state['smdp_ot']
        return state

    def __setstate__(self, state):
        """helper function called when unpickling the object from persistent storage. We must recreate all
        members from the state generated in __getstate__ above."""
        # restore eUICC certificate from DER
        if '_euicc_cert' in state:
            self.euicc_cert = x509.load_der_x509_certificate(state['_euicc_cert'])
            del state['_euicc_cert']
        else:
            self.euicc_cert = None
        # restore EUM certificate from DER
        if '_eum_cert' in state:
            self.eum_cert = x509.load_der_x509_certificate(state['_eum_cert'])
            del state['_eum_cert']
        # restore one-time SMDP private key from integer + curve
        if state.get('_smdp_otsk', None):
            self.smdp_ot = ec.derive_private_key(state['_smdp_otsk'], state['_smdp_ot_curve'])
            # FIXME: how to add the public key from smdp_otpk to an instance of EllipticCurvePrivateKey?
            del state['_smdp_otsk']
            del state['_smdp_ot_curve']
        # automatically recover all the remainig state
        self.__dict__.update(state)


class RspSessionStore(shelve.DbfilenameShelf):
    """A derived class as wrapper around the database-backed non-volatile storage 'shelve', in case we might
    need to extend it in the future. We use it to store RspSessionState objects indexed by transactionId."""

def extract_euiccSigned1(authenticateServerResponse: bytes) -> bytes:
    """Extract the raw, DER-encoded binary euiccSigned1 field from the given AuthenticateServerResponse. This
    is needed due to the very peculiar SGP.22 notion of signing sections of DER-encoded ASN.1 objects."""
    rawtag, l, v, remainder = bertlv_parse_one_rawtag(authenticateServerResponse)
    if len(remainder):
        raise ValueError('Excess data at end of TLV')
    if rawtag != 0xbf38:
        raise ValueError('Unexpected outer tag: %s' % b2h(rawtag))
    rawtag, l, v1, remainder = bertlv_parse_one_rawtag(v)
    if rawtag != 0xa0:
        raise ValueError('Unexpected tag where CHOICE was expected')
    rawtag, l, tlv2, remainder = bertlv_return_one_rawtlv(v1)
    if rawtag != 0x30:
        raise ValueError('Unexpected tag where SEQUENCE was expected')
    return tlv2

def extract_euiccSigned2(prepareDownloadResponse: bytes) -> bytes:
    """Extract the raw, DER-encoded binary euiccSigned2 field from the given prepareDownloadrResponse. This is
    needed due to the very peculiar SGP.22 notion of signing sections of DER-encoded ASN.1 objects."""
    rawtag, l, v, remainder = bertlv_parse_one_rawtag(prepareDownloadResponse)
    if len(remainder):
        raise ValueError('Excess data at end of TLV')
    if rawtag != 0xbf21:
        raise ValueError('Unexpected outer tag: %s' % b2h(rawtag))
    rawtag, l, v1, remainder = bertlv_parse_one_rawtag(v)
    if rawtag != 0xa0:
        raise ValueError('Unexpected tag where CHOICE was expected')
    rawtag, l, tlv2, remainder = bertlv_return_one_rawtlv(v1)
    if rawtag != 0x30:
        raise ValueError('Unexpected tag where SEQUENCE was expected')
    return tlv2
