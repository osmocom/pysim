import sys
from typing import Optional, Tuple
from importlib import resources

class PMO:
    """Convenience conversion class for ProfileManagementOperation as used in ES9+ notifications."""
    pmo4operation = {
        'install': 0x80,
        'enable': 0x40,
        'disable': 0x20,
        'delete': 0x10,
    }

    def __init__(self, op: str):
        if not op in self.pmo4operation:
            raise ValueError('Unknown operation "%s"' % op)
        self.op = op

    def to_int(self):
        return self.pmo4operation[self.op]

    @staticmethod
    def _num_bits(data: int)-> int:
        for i in range(0, 8):
            if data & (1 << i):
                return 8-i
        return 0

    def to_bitstring(self) -> Tuple[bytes, int]:
        """return value in a format as used by asn1tools for BITSTRING."""
        val = self.to_int()
        return (bytes([val]), self._num_bits(val))

    @classmethod
    def from_int(cls, i: int) -> 'PMO':
        """Parse an integer representation."""
        for k, v in cls.pmo4operation.items():
            if v == i:
                return cls(k)
        raise ValueError('Unknown PMO 0x%02x' % i)

    @classmethod
    def from_bitstring(cls, bstr: Tuple[bytes, int]) -> 'PMO':
        """Parse a asn1tools BITSTRING representation."""
        return cls.from_int(bstr[0][0])

    def __str__(self):
        return self.op

def compile_asn1_subdir(subdir_name:str, codec='der'):
    """Helper function that compiles ASN.1 syntax from all files within given subdir"""
    import asn1tools
    asn_txt = ''
    __ver = sys.version_info
    if (__ver.major, __ver.minor) >= (3, 9):
        for i in resources.files('pySim.esim').joinpath('asn1').joinpath(subdir_name).iterdir():
            asn_txt += i.read_text()
            asn_txt += "\n"
    #else:
        #print(resources.read_text(__name__, 'asn1/rsp.asn'))
    return asn1tools.compile_string(asn_txt, codec=codec)


class ActivationCode:
    """SGP.22 section 4.1 Activation Code"""
    def __init__(self, hostname:str, token:str, oid: Optional[str] = None, cc_required: Optional[bool] = False):
        if '$' in hostname:
            raise ValueError('$ sign not permitted in hostname')
        self.hostname = hostname
        if '$' in token:
            raise ValueError('$ sign not permitted in token')
        self.token = token
        # TODO: validate OID
        self.oid = oid
        self.cc_required = cc_required
        # only format 1 is specified and supported here
        self.format = 1

    @staticmethod
    def decode_str(ac: str) -> dict:
        """decode an activation code from its string representation."""
        if ac[0] != '1':
            raise ValueError("Unsupported AC_Format '%s'!" % ac[0])
        ac_elements = ac.split('$')
        d = {
            'oid': None,
            'cc_required': False,
          }
        d['format'] = ac_elements.pop(0)
        d['hostname'] = ac_elements.pop(0)
        d['token'] = ac_elements.pop(0)
        if len(ac_elements):
            oid = ac_elements.pop(0)
            if oid != '':
                d['oid'] = oid
        if len(ac_elements):
            ccr = ac_elements.pop(0)
            if ccr == '1':
                d['cc_required'] = True
        return d

    @classmethod
    def from_string(cls, ac: str) -> 'ActivationCode':
        """Create new instance from SGP.22 section 4.1 string representation."""
        d = cls.decode_str(ac)
        return cls(d['hostname'], d['token'], d['oid'], d['cc_required'])

    def to_string(self, for_qrcode:bool = False) -> str:
        """Convert from internal representation to SGP.22 section 4.1 string representation."""
        if for_qrcode:
            ret = 'LPA:'
        else:
            ret = ''
        ret += '%d$%s$%s' % (self.format, self.hostname, self.token)
        if self.oid:
            ret += '$%s' % (self.oid)
        elif self.cc_required:
            ret += '$'
        if self.cc_required:
            ret += '$1'
        return ret

    def __str__(self):
        return self.to_string()

    def to_qrcode(self):
        """Encode internal representation to QR code."""
        import qrcode
        qr = qrcode.QRCode()
        qr.add_data(self.to_string(for_qrcode=True))
        return qr.make_image()

    def __repr__(self):
        return "ActivationCode(format=%u, hostname='%s', token='%s', oid=%s, cc_required=%s)" % (self.format,
                                                                                                 self.hostname,
                                                                                                 self.token,
                                                                                                 self.oid,
                                                                                                 self.cc_required)
