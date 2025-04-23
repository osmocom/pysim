"""Code related to SMS Encoding/Decoding"""
# simplistic SMS T-PDU code, as unfortunately nobody bothered to port the python smspdu
# module to python3, and I gave up after >= 3 hours of trying and failing to do so

# (C) 2022 by Harald Welte <laforge@osmocom.org>
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

import typing
import abc
from bidict import bidict
from construct import Int8ub, Byte, Bit, Flag, BitsInteger
from construct import Struct, Enum, Tell, BitStruct, this, Padding
from construct import Prefixed, GreedyRange
from osmocom.construct import HexAdapter, BcdAdapter, TonNpi, Bytes, GreedyBytes
from osmocom.utils import Hexstr, h2b, b2h

from smpp.pdu import pdu_types, operations

BytesOrHex = typing.Union[Hexstr, bytes]

class UserDataHeader:
    # a single IE in the user data header
    ie_c = Struct('iei'/Int8ub, 'length'/Int8ub, 'value'/Bytes(this.length))
    # parser for the full UDH: Length octet followed by sequence of IEs
    _construct = Struct('ies'/Prefixed(Int8ub, GreedyRange(ie_c)),
                        'data'/GreedyBytes)

    def __init__(self, ies=[]):
        self.ies = ies

    def __repr__(self) -> str:
        return 'UDH(%r)' % self.ies

    def has_ie(self, iei:int) -> bool:
        for ie in self.ies:
            if ie['iei'] == iei:
                return True
        return False

    @classmethod
    def from_bytes(cls, inb: BytesOrHex) -> typing.Tuple['UserDataHeader', bytes]:
        if isinstance(inb, str):
            inb = h2b(inb)
        res = cls._construct.parse(inb)
        return cls(res['ies']), res['data']

    def to_bytes(self) -> bytes:
        return self._construct.build({'ies':self.ies, 'data':b''})


def smpp_dcs_is_8bit(dcs: pdu_types.DataCoding) -> bool:
    """Determine if the given SMPP data coding scheme is 8-bit or not."""
    if dcs == pdu_types.DataCoding(pdu_types.DataCodingScheme.DEFAULT,
                                   pdu_types.DataCodingDefault.OCTET_UNSPECIFIED):
        return True
    if dcs == pdu_types.DataCoding(pdu_types.DataCodingScheme.DEFAULT,
                                   pdu_types.DataCodingDefault.OCTET_UNSPECIFIED_COMMON):
        return True
    # pySim/sms.py:72:21: E1101: Instance of 'DataCodingScheme' has no 'GSM_MESSAGE_CLASS' member (no-member)
    # pylint: disable=no-member
    if dcs.scheme == pdu_types.DataCodingScheme.GSM_MESSAGE_CLASS and dcs.schemeData['msgCoding'] == pdu_types.DataCodingGsmMsgCoding.DATA_8BIT:
        return True
    else:
        return False

def ensure_smpp_is_8bit(dcs: pdu_types.DataCoding):
    """Assert if given SMPP data coding scheme is not 8-bit."""
    if not smpp_dcs_is_8bit(dcs):
        raise ValueError('We only support 8bit coded SMS for now')

class AddressField:
    """Representation of an address field as used in SMS T-PDU."""
    _construct = Struct('addr_len'/Int8ub,
                        'type_of_addr'/TonNpi,
                        'digits'/BcdAdapter(Bytes(this.addr_len//2 + this.addr_len%2)),
                        'tell'/Tell)
    smpp_map_npi = bidict({
        'UNKNOWN': 'unknown',
        'ISDN': 'isdn_e164',
        'DATA': 'data_x121',
        'TELEX': 'telex_f69',
        'LAND_MOBILE': 'sc_specific6',
        'NATIONAL': 'national',
        'PRIVATE': 'private',
        'ERMES': 'ermes',
        })
    smpp_map_ton = bidict({
        'UNKNOWN': 'unknown',
        'INTERNATIONAL': 'international',
        'NATIONAL': 'national',
        'NETWORK_SPECIFIC': 'network_specific',
        'SUBSCRIBER_NUMBER': 'short_code',
        'ALPHANUMERIC': 'alphanumeric',
        'ABBREVIATED': 'abbreviated',
        })


    def __init__(self, digits, ton='unknown', npi='unknown'):
        self.ton = ton
        self.npi = npi
        self.digits = digits

    def __str__(self):
        return 'AddressField(TON=%s, NPI=%s, %s)' % (self.ton, self.npi, self.digits)

    @classmethod
    def from_bytes(cls, inb: BytesOrHex) -> typing.Tuple['AddressField', bytes]:
        """Construct an AddressField instance from the binary T-PDU address format."""
        if isinstance(inb, str):
            inb = h2b(inb)
        res = cls._construct.parse(inb)
        #print("size: %s" % cls._construct.sizeof())
        ton = res['type_of_addr']['type_of_number']
        npi = res['type_of_addr']['numbering_plan_id']
        # return resulting instance + remainder bytes
        return cls(res['digits'][:res['addr_len']], ton, npi), inb[res['tell']:]

    @classmethod
    def from_smpp(cls, addr, ton, npi) -> 'AddressField':
        """Construct an AddressField from {source,dest}_addr_{,ton,npi} attributes of smpp.pdu."""
        # return the resulting instance
        return cls(addr.decode('ascii'), AddressField.smpp_map_ton[ton.name], AddressField.smpp_map_npi[npi.name])

    def to_smpp(self):
        """Return smpp.pdo.*.source,dest}_addr_{,ton,npi} attributes for given AddressField."""
        return (self.digits, self.smpp_map_ton.inverse[self.ton], self.smpp_map_npi.inverse[self.npi])

    def to_bytes(self) -> bytes:
        """Encode the AddressField into the binary representation as used in T-PDU."""
        num_digits = len(self.digits)
        if num_digits % 2:
            self.digits += 'f'
        d = {
            'addr_len': num_digits,
            'type_of_addr': {
                'ext': True,
                'type_of_number': self.ton,
                'numbering_plan_id': self.npi,
                },
            'digits': self.digits,
            }
        return self._construct.build(d)


class SMS_TPDU(abc.ABC):
    """Base class for a SMS T-PDU."""
    def __init__(self, **kwargs):
        self.tp_mti = kwargs.get('tp_mti', None)
        self.tp_rp = kwargs.get('tp_rp', False)
        self.tp_udhi = kwargs.get('tp_udhi', False)
        self.tp_pid = kwargs.get('tp_pid', None)
        self.tp_dcs = kwargs.get('tp_dcs', None)
        self.tp_udl = kwargs.get('tp_udl', None)
        self.tp_ud = kwargs.get('tp_ud', None)



class SMS_DELIVER(SMS_TPDU):
    """Representation of a SMS-DELIVER T-PDU. This is the Network to MS/UE (downlink) direction."""
    flags_construct = BitStruct('tp_rp'/Flag, 'tp_udhi'/Flag, 'tp_rp'/Flag, 'tp_sri'/Flag,
                                Padding(1), 'tp_mms'/Flag, 'tp_mti'/BitsInteger(2))
    def __init__(self, **kwargs):
        kwargs['tp_mti'] = 0
        super().__init__(**kwargs)
        self.tp_lp = kwargs.get('tp_lp', False)
        self.tp_mms = kwargs.get('tp_mms', False)
        self.tp_oa = kwargs.get('tp_oa', None)
        self.tp_scts = kwargs.get('tp_scts', None)
        self.tp_sri = kwargs.get('tp_sri', False)

    def __repr__(self):
        return '%s(MTI=%s, MMS=%s, LP=%s, RP=%s, UDHI=%s, SRI=%s, OA=%s, PID=%2x, DCS=%x, SCTS=%s, UDL=%u, UD=%s)' % (self.__class__.__name__, self.tp_mti, self.tp_mms, self.tp_lp, self.tp_rp, self.tp_udhi, self.tp_sri, self.tp_oa, self.tp_pid, self.tp_dcs, self.tp_scts, self.tp_udl, self.tp_ud)

    @classmethod
    def from_bytes(cls, inb: BytesOrHex) -> 'SMS_DELIVER':
        """Construct a SMS_DELIVER instance from the binary encoded format as used in T-PDU."""
        if isinstance(inb, str):
            inb = h2b(inb)
        d = SMS_DELIVER.flags_construct.parse(inb)
        oa, remainder = AddressField.from_bytes(inb[1:])
        d['tp_oa'] = oa
        offset = 0
        d['tp_pid'] = remainder[offset]
        offset += 1
        d['tp_dcs'] = remainder[offset]
        offset += 1
        # TODO: further decode
        d['tp_scts'] = remainder[offset:offset+7]
        offset += 7
        d['tp_udl'] = remainder[offset]
        offset += 1
        d['tp_ud'] = remainder[offset:]
        return cls(**d)

    def to_bytes(self) -> bytes:
        """Encode a SMS_DELIVER instance to the binary encoded format as used in T-PDU."""
        outb = bytearray()
        d = {
            'tp_mti': self.tp_mti, 'tp_mms': self.tp_mms, 'tp_lp': self.tp_lp,
            'tp_rp': self.tp_rp, 'tp_udhi': self.tp_udhi, 'tp_sri': self.tp_sri,
            }
        flags = SMS_DELIVER.flags_construct.build(d)
        outb.extend(flags)
        outb.extend(self.tp_oa.to_bytes())
        outb.append(self.tp_pid)
        outb.append(self.tp_dcs)
        outb.extend(self.tp_scts)
        outb.append(self.tp_udl)
        outb.extend(self.tp_ud)

        return outb

    @classmethod
    def from_smpp(cls, smpp_pdu) -> 'SMS_DELIVER':
        """Construct a SMS_DELIVER instance from the deliver format used by smpp.pdu."""
        if smpp_pdu.id == pdu_types.CommandId.submit_sm:
            return cls.from_smpp_submit(smpp_pdu)
        else:
            raise ValueError('Unsupported SMPP commandId %s' % smpp_pdu.id)

    @classmethod
    def from_smpp_submit(cls, smpp_pdu) -> 'SMS_DELIVER':
        """Construct a SMS_DELIVER instance from the submit format used by smpp.pdu."""
        ensure_smpp_is_8bit(smpp_pdu.params['data_coding'])
        tp_oa = AddressField.from_smpp(smpp_pdu.params['source_addr'],
                                      smpp_pdu.params['source_addr_ton'],
                                      smpp_pdu.params['source_addr_npi'])
        tp_ud = smpp_pdu.params['short_message']
        d = {
            'tp_lp': False,
            'tp_mms': False,
            'tp_oa': tp_oa,
            'tp_scts': h2b('22705200000000'), # FIXME
            'tp_sri': False,
            'tp_rp': False,
            'tp_udhi': pdu_types.EsmClassGsmFeatures.UDHI_INDICATOR_SET in smpp_pdu.params['esm_class'].gsmFeatures,
            'tp_pid': smpp_pdu.params['protocol_id'],
            'tp_dcs': 0xF6, # we only deal with binary SMS here
            'tp_udl': len(tp_ud),
            'tp_ud': tp_ud,
            }
        return cls(**d)

    @classmethod
    def from_submit(cls, submit: 'SMS_SUBMIT') -> 'SMS_DELIVER':
        """Construct a SMS_DELIVER instance from a SMS_SUBMIT instance."""
        d = {
            # common fields (SMS_TPDU base class) which exist in submit, so we can copy them
            'tp_mti': submit.tp_mti,
            'tp_rp': submit.tp_rp,
            'tp_udhi': submit.tp_udhi,
            'tp_pid': submit.tp_pid,
            'tp_dcs': submit.tp_dcs,
            'tp_udl': submit.tp_udl,
            'tp_ud': submit.tp_ud,
            # SMS_DELIVER specific fields
            'tp_lp': False,
            'tp_mms': False,
            'tp_oa': None,
            'tp_scts': h2b('22705200000000'), # FIXME
            'tp_sri': False,
            }
        return cls(**d)

    def to_smpp(self) -> pdu_types.PDU:
        """Translate a SMS_DELIVER instance to a smpp.pdu.operations.DeliverSM instance."""
        # we only deal with binary SMS here:
        if self.tp_dcs != 0xF6:
            raise ValueError('Unsupported DCS: We only support DCS=0xF6 for now')
        dcs = pdu_types.DataCoding(pdu_types.DataCodingScheme.DEFAULT,
                                   pdu_types.DataCodingDefault.OCTET_UNSPECIFIED)
        esm_class = pdu_types.EsmClass(pdu_types.EsmClassMode.DEFAULT, pdu_types.EsmClassType.DEFAULT,
                                       gsmFeatures=[pdu_types.EsmClassGsmFeatures.UDHI_INDICATOR_SET])
        if self.tp_oa:
            oa_digits, oa_ton, oa_npi = self.tp_oa.to_smpp()
        else:
            oa_digits, oa_ton, oa_npi = None, None, None
        return operations.DeliverSM(source_addr=oa_digits,
                                    source_addr_ton=oa_ton,
                                    source_addr_npi=oa_npi,
                                    #destination_addr=ESME_MSISDN,
                                    esm_class=esm_class,
                                    protocol_id=self.tp_pid,
                                    data_coding=dcs,
                                    short_message=self.tp_ud)



class SMS_SUBMIT(SMS_TPDU):
    """Representation of a SMS-SUBMIT T-PDU. This is the MS/UE -> network (uplink) direction."""
    flags_construct = BitStruct('tp_srr'/Flag, 'tp_udhi'/Flag, 'tp_rp'/Flag,
                                'tp_vpf'/Enum(BitsInteger(2), none=0, relative=2, enhanced=1, absolute=3),
                                'tp_rd'/Flag, 'tp_mti'/BitsInteger(2))
    def __init__(self, **kwargs):
        kwargs['tp_mti'] = 1
        super().__init__(**kwargs)
        self.tp_rd = kwargs.get('tp_rd', False)
        self.tp_vpf = kwargs.get('tp_vpf', 'none')
        self.tp_srr = kwargs.get('tp_srr', False)
        self.tp_mr = kwargs.get('tp_mr', None)
        self.tp_da = kwargs.get('tp_da', None)
        self.tp_vp = kwargs.get('tp_vp', None)

    def __repr__(self):
        return '%s(MTI=%s, RD=%s, VPF=%u, RP=%s, UDHI=%s, SRR=%s, DA=%s, PID=%2x, DCS=%x, VP=%s, UDL=%u, UD=%s)' % (self.__class__.__name__, self.tp_mti, self.tp_rd, self.tp_vpf, self.tp_rp, self.tp_udhi, self.tp_srr, self.tp_da, self.tp_pid, self.tp_dcs, self.tp_vp, self.tp_udl, self.tp_ud)

    @classmethod
    def from_bytes(cls, inb:BytesOrHex) -> 'SMS_SUBMIT':
        """Construct a SMS_SUBMIT instance from the binary encoded format as used in T-PDU."""
        offset = 0
        if isinstance(inb, str):
            inb = h2b(inb)
        d = SMS_SUBMIT.flags_construct.parse(inb)
        offset += 1
        d['tp_mr']= inb[offset]
        offset += 1
        da, remainder = AddressField.from_bytes(inb[2:])
        d['tp_da'] = da

        offset = 0
        d['tp_pid'] = remainder[offset]
        offset += 1
        d['tp_dcs'] = remainder[offset]
        offset += 1
        if d['tp_vpf'] == 'none':
            pass
        elif d['tp_vpf'] == 'relative':
            # TODO: further decode
            d['tp_vp'] = remainder[offset:offset+1]
            offset += 1
        elif d['tp_vpf'] == 'enhanced':
            # TODO: further decode
            d['tp_vp'] = remainder[offset:offset+7]
            offset += 7
        elif d['tp_vpf'] == 'absolute':
            # TODO: further decode
            d['tp_vp'] = remainder[offset:offset+7]
            offset += 7
        else:
            raise ValueError('Invalid VPF: %s' % d['tp_vpf'])
        d['tp_udl'] = remainder[offset]
        offset += 1
        d['tp_ud'] = remainder[offset:]
        return cls(**d)

    def to_bytes(self) -> bytes:
        """Encode a SMS_SUBMIT instance to the binary encoded format as used in T-PDU."""
        outb = bytearray()
        d = {
            'tp_mti': self.tp_mti, 'tp_rd': self.tp_rd, 'tp_vpf': self.tp_vpf,
            'tp_rp': self.tp_rp, 'tp_udhi': self.tp_udhi, 'tp_srr': self.tp_srr,
            }
        flags = SMS_SUBMIT.flags_construct.build(d)
        outb.extend(flags)
        outb.append(self.tp_mr)
        outb.extend(self.tp_da.to_bytes())
        outb.append(self.tp_pid)
        outb.append(self.tp_dcs)
        if self.tp_vpf != 'none':
            outb.extend(self.tp_vp)
        outb.append(self.tp_udl)
        outb.extend(self.tp_ud)
        return outb

    @classmethod
    def from_smpp(cls, smpp_pdu) -> 'SMS_SUBMIT':
        """Construct a SMS_SUBMIT instance from the format used by smpp.pdu."""
        if smpp_pdu.id == pdu_types.CommandId.submit_sm:
            return cls.from_smpp_submit(smpp_pdu)
        else:
            raise ValueError('Unsupported SMPP commandId %s' % smpp_pdu.id)

    @classmethod
    def from_smpp_submit(cls, smpp_pdu) -> 'SMS_SUBMIT':
        """Construct a SMS_SUBMIT instance from the submit format used by smpp.pdu."""
        ensure_smpp_is_8bit(smpp_pdu.params['data_coding'])
        tp_da = AddressField.from_smpp(smpp_pdu.params['destination_addr'],
                                       smpp_pdu.params['dest_addr_ton'],
                                       smpp_pdu.params['dest_addr_npi'])
        tp_ud = smpp_pdu.params['short_message']
        #vp_smpp = smpp_pdu.params['validity_period']
        #if not vp_smpp:
        #    vpf = 'none'
        d = {
            'tp_rd': True if smpp_pdu.params['replace_if_present_flag'].name == 'REPLACE' else False,
            'tp_vpf': None, # vpf,
            'tp_rp': False, # related to ['registered_delivery'] ?
            'tp_udhi': pdu_types.EsmClassGsmFeatures.UDHI_INDICATOR_SET in smpp_pdu.params['esm_class'].gsmFeatures,
            'tp_srr': True if smpp_pdu.params['registered_delivery'] else False,
            'tp_mr': 0, # FIXME: sm_default_msg_id ?
            'tp_da': tp_da,
            'tp_pid': smpp_pdu.params['protocol_id'],
            'tp_dcs': 0xF6, # FIXME: we only deal with binary SMS here
            'tp_vp': None, # FIXME: implement VPF conversion
            'tp_udl': len(tp_ud),
            'tp_ud': tp_ud,
            }
        return cls(**d)

    def to_smpp(self) -> pdu_types.PDU:
        """Translate a SMS_SUBMIT instance to a smpp.pdu.operations.SubmitSM instance."""
        esm_class = pdu_types.EsmClass(pdu_types.EsmClassMode.DEFAULT, pdu_types.EsmClassType.DEFAULT)
        reg_del = pdu_types.RegisteredDelivery(pdu_types.RegisteredDeliveryReceipt.NO_SMSC_DELIVERY_RECEIPT_REQUESTED)
        if self.tp_rp:
            repl_if = pdu_types.ReplaceIfPresentFlag.REPLACE
        else:
            repl_if = pdu_types.ReplaceIfPresentFlag.DO_NOT_REPLACE
        # we only deal with binary SMS here:
        if self.tp_dcs != 0xF6:
            raise ValueError('Unsupported DCS: We only support DCS=0xF6 for now')
        dc = pdu_types.DataCoding(pdu_types.DataCodingScheme.DEFAULT, pdu_types.DataCodingDefault.OCTET_UNSPECIFIED)
        (daddr, ton, npi) = self.tp_da.to_smpp()
        return operations.SubmitSM(service_type='',
                                   source_addr_ton=pdu_types.AddrTon.ALPHANUMERIC,
                                   source_addr_npi=pdu_types.AddrNpi.UNKNOWN,
                                   source_addr='simcard',
                                   dest_addr_ton=ton,
                                   dest_addr_npi=npi,
                                   destination_addr=daddr,
                                   esm_class=esm_class,
                                   protocol_id=self.tp_pid,
                                   priority_flag=pdu_types.PriorityFlag.LEVEL_0,
                                   #schedule_delivery_time,
                                   #validity_period,
                                   registered_delivery=reg_del,
                                   replace_if_present_flag=repl_if,
                                   data_coding=dc,
                                   #sm_default_msg_id,
                                   short_message=self.tp_ud)
