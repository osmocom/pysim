################################################################################
# LEGACY
################################################################################

import abc
from smartcard.util import toBytes
from pytlv.TLV import *

from pySim.cards import SimCardBase, UiccCardBase
from pySim.utils import dec_iccid, enc_iccid, dec_imsi, enc_imsi
from pySim.utils import enc_plmn, get_addr_type
from pySim.utils import is_hex, h2b, b2h, h2s, s2h, lpad, rpad
from pySim.legacy.utils import enc_ePDGSelection, format_xplmn_w_act, format_xplmn, dec_st, enc_st
from pySim.legacy.utils import format_ePDGSelection, dec_addr_tlv, enc_addr_tlv, dec_msisdn, enc_msisdn
from pySim.legacy.ts_51_011 import EF, DF
from pySim.legacy.ts_31_102 import EF_USIM_ADF_map
from pySim.legacy.ts_31_103 import EF_ISIM_ADF_map

from pySim.ts_51_011 import EF_AD, EF_SPN

def format_addr(addr: str, addr_type: str) -> str:
    """
    helper function to format an FQDN (addr_type = '00') or IPv4
    (addr_type = '01') address string into a printable string that
    contains the hexadecimal representation and the original address
    string (addr)
    """
    res = ""
    if addr_type == '00':  # FQDN
        res += "\t%s # %s\n" % (s2h(addr), addr)
    elif addr_type == '01':  # IPv4
        octets = addr.split(".")
        addr_hex = ""
        for o in octets:
            addr_hex += ("%02x" % int(o))
        res += "\t%s # %s\n" % (addr_hex, addr)
    return res



class SimCard(SimCardBase):
    """Higher-layer class that is used *only* by legacy pySim-{prog,read}."""

    def __init__(self, scc):
        self._adm_chv_num = 4
        super().__init__(scc)

    def read_binary(self, ef, length=None, offset=0):
        ef_path = ef in EF and EF[ef] or ef
        return self._scc.read_binary(ef_path, length, offset)

    def read_record(self, ef, rec_no):
        ef_path = ef in EF and EF[ef] or ef
        return self._scc.read_record(ef_path, rec_no)

    def verify_adm(self, key):
        """Authenticate with ADM key"""
        (res, sw) = self._scc.verify_chv(self._adm_chv_num, key)
        return sw

    def read_iccid(self):
        (res, sw) = self._scc.read_binary(EF['ICCID'])
        if sw == '9000':
            return (dec_iccid(res), sw)
        else:
            return (None, sw)

    def update_iccid(self, iccid):
        data, sw = self._scc.update_binary(EF['ICCID'], enc_iccid(iccid))
        return sw

    def read_imsi(self):
        (res, sw) = self._scc.read_binary(EF['IMSI'])
        if sw == '9000':
            return (dec_imsi(res), sw)
        else:
            return (None, sw)

    def update_imsi(self, imsi):
        data, sw = self._scc.update_binary(EF['IMSI'], enc_imsi(imsi))
        return sw

    def update_acc(self, acc):
        data, sw = self._scc.update_binary(EF['ACC'], lpad(acc, 4, c='0'))
        return sw

    def read_hplmn_act(self):
        (res, sw) = self._scc.read_binary(EF['HPLMNAcT'])
        if sw == '9000':
            return (format_xplmn_w_act(res), sw)
        else:
            return (None, sw)

    def update_hplmn_act(self, mcc, mnc, access_tech='FFFF'):
        """
        Update Home PLMN with access technology bit-field

        See Section "10.3.37 EFHPLMNwAcT (HPLMN Selector with Access Technology)"
        in ETSI TS 151 011 for the details of the access_tech field coding.
        Some common values:
        access_tech = '0080' # Only GSM is selected
        access_tech = 'FFFF' # All technologies selected, even Reserved for Future Use ones
        """
        # get size and write EF.HPLMNwAcT
        data = self._scc.read_binary(EF['HPLMNwAcT'], length=None, offset=0)
        size = len(data[0]) // 2
        hplmn = enc_plmn(mcc, mnc)
        content = hplmn + access_tech
        data, sw = self._scc.update_binary(
            EF['HPLMNwAcT'], content + 'ffffff0000' * (size // 5 - 1))
        return sw

    def read_oplmn_act(self):
        (res, sw) = self._scc.read_binary(EF['OPLMNwAcT'])
        if sw == '9000':
            return (format_xplmn_w_act(res), sw)
        else:
            return (None, sw)

    def update_oplmn_act(self, mcc, mnc, access_tech='FFFF'):
        """get size and write EF.OPLMNwAcT, See note in update_hplmn_act()"""
        data = self._scc.read_binary(EF['OPLMNwAcT'], length=None, offset=0)
        size = len(data[0]) // 2
        hplmn = enc_plmn(mcc, mnc)
        content = hplmn + access_tech
        data, sw = self._scc.update_binary(
            EF['OPLMNwAcT'], content + 'ffffff0000' * (size // 5 - 1))
        return sw

    def read_plmn_act(self):
        (res, sw) = self._scc.read_binary(EF['PLMNwAcT'])
        if sw == '9000':
            return (format_xplmn_w_act(res), sw)
        else:
            return (None, sw)

    def update_plmn_act(self, mcc, mnc, access_tech='FFFF'):
        """get size and write EF.PLMNwAcT, See note in update_hplmn_act()"""
        data = self._scc.read_binary(EF['PLMNwAcT'], length=None, offset=0)
        size = len(data[0]) // 2
        hplmn = enc_plmn(mcc, mnc)
        content = hplmn + access_tech
        data, sw = self._scc.update_binary(
            EF['PLMNwAcT'], content + 'ffffff0000' * (size // 5 - 1))
        return sw

    def update_plmnsel(self, mcc, mnc):
        data = self._scc.read_binary(EF['PLMNsel'], length=None, offset=0)
        size = len(data[0]) // 2
        hplmn = enc_plmn(mcc, mnc)
        data, sw = self._scc.update_binary(
            EF['PLMNsel'], hplmn + 'ff' * (size-3))
        return sw

    def update_smsp(self, smsp):
        data, sw = self._scc.update_record(EF['SMSP'], 1, rpad(smsp, 84))
        return sw

    def update_ad(self, mnc=None, opmode=None, ofm=None, path=EF['AD']):
        """
        Update Administrative Data (AD)

        See Sec. "4.2.18 EF_AD (Administrative Data)"
        in 3GPP TS 31.102 for the details of the EF_AD contents.

        Set any parameter to None to keep old value(s) on card.

        Parameters:
                mnc (str): MNC of IMSI
                opmode (Hex-str, 1 Byte): MS Operation Mode
                ofm (Hex-str, 1 Byte): Operational Feature Monitor (OFM) aka Ciphering Indicator
                path (optional list with file path e.g. ['3f00', '7f20', '6fad'])

        Returns:
                str: Return code of write operation
        """

        ad = EF_AD()

        # read from card
        raw_hex_data, sw = self._scc.read_binary(
            path, length=None, offset=0)
        abstract_data = ad.decode_hex(raw_hex_data)

        # perform updates
        if mnc and abstract_data['extensions']:
            # Note: Since we derive the length of the MNC by the string length
            # of the mnc parameter, the caller must ensure that mnc has the
            # correct length and is padded with zeros (if necessary).
            mnclen = len(str(mnc))
            if mnclen > 3 or mnclen < 2:
                raise RuntimeError('invalid length of mnc "{}", expecting 2 or 3 digits'.format(mnc))
            abstract_data['extensions']['mnc_len'] = mnclen
        if opmode:
            opmode_num = int(opmode, 16)
            if opmode_num in [int(v) for v in EF_AD.OP_MODE]:
                abstract_data['ms_operation_mode'] = opmode_num
            else:
                raise RuntimeError('invalid opmode "{}"'.format(opmode))
        if ofm:
            abstract_data['ofm'] = bool(int(ofm, 16))

        # write to card
        raw_hex_data = ad.encode_hex(abstract_data)
        data, sw = self._scc.update_binary(path, raw_hex_data)
        return sw

    def read_spn(self):
        (content, sw) = self._scc.read_binary(EF['SPN'])
        if sw == '9000':
            abstract_data = EF_SPN().decode_hex(content)
            show_in_hplmn = abstract_data['show_in_hplmn']
            hide_in_oplmn = abstract_data['hide_in_oplmn']
            name = abstract_data['spn']
            return ((name, show_in_hplmn, hide_in_oplmn), sw)
        else:
            return (None, sw)

    def update_spn(self, name="", show_in_hplmn=False, hide_in_oplmn=False):
        abstract_data = {
            'hide_in_oplmn': hide_in_oplmn,
            'show_in_hplmn': show_in_hplmn,
            'spn': name,
        }
        content = EF_SPN().encode_hex(abstract_data)
        data, sw = self._scc.update_binary(EF['SPN'], content)
        return sw

    def read_gid1(self):
        (res, sw) = self._scc.read_binary(EF['GID1'])
        if sw == '9000':
            return (res, sw)
        else:
            return (None, sw)

    def read_msisdn(self):
        (res, sw) = self._scc.read_record(EF['MSISDN'], 1)
        if sw == '9000':
            return (dec_msisdn(res), sw)
        else:
            return (None, sw)


class UsimCard(UiccCardBase, SimCard):
    """Higher-layer class that is used *only* by legacy pySim-{prog,read}."""

    def read_ehplmn(self):
        (res, sw) = self._scc.read_binary(EF_USIM_ADF_map['EHPLMN'])
        if sw == '9000':
            return (format_xplmn(res), sw)
        else:
            return (None, sw)

    def update_ehplmn(self, mcc, mnc):
        data = self._scc.read_binary(
            EF_USIM_ADF_map['EHPLMN'], length=None, offset=0)
        size = len(data[0]) // 2
        ehplmn = enc_plmn(mcc, mnc)
        data, sw = self._scc.update_binary(EF_USIM_ADF_map['EHPLMN'], ehplmn)
        return sw

    def read_fplmn(self):
        res, sw = self._scc.read_binary(EF_USIM_ADF_map['FPLMN'])
        if sw == '9000':
            return format_xplmn(res), sw
        else:
            return None, sw

    def update_fplmn(self, fplmn):
        self._scc.select_file('3f00')
        self.select_adf_by_aid('USIM')
        size = self._scc.binary_size(EF_USIM_ADF_map['FPLMN'])
        encoded = ''.join([enc_plmn(plmn[:3], plmn[3:]) for plmn in fplmn])
        encoded = rpad(encoded, size)
        data, sw = self._scc.update_binary(EF_USIM_ADF_map['FPLMN'], encoded)
        return sw

    def read_epdgid(self):
        (res, sw) = self._scc.read_binary(EF_USIM_ADF_map['ePDGId'])
        if sw == '9000':
            try:
                addr, addr_type = dec_addr_tlv(res)
            except:
                addr = None
                addr_type = None
            return (format_addr(addr, addr_type), sw)
        else:
            return (None, sw)

    def update_epdgid(self, epdgid):
        size = self._scc.binary_size(EF_USIM_ADF_map['ePDGId']) * 2
        if len(epdgid) > 0:
            addr_type = get_addr_type(epdgid)
            if addr_type == None:
                raise ValueError(
                    "Unknown ePDG Id address type or invalid address provided")
            epdgid_tlv = rpad(enc_addr_tlv(epdgid, ('%02x' % addr_type)), size)
        else:
            epdgid_tlv = rpad('ff', size)
        data, sw = self._scc.update_binary(
            EF_USIM_ADF_map['ePDGId'], epdgid_tlv)
        return sw

    def read_ePDGSelection(self):
        (res, sw) = self._scc.read_binary(EF_USIM_ADF_map['ePDGSelection'])
        if sw == '9000':
            return (format_ePDGSelection(res), sw)
        else:
            return (None, sw)

    def update_ePDGSelection(self, mcc, mnc):
        (res, sw) = self._scc.read_binary(
            EF_USIM_ADF_map['ePDGSelection'], length=None, offset=0)
        if sw == '9000' and (len(mcc) == 0 or len(mnc) == 0):
            # Reset contents
            # 80 - Tag value
            (res, sw) = self._scc.update_binary(
                EF_USIM_ADF_map['ePDGSelection'], rpad('', len(res)))
        elif sw == '9000':
            (res, sw) = self._scc.update_binary(
                EF_USIM_ADF_map['ePDGSelection'], enc_ePDGSelection(res, mcc, mnc))
        return sw

    def read_ust(self):
        (res, sw) = self._scc.read_binary(EF_USIM_ADF_map['UST'])
        if sw == '9000':
            # Print those which are available
            return ([res, dec_st(res, table="usim")], sw)
        else:
            return ([None, None], sw)

    def update_ust(self, service, bit=1):
        (res, sw) = self._scc.read_binary(EF_USIM_ADF_map['UST'])
        if sw == '9000':
            content = enc_st(res, service, bit)
            (res, sw) = self._scc.update_binary(
                EF_USIM_ADF_map['UST'], content)
        return sw

    def update_est(self, service, bit=1):
        (res, sw) = self._scc.read_binary(EF_USIM_ADF_map['EST'])
        if sw == '9000':
            content = enc_st(res, service, bit)
            (res, sw) = self._scc.update_binary(
                EF_USIM_ADF_map['EST'], content)
        return sw



class IsimCard(UiccCardBase):
    """Higher-layer class that is used *only* by legacy pySim-{prog,read}."""

    name = 'ISIM'

    def read_pcscf(self):
        rec_cnt = self._scc.record_count(EF_ISIM_ADF_map['PCSCF'])
        pcscf_recs = ""
        for i in range(0, rec_cnt):
            (res, sw) = self._scc.read_record(EF_ISIM_ADF_map['PCSCF'], i + 1)
            if sw == '9000':
                try:
                    addr, addr_type = dec_addr_tlv(res)
                except:
                    addr = None
                    addr_type = None
                content = format_addr(addr, addr_type)
                pcscf_recs += "%s" % (len(content)
                                      and content or '\tNot available\n')
            else:
                pcscf_recs += "\tP-CSCF: Can't read, response code = %s\n" % (
                    sw)
        return pcscf_recs

    def update_pcscf(self, pcscf):
        if len(pcscf) > 0:
            addr_type = get_addr_type(pcscf)
            if addr_type == None:
                raise ValueError(
                    "Unknown PCSCF address type or invalid address provided")
            content = enc_addr_tlv(pcscf, ('%02x' % addr_type))
        else:
            # Just the tag value
            content = '80'
        rec_size_bytes = self._scc.record_size(EF_ISIM_ADF_map['PCSCF'])
        pcscf_tlv = rpad(content, rec_size_bytes*2)
        data, sw = self._scc.update_record(
            EF_ISIM_ADF_map['PCSCF'], 1, pcscf_tlv)
        return sw

    def read_domain(self):
        (res, sw) = self._scc.read_binary(EF_ISIM_ADF_map['DOMAIN'])
        if sw == '9000':
            # Skip the initial tag value ('80') byte and get length of contents
            length = int(res[2:4], 16)
            content = h2s(res[4:4+(length*2)])
            return (content, sw)
        else:
            return (None, sw)

    def update_domain(self, domain=None, mcc=None, mnc=None):
        hex_str = ""
        if domain:
            hex_str = s2h(domain)
        elif mcc and mnc:
            # MCC and MNC always has 3 digits in domain form
            plmn_str = 'mnc' + lpad(mnc, 3, "0") + '.mcc' + lpad(mcc, 3, "0")
            hex_str = s2h('ims.' + plmn_str + '.3gppnetwork.org')

        # Build TLV
        tlv = TLV(['80'])
        content = tlv.build({'80': hex_str})

        bin_size_bytes = self._scc.binary_size(EF_ISIM_ADF_map['DOMAIN'])
        data, sw = self._scc.update_binary(
            EF_ISIM_ADF_map['DOMAIN'], rpad(content, bin_size_bytes*2))
        return sw

    def read_impi(self):
        (res, sw) = self._scc.read_binary(EF_ISIM_ADF_map['IMPI'])
        if sw == '9000':
            # Skip the initial tag value ('80') byte and get length of contents
            length = int(res[2:4], 16)
            content = h2s(res[4:4+(length*2)])
            return (content, sw)
        else:
            return (None, sw)

    def update_impi(self, impi=None):
        hex_str = ""
        if impi:
            hex_str = s2h(impi)
        # Build TLV
        tlv = TLV(['80'])
        content = tlv.build({'80': hex_str})

        bin_size_bytes = self._scc.binary_size(EF_ISIM_ADF_map['IMPI'])
        data, sw = self._scc.update_binary(
            EF_ISIM_ADF_map['IMPI'], rpad(content, bin_size_bytes*2))
        return sw

    def read_impu(self):
        rec_cnt = self._scc.record_count(EF_ISIM_ADF_map['IMPU'])
        impu_recs = ""
        for i in range(0, rec_cnt):
            (res, sw) = self._scc.read_record(EF_ISIM_ADF_map['IMPU'], i + 1)
            if sw == '9000':
                # Skip the initial tag value ('80') byte and get length of contents
                length = int(res[2:4], 16)
                content = h2s(res[4:4+(length*2)])
                impu_recs += "\t%s\n" % (len(content)
                                         and content or 'Not available')
            else:
                impu_recs += "IMS public user identity: Can't read, response code = %s\n" % (
                    sw)
        return impu_recs

    def update_impu(self, impu=None):
        hex_str = ""
        if impu:
            hex_str = s2h(impu)
        # Build TLV
        tlv = TLV(['80'])
        content = tlv.build({'80': hex_str})

        rec_size_bytes = self._scc.record_size(EF_ISIM_ADF_map['IMPU'])
        impu_tlv = rpad(content, rec_size_bytes*2)
        data, sw = self._scc.update_record(
            EF_ISIM_ADF_map['IMPU'], 1, impu_tlv)
        return sw

    def read_iari(self):
        rec_cnt = self._scc.record_count(EF_ISIM_ADF_map['UICCIARI'])
        uiari_recs = ""
        for i in range(0, rec_cnt):
            (res, sw) = self._scc.read_record(
                EF_ISIM_ADF_map['UICCIARI'], i + 1)
            if sw == '9000':
                # Skip the initial tag value ('80') byte and get length of contents
                length = int(res[2:4], 16)
                content = h2s(res[4:4+(length*2)])
                uiari_recs += "\t%s\n" % (len(content)
                                          and content or 'Not available')
            else:
                uiari_recs += "UICC IARI: Can't read, response code = %s\n" % (
                    sw)
        return uiari_recs

    def update_ist(self, service, bit=1):
        (res, sw) = self._scc.read_binary(EF_ISIM_ADF_map['IST'])
        if sw == '9000':
            content = enc_st(res, service, bit)
            (res, sw) = self._scc.update_binary(
                EF_ISIM_ADF_map['IST'], content)
        return sw


class MagicSimBase(abc.ABC, SimCard):
    """
    Theses cards uses several record based EFs to store the provider infos,
    each possible provider uses a specific record number in each EF. The
    indexes used are ( where N is the number of providers supported ) :
     - [2 .. N+1] for the operator name
     - [1 .. N] for the programmable EFs

    * 3f00/7f4d/8f0c : Operator Name

    bytes 0-15 : provider name, padded with 0xff
    byte  16   : length of the provider name
    byte  17   : 01 for valid records, 00 otherwise

    * 3f00/7f4d/8f0d : Programmable Binary EFs

    * 3f00/7f4d/8f0e : Programmable Record EFs

    """

    _files = {}  # type: Dict[str, Tuple[str, int, bool]]
    _ki_file = None  # type: Optional[str]

    @classmethod
    def autodetect(kls, scc):
        try:
            for p, l, t in kls._files.values():
                if not t:
                    continue
                if scc.record_size(['3f00', '7f4d', p]) != l:
                    return None
        except:
            return None

        return kls(scc)

    def _get_count(self):
        """
        Selects the file and returns the total number of entries
        and entry size
        """
        f = self._files['name']

        r = self._scc.select_path(['3f00', '7f4d', f[0]])
        rec_len = int(r[-1][28:30], 16)
        tlen = int(r[-1][4:8], 16)
        rec_cnt = (tlen // rec_len) - 1

        if (rec_cnt < 1) or (rec_len != f[1]):
            raise RuntimeError('Bad card type')

        return rec_cnt

    def program(self, p):
        # Go to dir
        self._scc.select_path(['3f00', '7f4d'])

        # Home PLMN in PLMN_Sel format
        hplmn = enc_plmn(p['mcc'], p['mnc'])

        # Operator name ( 3f00/7f4d/8f0c )
        self._scc.update_record(self._files['name'][0], 2,
                                rpad(b2h(p['name']), 32) + ('%02x' %
                                                            len(p['name'])) + '01'
                                )

        # ICCID/IMSI/Ki/HPLMN ( 3f00/7f4d/8f0d )
        v = ''

        # inline Ki
        if self._ki_file is None:
            v += p['ki']

            # ICCID
        v += '3f00' + '2fe2' + '0a' + enc_iccid(p['iccid'])

        # IMSI
        v += '7f20' + '6f07' + '09' + enc_imsi(p['imsi'])

        # Ki
        if self._ki_file:
            v += self._ki_file + '10' + p['ki']

            # PLMN_Sel
        v += '6f30' + '18' + rpad(hplmn, 36)

        # ACC
        # This doesn't work with "fake" SuperSIM cards,
        # but will hopefully work with real SuperSIMs.
        if p.get('acc') is not None:
            v += '6f78' + '02' + lpad(p['acc'], 4)

        self._scc.update_record(self._files['b_ef'][0], 1,
                                rpad(v, self._files['b_ef'][1]*2)
                                )

        # SMSP ( 3f00/7f4d/8f0e )
        # FIXME

        # Write PLMN_Sel forcefully as well
        r = self._scc.select_path(['3f00', '7f20', '6f30'])
        tl = int(r[-1][4:8], 16)

        hplmn = enc_plmn(p['mcc'], p['mnc'])
        self._scc.update_binary('6f30', hplmn + 'ff' * (tl-3))

    def erase(self):
        # Dummy
        df = {}
        for k, v in self._files.items():
            ofs = 1
            fv = v[1] * 'ff'
            if k == 'name':
                ofs = 2
                fv = fv[0:-4] + '0000'
            df[v[0]] = (fv, ofs)

        # Write
        for n in range(0, self._get_count()):
            for k, (msg, ofs) in df.items():
                self._scc.update_record(['3f00', '7f4d', k], n + ofs, msg)


class SuperSim(MagicSimBase):

    name = 'supersim'

    _files = {
        'name': ('8f0c', 18, True),
        'b_ef': ('8f0d', 74, True),
        'r_ef': ('8f0e', 50, True),
    }

    _ki_file = None


class MagicSim(MagicSimBase):

    name = 'magicsim'

    _files = {
        'name': ('8f0c', 18, True),
        'b_ef': ('8f0d', 130, True),
        'r_ef': ('8f0e', 102, False),
    }

    _ki_file = '6f1b'


class FakeMagicSim(SimCard):
    """
    Theses cards have a record based EF 3f00/000c that contains the provider
    information. See the program method for its format. The records go from
    1 to N.
    """

    name = 'fakemagicsim'

    @classmethod
    def autodetect(kls, scc):
        try:
            if scc.record_size(['3f00', '000c']) != 0x5a:
                return None
        except:
            return None

        return kls(scc)

    def _get_infos(self):
        """
        Selects the file and returns the total number of entries
        and entry size
        """

        r = self._scc.select_path(['3f00', '000c'])
        rec_len = int(r[-1][28:30], 16)
        tlen = int(r[-1][4:8], 16)
        rec_cnt = (tlen // rec_len) - 1

        if (rec_cnt < 1) or (rec_len != 0x5a):
            raise RuntimeError('Bad card type')

        return rec_cnt, rec_len

    def program(self, p):
        # Home PLMN
        r = self._scc.select_path(['3f00', '7f20', '6f30'])
        tl = int(r[-1][4:8], 16)

        hplmn = enc_plmn(p['mcc'], p['mnc'])
        self._scc.update_binary('6f30', hplmn + 'ff' * (tl-3))

        # Get total number of entries and entry size
        rec_cnt, rec_len = self._get_infos()

        # Set first entry
        entry = (
            '81' +  # 1b  Status: Valid & Active
            rpad(s2h(p['name'][0:14]), 28) +  # 14b  Entry Name
            enc_iccid(p['iccid']) +			# 10b  ICCID
            enc_imsi(p['imsi']) +  # 9b  IMSI_len + id_type(9) + IMSI
            p['ki'] +				# 16b  Ki
            lpad(p['smsp'], 80)			# 40b  SMSP (padded with ff if needed)
        )
        self._scc.update_record('000c', 1, entry)

    def erase(self):
        # Get total number of entries and entry size
        rec_cnt, rec_len = self._get_infos()

        # Erase all entries
        entry = 'ff' * rec_len
        for i in range(0, rec_cnt):
            self._scc.update_record('000c', 1+i, entry)


class GrcardSim(SimCard):
    """
    Greencard (grcard.cn) HZCOS GSM SIM
    These cards have a much more regular ISO 7816-4 / TS 11.11 structure,
    and use standard UPDATE RECORD / UPDATE BINARY commands except for Ki.
    """

    name = 'grcardsim'

    @classmethod
    def autodetect(kls, scc):
        return None

    def program(self, p):
        # We don't really know yet what ADM PIN 4 is about
        #self._scc.verify_chv(4, h2b("4444444444444444"))

        # Authenticate using ADM PIN 5
        if p['pin_adm']:
            pin = h2b(p['pin_adm'])
        else:
            pin = h2b("4444444444444444")
        self._scc.verify_chv(5, pin)

        # EF.ICCID
        r = self._scc.select_path(['3f00', '2fe2'])
        data, sw = self._scc.update_binary('2fe2', enc_iccid(p['iccid']))

        # EF.IMSI
        r = self._scc.select_path(['3f00', '7f20', '6f07'])
        data, sw = self._scc.update_binary('6f07', enc_imsi(p['imsi']))

        # EF.ACC
        if p.get('acc') is not None:
            data, sw = self._scc.update_binary('6f78', lpad(p['acc'], 4))

        # EF.SMSP
        if p.get('smsp'):
            r = self._scc.select_path(['3f00', '7f10', '6f42'])
            data, sw = self._scc.update_record('6f42', 1, lpad(p['smsp'], 80))

        # Set the Ki using proprietary command
        pdu = '80d4020010' + p['ki']
        data, sw = self._scc.send_apdu(pdu)

        # EF.HPLMN
        r = self._scc.select_path(['3f00', '7f20', '6f30'])
        size = int(r[-1][4:8], 16)
        hplmn = enc_plmn(p['mcc'], p['mnc'])
        self._scc.update_binary('6f30', hplmn + 'ff' * (size-3))

        # EF.SPN (Service Provider Name)
        r = self._scc.select_path(['3f00', '7f20', '6f30'])
        size = int(r[-1][4:8], 16)
        # FIXME

        # FIXME: EF.MSISDN


class SysmoSIMgr1(GrcardSim):
    """
    sysmocom sysmoSIM-GR1
    These cards have a much more regular ISO 7816-4 / TS 11.11 structure,
    and use standard UPDATE RECORD / UPDATE BINARY commands except for Ki.
    """
    name = 'sysmosim-gr1'

    @classmethod
    def autodetect(kls, scc):
        try:
            # Look for ATR
            if scc.get_atr() == toBytes("3B 99 18 00 11 88 22 33 44 55 66 77 60"):
                return kls(scc)
        except:
            return None
        return None


class SysmoUSIMgr1(UsimCard):
    """
    sysmocom sysmoUSIM-GR1
    """
    name = 'sysmoUSIM-GR1'

    @classmethod
    def autodetect(kls, scc):
        # TODO: Access the ATR
        return None

    def program(self, p):
        # TODO: check if verify_chv could be used or what it needs
        # self._scc.verify_chv(0x0A, [0x33,0x32,0x32,0x31,0x33,0x32,0x33,0x32])
        # Unlock the card..
        data, sw = self._scc.send_apdu_checksw(
            "0020000A083332323133323332")

        # TODO: move into SimCardCommands
        par = (p['ki'] +			# 16b  K
               p['opc'] +				# 32b  OPC
               enc_iccid(p['iccid']) +  # 10b  ICCID
               enc_imsi(p['imsi'])  # 9b  IMSI_len + id_type(9) + IMSI
               )
        data, sw = self._scc.send_apdu_checksw("0099000033" + par)


class SysmoSIMgr2(SimCard):
    """
    sysmocom sysmoSIM-GR2
    """

    name = 'sysmoSIM-GR2'

    @classmethod
    def autodetect(kls, scc):
        try:
            # Look for ATR
            if scc.get_atr() == toBytes("3B 7D 94 00 00 55 55 53 0A 74 86 93 0B 24 7C 4D 54 68"):
                return kls(scc)
        except:
            return None
        return None

    def program(self, p):

        # select MF
        r = self._scc.select_path(['3f00'])

        # authenticate as SUPER ADM using default key
        self._scc.verify_chv(0x0b, h2b("3838383838383838"))

        # set ADM pin using proprietary command
        # INS: D4
        # P1: 3A for PIN, 3B for PUK
        # P2: CHV number, as in VERIFY CHV for PIN, and as in UNBLOCK CHV for PUK
        # P3: 08, CHV length (curiously the PUK is also 08 length, instead of 10)
        if p['pin_adm']:
            pin = h2b(p['pin_adm'])
        else:
            pin = h2b("4444444444444444")

        pdu = 'A0D43A0508' + b2h(pin)
        data, sw = self._scc.send_apdu(pdu)

        # authenticate as ADM (enough to write file, and can set PINs)

        self._scc.verify_chv(0x05, pin)

        # write EF.ICCID
        data, sw = self._scc.update_binary('2fe2', enc_iccid(p['iccid']))

        # select DF_GSM
        r = self._scc.select_path(['7f20'])

        # write EF.IMSI
        data, sw = self._scc.update_binary('6f07', enc_imsi(p['imsi']))

        # write EF.ACC
        if p.get('acc') is not None:
            data, sw = self._scc.update_binary('6f78', lpad(p['acc'], 4))

        # get size and write EF.HPLMN
        r = self._scc.select_path(['6f30'])
        size = int(r[-1][4:8], 16)
        hplmn = enc_plmn(p['mcc'], p['mnc'])
        self._scc.update_binary('6f30', hplmn + 'ff' * (size-3))

        # set COMP128 version 0 in proprietary file
        data, sw = self._scc.update_binary('0001', '001000')

        # set Ki in proprietary file
        data, sw = self._scc.update_binary('0001', p['ki'], 3)

        # select DF_TELECOM
        r = self._scc.select_path(['3f00', '7f10'])

        # write EF.SMSP
        if p.get('smsp'):
            data, sw = self._scc.update_record('6f42', 1, lpad(p['smsp'], 80))


class SysmoUSIMSJS1(UsimCard):
    """
    sysmocom sysmoUSIM-SJS1
    """

    name = 'sysmoUSIM-SJS1'

    def __init__(self, ssc):
        super(SysmoUSIMSJS1, self).__init__(ssc)

    @classmethod
    def autodetect(kls, scc):
        try:
            # Look for ATR
            if scc.get_atr() == toBytes("3B 9F 96 80 1F C7 80 31 A0 73 BE 21 13 67 43 20 07 18 00 00 01 A5"):
                return kls(scc)
        except:
            return None
        return None

    def verify_adm(self, key):
        # authenticate as ADM using default key (written on the card..)
        if not key:
            raise ValueError(
                "Please provide a PIN-ADM as there is no default one")
        (res, sw) = self._scc.verify_chv(0x0A, key)
        return sw

    def program(self, p):
        self.verify_adm(h2b(p['pin_adm']))

        # select MF
        r = self._scc.select_path(['3f00'])

        # write EF.ICCID
        data, sw = self._scc.update_binary('2fe2', enc_iccid(p['iccid']))

        # select DF_GSM
        r = self._scc.select_path(['7f20'])

        # set Ki in proprietary file
        data, sw = self._scc.update_binary('00FF', p['ki'])

        # set OPc in proprietary file
        if 'opc' in p:
            content = "01" + p['opc']
            data, sw = self._scc.update_binary('00F7', content)

        # set Service Provider Name
        if p.get('name') is not None:
            self.update_spn(p['name'], True, True)

        if p.get('acc') is not None:
            self.update_acc(p['acc'])

        # write EF.IMSI
        data, sw = self._scc.update_binary('6f07', enc_imsi(p['imsi']))

        # EF.PLMNsel
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_plmnsel(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming PLMNsel failed with code %s" % sw)

        # EF.PLMNwAcT
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_plmn_act(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming PLMNwAcT failed with code %s" % sw)

        # EF.OPLMNwAcT
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_oplmn_act(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming OPLMNwAcT failed with code %s" % sw)

        # EF.HPLMNwAcT
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_hplmn_act(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming HPLMNwAcT failed with code %s" % sw)

        # EF.AD
        if (p.get('mcc') and p.get('mnc')) or p.get('opmode'):
            if p.get('mcc') and p.get('mnc'):
                mnc = p['mnc']
            else:
                mnc = None
            sw = self.update_ad(mnc=mnc, opmode=p.get('opmode'))
            if sw != '9000':
                print("Programming AD failed with code %s" % sw)

        # EF.SMSP
        if p.get('smsp'):
            r = self._scc.select_path(['3f00', '7f10'])
            data, sw = self._scc.update_record(
                '6f42', 1, lpad(p['smsp'], 104), force_len=True)

        # EF.MSISDN
        # TODO: Alpha Identifier (currently 'ff'O * 20)
        # TODO: Capability/Configuration1 Record Identifier
        # TODO: Extension1 Record Identifier
        if p.get('msisdn') is not None:
            msisdn = enc_msisdn(p['msisdn'])
            data = 'ff' * 20 + msisdn

            r = self._scc.select_path(['3f00', '7f10'])
            data, sw = self._scc.update_record('6F40', 1, data, force_len=True)


class FairwavesSIM(UsimCard):
    """
    FairwavesSIM

    The SIM card is operating according to the standard.
    For Ki/OP/OPC programming the following files are additionally open for writing:
            3F00/7F20/FF01 – OP/OPC:
            byte 1 = 0x01, bytes 2-17: OPC;
            byte 1 = 0x00, bytes 2-17: OP;
            3F00/7F20/FF02: Ki
    """

    name = 'Fairwaves-SIM'
    # Propriatary files
    _EF_num = {
        'Ki': 'FF02',
        'OP/OPC': 'FF01',
    }
    _EF = {
        'Ki':     DF['GSM']+[_EF_num['Ki']],
        'OP/OPC': DF['GSM']+[_EF_num['OP/OPC']],
    }

    def __init__(self, ssc):
        super(FairwavesSIM, self).__init__(ssc)
        self._adm_chv_num = 0x11
        self._adm2_chv_num = 0x12

    @classmethod
    def autodetect(kls, scc):
        try:
            # Look for ATR
            if scc.get_atr() == toBytes("3B 9F 96 80 1F C7 80 31 A0 73 BE 21 13 67 44 22 06 10 00 00 01 A9"):
                return kls(scc)
        except:
            return None
        return None

    def verify_adm2(self, key):
        '''
        Authenticate with ADM2 key.

        Fairwaves SIM cards support hierarchical key structure and ADM2 key
        is a key which has access to proprietary files (Ki and OP/OPC).
        That said, ADM key inherits permissions of ADM2 key and thus we rarely
        need ADM2 key per se.
        '''
        (res, sw) = self._scc.verify_chv(self._adm2_chv_num, key)
        return sw

    def read_ki(self):
        """
        Read Ki in proprietary file.

        Requires ADM1 access level
        """
        return self._scc.read_binary(self._EF['Ki'])

    def update_ki(self, ki):
        """
        Set Ki in proprietary file.

        Requires ADM1 access level
        """
        data, sw = self._scc.update_binary(self._EF['Ki'], ki)
        return sw

    def read_op_opc(self):
        """
        Read Ki in proprietary file.

        Requires ADM1 access level
        """
        (ef, sw) = self._scc.read_binary(self._EF['OP/OPC'])
        type = 'OP' if ef[0:2] == '00' else 'OPC'
        return ((type, ef[2:]), sw)

    def update_op(self, op):
        """
        Set OP in proprietary file.

        Requires ADM1 access level
        """
        content = '00' + op
        data, sw = self._scc.update_binary(self._EF['OP/OPC'], content)
        return sw

    def update_opc(self, opc):
        """
        Set OPC in proprietary file.

        Requires ADM1 access level
        """
        content = '01' + opc
        data, sw = self._scc.update_binary(self._EF['OP/OPC'], content)
        return sw

    def program(self, p):
        # For some reason the card programming only works when the card
        # is handled as a classic SIM, even though it is an USIM, so we
        # reconfigure the class byte and the select control field on
        # the fly. When the programming is done the original values are
        # restored.
        cla_byte_orig = self._scc.cla_byte
        sel_ctrl_orig = self._scc.sel_ctrl
        self._scc.cla_byte = "a0"
        self._scc.sel_ctrl = "0000"

        try:
            self._program(p)
        finally:
            # restore original cla byte and sel ctrl
            self._scc.cla_byte = cla_byte_orig
            self._scc.sel_ctrl = sel_ctrl_orig

    def _program(self, p):
        # authenticate as ADM1
        if not p['pin_adm']:
            raise ValueError(
                "Please provide a PIN-ADM as there is no default one")
        self.verify_adm(h2b(p['pin_adm']))

        # TODO: Set operator name
        if p.get('smsp') is not None:
            sw = self.update_smsp(p['smsp'])
            if sw != '9000':
                print("Programming SMSP failed with code %s" % sw)
        # This SIM doesn't support changing ICCID
        if p.get('mcc') is not None and p.get('mnc') is not None:
            sw = self.update_hplmn_act(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming MCC/MNC failed with code %s" % sw)
        if p.get('imsi') is not None:
            sw = self.update_imsi(p['imsi'])
            if sw != '9000':
                print("Programming IMSI failed with code %s" % sw)
        if p.get('ki') is not None:
            sw = self.update_ki(p['ki'])
            if sw != '9000':
                print("Programming Ki failed with code %s" % sw)
        if p.get('opc') is not None:
            sw = self.update_opc(p['opc'])
            if sw != '9000':
                print("Programming OPC failed with code %s" % sw)
        if p.get('acc') is not None:
            sw = self.update_acc(p['acc'])
            if sw != '9000':
                print("Programming ACC failed with code %s" % sw)


class OpenCellsSim(SimCard):
    """
    OpenCellsSim

    """

    name = 'OpenCells-SIM'

    def __init__(self, ssc):
        super(OpenCellsSim, self).__init__(ssc)
        self._adm_chv_num = 0x0A

    @classmethod
    def autodetect(kls, scc):
        try:
            # Look for ATR
            if scc.get_atr() == toBytes("3B 9F 95 80 1F C3 80 31 E0 73 FE 21 13 57 86 81 02 86 98 44 18 A8"):
                return kls(scc)
        except:
            return None
        return None

    def program(self, p):
        if not p['pin_adm']:
            raise ValueError(
                "Please provide a PIN-ADM as there is no default one")
        self._scc.verify_chv(0x0A, h2b(p['pin_adm']))

        # select MF
        r = self._scc.select_path(['3f00'])

        # write EF.ICCID
        data, sw = self._scc.update_binary('2fe2', enc_iccid(p['iccid']))

        r = self._scc.select_path(['7ff0'])

        # set Ki in proprietary file
        data, sw = self._scc.update_binary('FF02', p['ki'])

        # set OPC in proprietary file
        data, sw = self._scc.update_binary('FF01', p['opc'])

        # select DF_GSM
        r = self._scc.select_path(['7f20'])

        # write EF.IMSI
        data, sw = self._scc.update_binary('6f07', enc_imsi(p['imsi']))


class WavemobileSim(UsimCard):
    """
    WavemobileSim

    """

    name = 'Wavemobile-SIM'

    def __init__(self, ssc):
        super(WavemobileSim, self).__init__(ssc)
        self._adm_chv_num = 0x0A

    @classmethod
    def autodetect(kls, scc):
        try:
            # Look for ATR
            if scc.get_atr() == toBytes("3B 9F 95 80 1F C7 80 31 E0 73 F6 21 13 67 4D 45 16 00 43 01 00 8F"):
                return kls(scc)
        except:
            return None
        return None

    def program(self, p):
        if not p['pin_adm']:
            raise ValueError(
                "Please provide a PIN-ADM as there is no default one")
        self.verify_adm(h2b(p['pin_adm']))

        # EF.ICCID
        # TODO: Add programming of the ICCID
        if p.get('iccid'):
            print(
                "Warning: Programming of the ICCID is not implemented for this type of card.")

        # KI (Presumably a proprietary file)
        # TODO: Add programming of KI
        if p.get('ki'):
            print(
                "Warning: Programming of the KI is not implemented for this type of card.")

        # OPc (Presumably a proprietary file)
        # TODO: Add programming of OPc
        if p.get('opc'):
            print(
                "Warning: Programming of the OPc is not implemented for this type of card.")

        # EF.SMSP
        if p.get('smsp'):
            sw = self.update_smsp(p['smsp'])
            if sw != '9000':
                print("Programming SMSP failed with code %s" % sw)

        # EF.IMSI
        if p.get('imsi'):
            sw = self.update_imsi(p['imsi'])
            if sw != '9000':
                print("Programming IMSI failed with code %s" % sw)

        # EF.ACC
        if p.get('acc'):
            sw = self.update_acc(p['acc'])
            if sw != '9000':
                print("Programming ACC failed with code %s" % sw)

        # EF.PLMNsel
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_plmnsel(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming PLMNsel failed with code %s" % sw)

        # EF.PLMNwAcT
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_plmn_act(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming PLMNwAcT failed with code %s" % sw)

        # EF.OPLMNwAcT
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_oplmn_act(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming OPLMNwAcT failed with code %s" % sw)

        # EF.AD
        if (p.get('mcc') and p.get('mnc')) or p.get('opmode'):
            if p.get('mcc') and p.get('mnc'):
                mnc = p['mnc']
            else:
                mnc = None
            sw = self.update_ad(mnc=mnc, opmode=p.get('opmode'))
            if sw != '9000':
                print("Programming AD failed with code %s" % sw)

        return None


class SysmoISIMSJA2(UsimCard, IsimCard):
    """
    sysmocom sysmoISIM-SJA2
    """

    name = 'sysmoISIM-SJA2'

    @classmethod
    def autodetect(kls, scc):
        try:
            # Try card model #1
            atr = "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 75 30 34 05 4B A9"
            if scc.get_atr() == toBytes(atr):
                return kls(scc)

            # Try card model #2
            atr = "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 75 31 33 02 51 B2"
            if scc.get_atr() == toBytes(atr):
                return kls(scc)

            # Try card model #3
            atr = "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 52 75 31 04 51 D5"
            if scc.get_atr() == toBytes(atr):
                return kls(scc)
        except:
            return None
        return None

    def verify_adm(self, key):
        # authenticate as ADM using default key (written on the card..)
        if not key:
            raise ValueError(
                "Please provide a PIN-ADM as there is no default one")
        (res, sw) = self._scc.verify_chv(0x0A, key)
        return sw

    def program(self, p):
        self.verify_adm(h2b(p['pin_adm']))

        # Populate AIDs
        self.read_aids()

        # This type of card does not allow to reprogram the ICCID.
        # Reprogramming the ICCID would mess up the card os software
        # license management, so the ICCID must be kept at its factory
        # setting!
        if p.get('iccid'):
            print(
                "Warning: Programming of the ICCID is not implemented for this type of card.")

        # select DF_GSM
        self._scc.select_path(['7f20'])

        # set Service Provider Name
        if p.get('name') is not None:
            self.update_spn(p['name'], True, True)

        # write EF.IMSI
        if p.get('imsi'):
            self._scc.update_binary('6f07', enc_imsi(p['imsi']))

        # EF.PLMNsel
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_plmnsel(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming PLMNsel failed with code %s" % sw)

        # EF.PLMNwAcT
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_plmn_act(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming PLMNwAcT failed with code %s" % sw)

        # EF.OPLMNwAcT
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_oplmn_act(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming OPLMNwAcT failed with code %s" % sw)

        # EF.HPLMNwAcT
        if p.get('mcc') and p.get('mnc'):
            sw = self.update_hplmn_act(p['mcc'], p['mnc'])
            if sw != '9000':
                print("Programming HPLMNwAcT failed with code %s" % sw)

        # EF.AD
        if (p.get('mcc') and p.get('mnc')) or p.get('opmode'):
            if p.get('mcc') and p.get('mnc'):
                mnc = p['mnc']
            else:
                mnc = None
            sw = self.update_ad(mnc=mnc, opmode=p.get('opmode'))
            if sw != '9000':
                print("Programming AD failed with code %s" % sw)

        # EF.SMSP
        if p.get('smsp'):
            r = self._scc.select_path(['3f00', '7f10'])
            data, sw = self._scc.update_record(
                '6f42', 1, lpad(p['smsp'], 104), force_len=True)

        # EF.MSISDN
        # TODO: Alpha Identifier (currently 'ff'O * 20)
        # TODO: Capability/Configuration1 Record Identifier
        # TODO: Extension1 Record Identifier
        if p.get('msisdn') is not None:
            msisdn = enc_msisdn(p['msisdn'])
            content = 'ff' * 20 + msisdn

            r = self._scc.select_path(['3f00', '7f10'])
            data, sw = self._scc.update_record(
                '6F40', 1, content, force_len=True)

        # EF.ACC
        if p.get('acc'):
            sw = self.update_acc(p['acc'])
            if sw != '9000':
                print("Programming ACC failed with code %s" % sw)

        # update EF-SIM_AUTH_KEY (and EF-USIM_AUTH_KEY_2G, which is
        # hard linked to EF-USIM_AUTH_KEY)
        self._scc.select_path(['3f00'])
        self._scc.select_path(['a515'])
        if p.get('ki'):
            self._scc.update_binary('6f20', p['ki'], 1)
        if p.get('opc'):
            self._scc.update_binary('6f20', p['opc'], 17)

        # update EF-USIM_AUTH_KEY in ADF.ISIM
        if self.adf_present("isim"):
            self.select_adf_by_aid(adf="isim")

            if p.get('ki'):
                self._scc.update_binary('af20', p['ki'], 1)
            if p.get('opc'):
                self._scc.update_binary('af20', p['opc'], 17)

            # update EF.P-CSCF in ADF.ISIM
            if self.file_exists(EF_ISIM_ADF_map['PCSCF']):
                if p.get('pcscf'):
                    sw = self.update_pcscf(p['pcscf'])
                else:
                    sw = self.update_pcscf("")
                if sw != '9000':
                    print("Programming P-CSCF failed with code %s" % sw)

            # update EF.DOMAIN in ADF.ISIM
            if self.file_exists(EF_ISIM_ADF_map['DOMAIN']):
                if p.get('ims_hdomain'):
                    sw = self.update_domain(domain=p['ims_hdomain'])
                else:
                    sw = self.update_domain()

                if sw != '9000':
                    print(
                        "Programming Home Network Domain Name failed with code %s" % sw)

            # update EF.IMPI in ADF.ISIM
            # TODO: Validate IMPI input
            if self.file_exists(EF_ISIM_ADF_map['IMPI']):
                if p.get('impi'):
                    sw = self.update_impi(p['impi'])
                else:
                    sw = self.update_impi()
                if sw != '9000':
                    print("Programming IMPI failed with code %s" % sw)

            # update EF.IMPU in ADF.ISIM
            # TODO: Validate IMPU input
            # Support multiple IMPU if there is enough space
            if self.file_exists(EF_ISIM_ADF_map['IMPU']):
                if p.get('impu'):
                    sw = self.update_impu(p['impu'])
                else:
                    sw = self.update_impu()
                if sw != '9000':
                    print("Programming IMPU failed with code %s" % sw)

        if self.adf_present("usim"):
            self.select_adf_by_aid(adf="usim")

            # EF.AD in ADF.USIM
            if (p.get('mcc') and p.get('mnc')) or p.get('opmode'):
                 if p.get('mcc') and p.get('mnc'):
                     mnc = p['mnc']
                 else:
                     mnc = None
            sw = self.update_ad(mnc=mnc, opmode=p.get('opmode'),
                                path=EF_USIM_ADF_map['AD'])
            if sw != '9000':
                print("Programming AD failed with code %s" % sw)

            # update EF-USIM_AUTH_KEY in ADF.USIM
            if p.get('ki'):
                self._scc.update_binary('af20', p['ki'], 1)
            if p.get('opc'):
                self._scc.update_binary('af20', p['opc'], 17)

            # update EF.EHPLMN in ADF.USIM
            if self.file_exists(EF_USIM_ADF_map['EHPLMN']):
                if p.get('mcc') and p.get('mnc'):
                    sw = self.update_ehplmn(p['mcc'], p['mnc'])
                    if sw != '9000':
                        print("Programming EHPLMN failed with code %s" % sw)

            # update EF.ePDGId in ADF.USIM
            if self.file_exists(EF_USIM_ADF_map['ePDGId']):
                if p.get('epdgid'):
                    sw = self.update_epdgid(p['epdgid'])
                else:
                    sw = self.update_epdgid("")
                if sw != '9000':
                    print("Programming ePDGId failed with code %s" % sw)

            # update EF.ePDGSelection in ADF.USIM
            if self.file_exists(EF_USIM_ADF_map['ePDGSelection']):
                if p.get('epdgSelection'):
                    epdg_plmn = p['epdgSelection']
                    sw = self.update_ePDGSelection(
                        epdg_plmn[:3], epdg_plmn[3:])
                else:
                    sw = self.update_ePDGSelection("", "")
                if sw != '9000':
                    print("Programming ePDGSelection failed with code %s" % sw)

            # After successfully programming EF.ePDGId and EF.ePDGSelection,
            # Set service 106 and 107 as available in EF.UST
            # Disable service 95, 99, 115 if ISIM application is present
            if self.file_exists(EF_USIM_ADF_map['UST']):
                if p.get('epdgSelection') and p.get('epdgid'):
                    sw = self.update_ust(106, 1)
                    if sw != '9000':
                        print("Programming UST failed with code %s" % sw)
                    sw = self.update_ust(107, 1)
                    if sw != '9000':
                        print("Programming UST failed with code %s" % sw)

                sw = self.update_ust(95, 0)
                if sw != '9000':
                    print("Programming UST failed with code %s" % sw)
                sw = self.update_ust(99, 0)
                if sw != '9000':
                    print("Programming UST failed with code %s" % sw)
                sw = self.update_ust(115, 0)
                if sw != '9000':
                    print("Programming UST failed with code %s" % sw)

        return

class SysmoISIMSJA5(SysmoISIMSJA2):
    """
    sysmocom sysmoISIM-SJA5
    """

    name = 'sysmoISIM-SJA5'

    @classmethod
    def autodetect(kls, scc):
        try:
            # Try card model #1 (9FJ)
            atr = "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 35 75 30 35 02 51 CC"
            if scc.get_atr() == toBytes(atr):
                return kls(scc)
            # Try card model #2 (SLM17)
            atr = "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 35 75 30 35 02 65 F8"
            if scc.get_atr() == toBytes(atr):
                return kls(scc)
            # Try card model #3 (9FV)
            atr = "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 35 75 30 35 02 59 C4"
            if scc.get_atr() == toBytes(atr):
                return kls(scc)
        except:
            return None
        return None


class GialerSim(UsimCard):
    """
    Gialer sim cards (www.gialer.com).
    """
    name = 'gialersim'

    def __init__(self, ssc):
        super().__init__(ssc)
        self._program_handlers = {
            'iccid': self.update_iccid,
            'imsi': self.update_imsi,
            'acc': self.update_acc,
            'smsp': self.update_smsp,
            'ki': self.update_ki,
            'opc': self.update_opc,
            'fplmn': self.update_fplmn,
        }

    @classmethod
    def autodetect(cls, scc):
        try:
            # Look for ATR
            if scc.get_atr() == toBytes('3B 9F 95 80 1F C7 80 31 A0 73 B6 A1 00 67 CF 32 15 CA 9C D7 09 20'):
                return cls(scc)
        except:
            return None
        return None

    def program(self, p):
        self.set_apdu_parameter('00', '0004')
        # Authenticate
        self._scc.verify_chv(0xc, h2b('3834373936313533'))
        for handler in self._program_handlers:
            if p.get(handler) is not None:
                self._program_handlers[handler](p[handler])

        mcc = p.get('mcc')
        mnc = p.get('mnc')
        has_plmn = mcc is not None and mnc is not None
        # EF.HPLMN
        if has_plmn:
            self.update_hplmn_act(mcc, mnc)

        # EF.AD
        if has_plmn or (p.get('opmode') is not None):
            self.update_ad(mnc=mnc, opmode=p.get('opmode'))

    def update_smsp(self, smsp):
        data, sw = self._scc.update_record(EF['SMSP'], 1, rpad(smsp, 80))
        return sw

    def update_ki(self, ki):
        self._scc.select_path(['3f00', '0001'])
        self._scc.update_binary('0001', ki)

    def update_opc(self, opc):
        self._scc.select_path(['3f00', '6002'])
        # No idea why the '01' is required
        self._scc.update_binary('6002', '01' + opc)


# In order for autodetection ...
_cards_classes = [FakeMagicSim, SuperSim, MagicSim, GrcardSim,
                  SysmoSIMgr1, SysmoSIMgr2, SysmoUSIMgr1, SysmoUSIMSJS1,
                  FairwavesSIM, OpenCellsSim, WavemobileSim, SysmoISIMSJA2,
                  SysmoISIMSJA5, GialerSim]


def card_detect(ctype, scc):
    # Detect type if needed
    card = None
    ctypes = dict([(kls.name, kls) for kls in _cards_classes])

    if ctype == "auto":
        for kls in _cards_classes:
            card = kls.autodetect(scc)
            if card:
                print("Autodetected card type: %s" % card.name)
                card.reset()
                break

        if card is None:
            print("Autodetection failed")
            return None

    elif ctype in ctypes:
        card = ctypes[ctype](scc)

    else:
        raise ValueError("Unknown card type: %s" % ctype)

    return card
