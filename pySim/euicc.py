# -*- coding: utf-8 -*-

"""
Various definitions related to GSMA consumer + IoT eSIM / eUICC

Does *not* implement anything related to M2M eUICC

Related Specs: GSMA SGP.21, SGP.22, SGP.31, SGP32
"""

# Copyright (C) 2023 Harald Welte <laforge@osmocom.org>
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

import argparse

from construct import Array, Struct, FlagsEnum, GreedyRange
from cmd2 import cmd2, CommandSet, with_default_category
from osmocom.utils import Hexstr
from osmocom.tlv import *
from osmocom.construct import *

from pySim.exceptions import SwMatchError
from pySim.utils import Hexstr, SwHexstr, SwMatchstr
from pySim.commands import SimCardCommands
from pySim.ts_102_221 import CardProfileUICC
import pySim.global_platform

# SGP.02 Section 2.2.2
class Sgp02Eid(BER_TLV_IE, tag=0x5a):
    _construct = BcdAdapter(GreedyBytes)

# patch this into global_platform, to allow 'get_data sgp02_eid' in EF.ECASD
pySim.global_platform.DataCollection.possible_nested.append(Sgp02Eid)

def compute_eid_checksum(eid) -> str:
    """Compute and add/replace check digits of an EID value according to GSMA SGP.29 Section 10."""
    if isinstance(eid, str):
        if len(eid) == 30:
            # first pad by 2 digits
            eid += "00"
        elif len(eid) == 32:
            # zero the last two digits
            eid = eid[:-2] + "00"
        else:
            raise ValueError("and EID must be 30 or 32 digits")
        eid_int = int(eid)
    elif isinstance(eid, int):
        eid_int = eid
        if eid_int % 100:
            # zero the last two digits
            eid_int -= eid_int % 100
    # Using the resulting 32 digits as a decimal integer, compute the remainder of that number on division by
    # 97, Subtract the remainder from 98, and use the decimal result for the two check digits, if the result
    # is one digit long, its value SHALL be prefixed by one digit of 0.
    csum = 98 - (eid_int % 97)
    eid_int += csum
    return str(eid_int)

def verify_eid_checksum(eid) -> bool:
    """Verify the check digits of an EID value according to GSMA SGP.29 Section 10."""
    # Using the 32 digits as a decimal integer, compute the remainder of that number on division by 97. If the
    # remainder of the division is 1, the verification is successful; otherwise the EID is invalid.
    return int(eid) % 97 == 1

class VersionAdapter(Adapter):
    """convert an EUICC Version (3-int array) to a textual representation."""

    def _decode(self, obj, context, path):
        return "%u.%u.%u" % (obj[0], obj[1], obj[2])

    def _encode(self, obj, context, path):
        return [int(x) for x in obj.split('.')]

VersionType = VersionAdapter(Array(3, Int8ub))

# Application Identifiers as defined in GSMA SGP.02 Annex H
AID_ISD_R           = "A0000005591010FFFFFFFF8900000100"
AID_ECASD           = "A0000005591010FFFFFFFF8900000200"
AID_ISD_P_FILE      = "A0000005591010FFFFFFFF8900000D00"
AID_ISD_P_MODULE    = "A0000005591010FFFFFFFF8900000E00"

class SupportedVersionNumber(BER_TLV_IE, tag=0x82):
    _construct = GreedyBytes

class IsdrProprietaryApplicationTemplate(BER_TLV_IE, tag=0xe0, nested=[SupportedVersionNumber]):
    # FIXME: lpaeSupport - what kind of tag  would it have?
    pass

# GlobalPlatform 2.1.1 Section 9.9.3.1 from pySim/global_platform.py extended with E0
class FciTemplate(BER_TLV_IE, tag=0x6f, nested=pySim.global_platform.FciTemplateNestedList +
                                               [IsdrProprietaryApplicationTemplate]):
    pass


# SGP.22 Section 5.7.3: GetEuiccConfiguredAddresses
class DefaultDpAddress(BER_TLV_IE, tag=0x80):
    _construct = Utf8Adapter(GreedyBytes)
class RootDsAddress(BER_TLV_IE, tag=0x81):
    _construct = Utf8Adapter(GreedyBytes)
class EuiccConfiguredAddresses(BER_TLV_IE, tag=0xbf3c, nested=[DefaultDpAddress, RootDsAddress]):
    pass

# SGP.22 Section 5.7.4: SetDefaultDpAddress
class SetDefaultDpAddrRes(BER_TLV_IE, tag=0x80):
    _construct = Enum(Int8ub, ok=0, undefinedError=127)
class SetDefaultDpAddress(BER_TLV_IE, tag=0xbf3f, nested=[DefaultDpAddress, SetDefaultDpAddrRes]):
    pass

# SGP.22 Section 5.7.7: GetEUICCChallenge
class EuiccChallenge(BER_TLV_IE, tag=0x80):
    _construct = HexAdapter(Bytes(16))
class GetEuiccChallenge(BER_TLV_IE, tag=0xbf2e, nested=[EuiccChallenge]):
    pass

# SGP.22 Section 5.7.8: GetEUICCInfo
class SVN(BER_TLV_IE, tag=0x82):
    _construct = VersionType
class SubjectKeyIdentifier(BER_TLV_IE, tag=0x04):
    _construct = HexAdapter(GreedyBytes)
class EuiccCiPkiListForVerification(BER_TLV_IE, tag=0xa9, nested=[SubjectKeyIdentifier]):
    pass
class EuiccCiPkiListForSigning(BER_TLV_IE, tag=0xaa, nested=[SubjectKeyIdentifier]):
    pass
class EuiccInfo1(BER_TLV_IE, tag=0xbf20, nested=[SVN, EuiccCiPkiListForVerification, EuiccCiPkiListForSigning]):
    pass
class ProfileVersion(BER_TLV_IE, tag=0x81):
    _construct = VersionType
class EuiccFirmwareVer(BER_TLV_IE, tag=0x83):
    _construct = VersionType
class ExtCardResource(BER_TLV_IE, tag=0x84):
    _construct = HexAdapter(GreedyBytes)
class UiccCapability(BER_TLV_IE, tag=0x85):
    _construct = HexAdapter(GreedyBytes) # FIXME
class TS102241Version(BER_TLV_IE, tag=0x86):
    _construct = VersionType
class GlobalPlatformVersion(BER_TLV_IE, tag=0x87):
    _construct = VersionType
class RspCapability(BER_TLV_IE, tag=0x88):
    _construct = HexAdapter(GreedyBytes) # FIXME
class EuiccCategory(BER_TLV_IE, tag=0x8b):
    _construct = Enum(Int8ub, other=0, basicEuicc=1, mediumEuicc=2, contactlessEuicc=3)
class PpVersion(BER_TLV_IE, tag=0x04):
    _construct = VersionType
class SsAcreditationNumber(BER_TLV_IE, tag=0x0c):
    _construct = Utf8Adapter(GreedyBytes)
class IpaMode(BER_TLV_IE, tag=0x90):    # see SGP.32 v1.0
    _construct = Enum(Int8ub, ipad=0, ipea=1)
class IotVersion(BER_TLV_IE, tag=0x80): # see SGP.32 v1.0
    _construct = VersionType
class IotVersionSeq(BER_TLV_IE, tag=0xa0, nested=[IotVersion]): # see SGP.32 v1.0
    pass
class IotSpecificInfo(BER_TLV_IE, tag=0x94, nested=[IotVersionSeq]): # see SGP.32 v1.0
    pass
class EuiccInfo2(BER_TLV_IE, tag=0xbf22, nested=[ProfileVersion, SVN, EuiccFirmwareVer, ExtCardResource,
                                                 UiccCapability, TS102241Version, GlobalPlatformVersion,
                                                 RspCapability, EuiccCiPkiListForVerification,
                                                 EuiccCiPkiListForSigning, EuiccCategory, PpVersion,
                                                 SsAcreditationNumber, IpaMode, IotSpecificInfo]):
    pass

# SGP.22 Section 5.7.9: ListNotification
class ProfileMgmtOperation(BER_TLV_IE, tag=0x81):
    # we have to ignore the first byte which tells us how many padding bits are used in the last octet
    _construct = Struct(Byte, "pmo"/FlagsEnum(Byte, install=0x80, enable=0x40, disable=0x20, delete=0x10))
class ListNotificationReq(BER_TLV_IE, tag=0xbf28, nested=[ProfileMgmtOperation]):
    pass
class SeqNumber(BER_TLV_IE, tag=0x80):
    _construct = Asn1DerInteger()
class NotificationAddress(BER_TLV_IE, tag=0x0c):
    _construct = Utf8Adapter(GreedyBytes)
class Iccid(BER_TLV_IE, tag=0x5a):
    _construct = BcdAdapter(GreedyBytes)
class NotificationMetadata(BER_TLV_IE, tag=0xbf2f, nested=[SeqNumber, ProfileMgmtOperation,
                                                           NotificationAddress, Iccid]):
    pass
class NotificationMetadataList(BER_TLV_IE, tag=0xa0, nested=[NotificationMetadata]):
    pass
class ListNotificationsResultError(BER_TLV_IE, tag=0x81):
    _construct = Enum(Int8ub, undefinedError=127)
class ListNotificationResp(BER_TLV_IE, tag=0xbf28, nested=[NotificationMetadataList,
                                                           ListNotificationsResultError]):
    pass

# SGP.22 Section 5.7.11: RemoveNotificationFromList
class DeleteNotificationStatus(BER_TLV_IE, tag=0x80):
    _construct = Enum(Int8ub, ok=0, nothingToDelete=1, undefinedError=127)
class NotificationSentReq(BER_TLV_IE, tag=0xbf30, nested=[SeqNumber]):
    pass
class NotificationSentResp(BER_TLV_IE, tag=0xbf30, nested=[DeleteNotificationStatus]):
    pass

# SGP.22 Section 5.7.12: LoadCRL: FIXME
class LoadCRL(BER_TLV_IE, tag=0xbf35, nested=[]): # FIXME
    pass

# SGP.22 Section 5.7.15: GetProfilesInfo
class TagList(BER_TLV_IE, tag=0x5c):
    _construct = GreedyRange(Int8ub) # FIXME: tags could be multi-byte
class ProfileInfoListReq(BER_TLV_IE, tag=0xbf2d, nested=[TagList]): # FIXME: SearchCriteria
    pass
class IsdpAid(BER_TLV_IE, tag=0x4f):
    _construct = HexAdapter(GreedyBytes)
class ProfileState(BER_TLV_IE, tag=0x9f70):
    _construct = Enum(Int8ub, disabled=0, enabled=1)
class ProfileNickname(BER_TLV_IE, tag=0x90):
    _construct = Utf8Adapter(GreedyBytes)
class ServiceProviderName(BER_TLV_IE, tag=0x91):
    _construct = Utf8Adapter(GreedyBytes)
class ProfileName(BER_TLV_IE, tag=0x92):
    _construct = Utf8Adapter(GreedyBytes)
class IconType(BER_TLV_IE, tag=0x93):
    _construct = Enum(Int8ub, jpg=0, png=1)
class Icon(BER_TLV_IE, tag=0x94):
    _construct = GreedyBytes
class ProfileClass(BER_TLV_IE, tag=0x95):
    _construct = Enum(Int8ub, test=0, provisioning=1, operational=2)
class ProfileInfo(BER_TLV_IE, tag=0xe3, nested=[Iccid, IsdpAid, ProfileState, ProfileNickname,
                                                ServiceProviderName, ProfileName, IconType, Icon,
                                                ProfileClass]): # FIXME: more IEs
    pass
class ProfileInfoSeq(BER_TLV_IE, tag=0xa0, nested=[ProfileInfo]):
    pass
class ProfileInfoListError(BER_TLV_IE, tag=0x81):
    _construct = Enum(Int8ub, incorrectInputValues=1, undefinedError=2)
class ProfileInfoListResp(BER_TLV_IE, tag=0xbf2d, nested=[ProfileInfoSeq, ProfileInfoListError]):
    pass

# SGP.22 Section 5.7.16:: EnableProfile
class RefreshFlag(BER_TLV_IE, tag=0x81): # FIXME
    _construct = Int8ub # FIXME
class EnableResult(BER_TLV_IE, tag=0x80):
    _construct = Enum(Int8ub, ok=0, iccidOrAidNotFound=1, profileNotInDisabledState=2,
                      disallowedByPolicy=3, wrongProfileReenabling=4, catBusy=5, undefinedError=127)
class ProfileIdentifier(BER_TLV_IE, tag=0xa0, nested=[IsdpAid, Iccid]):
    pass
class EnableProfileReq(BER_TLV_IE, tag=0xbf31, nested=[ProfileIdentifier, RefreshFlag]):
    pass
class EnableProfileResp(BER_TLV_IE, tag=0xbf31, nested=[EnableResult]):
    pass

# SGP.22 Section 5.7.17 DisableProfile
class DisableResult(BER_TLV_IE, tag=0x80):
    _construct = Enum(Int8ub, ok=0, iccidOrAidNotFound=1, profileNotInEnabledState=2,
                      disallowedByPolicy=3, catBusy=5, undefinedError=127)
class DisableProfileReq(BER_TLV_IE, tag=0xbf32, nested=[ProfileIdentifier, RefreshFlag]):
    pass
class DisableProfileResp(BER_TLV_IE, tag=0xbf32, nested=[DisableResult]):
    pass

# SGP.22 Section 5.7.18: DeleteProfile
class DeleteResult(BER_TLV_IE, tag=0x80):
    _construct = Enum(Int8ub, ok=0, iccidOrAidNotFound=1, profileNotInDisabledState=2,
                      disallowedByPolicy=3, undefinedError=127)
class DeleteProfileReq(BER_TLV_IE, tag=0xbf33, nested=[IsdpAid, Iccid]):
    pass
class DeleteProfileResp(BER_TLV_IE, tag=0xbf33, nested=[DeleteResult]):
    pass

# SGP.22 Section 5.7.20 GetEID
class EidValue(BER_TLV_IE, tag=0x5a):
    _construct = HexAdapter(GreedyBytes)
class GetEuiccData(BER_TLV_IE, tag=0xbf3e, nested=[TagList, EidValue]):
    pass

# SGP.22 Section 5.7.21: ES10c SetNickname
class SnrProfileNickname(BER_TLV_IE, tag=0x8f):
    _construct = Utf8Adapter(GreedyBytes)
class SetNicknameReq(BER_TLV_IE, tag=0xbf29, nested=[Iccid, SnrProfileNickname]):
    pass
class SetNicknameResult(BER_TLV_IE, tag=0x80):
    _construct = Enum(Int8ub, ok=0, iccidNotFound=1, undefinedError=127)
class SetNicknameResp(BER_TLV_IE, tag=0xbf29, nested=[SetNicknameResult]):
    pass

# SGP.32 Section 5.9.10: ES10b: GetCerts
class GetCertsReq(BER_TLV_IE, tag=0xbf56):
    pass
class EumCertificate(BER_TLV_IE, tag=0xa5):
    _construct = GreedyBytes
class EuiccCertificate(BER_TLV_IE, tag=0xa6):
    _construct = GreedyBytes
class GetCertsError(BER_TLV_IE, tag=0x81):
    _construct = Enum(Int8ub, invalidCiPKId=1, undefinedError=127)
class GetCertsResp(BER_TLV_IE, tag=0xbf56, nested=[EumCertificate, EuiccCertificate, GetCertsError]):
    pass

# SGP.32 Section 5.9.18: ES10b: GetEimConfigurationData
class EimId(BER_TLV_IE, tag=0x80):
    _construct = Utf8Adapter(GreedyBytes)
class EimFqdn(BER_TLV_IE, tag=0x81):
    _construct = Utf8Adapter(GreedyBytes)
class EimIdType(BER_TLV_IE, tag=0x82):
    _construct = Enum(Int8ub, eimIdTypeOid=1, eimIdTypeFqdn=2, eimIdTypeProprietary=3)
class CounterValue(BER_TLV_IE, tag=0x83):
    _construct = Asn1DerInteger()
class AssociationToken(BER_TLV_IE, tag=0x84):
    _construct = Asn1DerInteger()
class EimSupportedProtocol(BER_TLV_IE, tag=0x87):
    _construct = Enum(Int8ub, eimRetrieveHttps=0, eimRetrieveCoaps=1, eimInjectHttps=2, eimInjectCoaps=3,
                      eimProprietary=4)
# FIXME: eimPublicKeyData, trustedPublicKeyDataTls, euiccCiPKId
class EimConfigurationData(BER_TLV_IE, tag=0x80, nested=[EimId, EimFqdn, EimIdType, CounterValue,
                                                         AssociationToken, EimSupportedProtocol]):
    pass
class EimConfigurationDataSeq(BER_TLV_IE, tag=0xa0, nested=[EimConfigurationData]):
    pass
class GetEimConfigurationData(BER_TLV_IE, tag=0xbf55, nested=[EimConfigurationDataSeq]):
    pass

class CardApplicationISDR(pySim.global_platform.CardApplicationSD):
    def __init__(self):
        super().__init__(name='ADF.ISD-R', aid=AID_ISD_R,
                         desc='ISD-R (Issuer Security Domain Root) Application')
        self.adf.decode_select_response = self.decode_select_response
        self.adf.shell_commands += [self.AddlShellCommands()]
        # we attempt to retrieve ISD-R key material from CardKeyProvider identified by EID
        self.adf.scp_key_identity = 'EID'

    @staticmethod
    def store_data(scc: SimCardCommands, tx_do: Hexstr, exp_sw: SwMatchstr ="9000") -> Tuple[Hexstr, SwHexstr]:
        """Perform STORE DATA according to Table 47+48 in Section 5.7.2 of SGP.22.
        Only single-block store supported for now."""
        capdu = '80E29100%02x%s' % (len(tx_do)//2, tx_do)
        return scc.send_apdu_checksw(capdu, exp_sw)

    @staticmethod
    def store_data_tlv(scc: SimCardCommands, cmd_do, resp_cls, exp_sw: SwMatchstr = '9000'):
        """Transceive STORE DATA APDU with the card, transparently encoding the command data from TLV
        and decoding the response data tlv."""
        if cmd_do:
            cmd_do_enc = cmd_do.to_tlv()
            cmd_do_len = len(cmd_do_enc)
            if cmd_do_len > 255:
                return ValueError('DO > 255 bytes not supported yet')
        else:
            cmd_do_enc = b''
        (data, _sw) = CardApplicationISDR.store_data(scc, b2h(cmd_do_enc), exp_sw=exp_sw)
        if data:
            if resp_cls:
                resp_do = resp_cls()
                resp_do.from_tlv(h2b(data))
                return resp_do
            else:
                return data
        else:
            return None

    @staticmethod
    def get_eid(scc: SimCardCommands) -> str:
        ged_cmd = GetEuiccData(children=[TagList(decoded=[0x5A])])
        ged = CardApplicationISDR.store_data_tlv(scc, ged_cmd, GetEuiccData)
        d = ged.to_dict()
        return flatten_dict_lists(d['get_euicc_data'])['eid_value']

    def decode_select_response(self, data_hex: Hexstr) -> object:
        t = FciTemplate()
        t.from_tlv(h2b(data_hex))
        d = t.to_dict()
        return flatten_dict_lists(d['fci_template'])

    @with_default_category('Application-Specific Commands')
    class AddlShellCommands(CommandSet):

        es10x_store_data_parser = argparse.ArgumentParser()
        es10x_store_data_parser.add_argument('TX_DO', help='Hexstring of encoded to-be-transmitted DO')

        @cmd2.with_argparser(es10x_store_data_parser)
        def do_es10x_store_data(self, opts):
            """Perform a raw STORE DATA command as defined for the ES10x eUICC interface."""
            (_data, _sw) = CardApplicationISDR.store_data(self._cmd.lchan.scc, opts.TX_DO)

        def do_get_euicc_configured_addresses(self, _opts):
            """Perform an ES10a GetEuiccConfiguredAddresses function."""
            eca = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, EuiccConfiguredAddresses(), EuiccConfiguredAddresses)
            d = eca.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['euicc_configured_addresses']))

        set_def_dp_addr_parser = argparse.ArgumentParser()
        set_def_dp_addr_parser.add_argument('DP_ADDRESS', help='Default SM-DP+ address as UTF-8 string')

        @cmd2.with_argparser(set_def_dp_addr_parser)
        def do_set_default_dp_address(self, opts):
            """Perform an ES10a SetDefaultDpAddress function."""
            sdda_cmd = SetDefaultDpAddress(children=[DefaultDpAddress(decoded=opts.DP_ADDRESS)])
            sdda = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, sdda_cmd, SetDefaultDpAddress)
            d = sdda.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['set_default_dp_address']))

        def do_get_euicc_challenge(self, _opts):
            """Perform an ES10b GetEUICCChallenge function."""
            gec = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, GetEuiccChallenge(), GetEuiccChallenge)
            d = gec.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['get_euicc_challenge']))

        def do_get_euicc_info1(self, _opts):
            """Perform an ES10b GetEUICCInfo (1) function."""
            ei1 = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, EuiccInfo1(), EuiccInfo1)
            d = ei1.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['euicc_info1']))

        def do_get_euicc_info2(self, _opts):
            """Perform an ES10b GetEUICCInfo (2) function."""
            ei2 = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, EuiccInfo2(), EuiccInfo2)
            d = ei2.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['euicc_info2']))

        def do_list_notification(self, _opts):
            """Perform an ES10b ListNotification function."""
            ln = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, ListNotificationReq(), ListNotificationResp)
            d = ln.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['list_notification_resp']))

        rem_notif_parser = argparse.ArgumentParser()
        rem_notif_parser.add_argument('SEQ_NR', type=int, help='Sequence Number of the to-be-removed notification')

        @cmd2.with_argparser(rem_notif_parser)
        def do_remove_notification_from_list(self, opts):
            """Perform an ES10b RemoveNotificationFromList function."""
            rn_cmd = NotificationSentReq(children=[SeqNumber(decoded=opts.SEQ_NR)])
            rn = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, rn_cmd, NotificationSentResp)
            d = rn.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['notification_sent_resp']))

        def do_get_profiles_info(self, _opts):
            """Perform an ES10c GetProfilesInfo function."""
            pi = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, ProfileInfoListReq(), ProfileInfoListResp)
            d = pi.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['profile_info_list_resp']))

        en_prof_parser = argparse.ArgumentParser()
        en_prof_grp = en_prof_parser.add_mutually_exclusive_group()
        en_prof_grp.add_argument('--isdp-aid', help='Profile identified by its ISD-P AID')
        en_prof_grp.add_argument('--iccid', help='Profile identified by its ICCID')
        en_prof_parser.add_argument('--refresh-required', action='store_true', help='whether a REFRESH is required')

        @cmd2.with_argparser(en_prof_parser)
        def do_enable_profile(self, opts):
            """Perform an ES10c EnableProfile function."""
            if opts.isdp_aid:
                p_id = ProfileIdentifier(children=[IsdpAid(decoded=opts.isdp_aid)])
            elif opts.iccid:
                p_id = ProfileIdentifier(children=[Iccid(decoded=opts.iccid)])
            else:
                # this is guaranteed by argparse; but we need this to make pylint happy
                raise ValueError('Either ISD-P AID or ICCID must be given')
            ep_cmd_contents = [p_id, RefreshFlag(decoded=opts.refresh_required)]
            ep_cmd = EnableProfileReq(children=ep_cmd_contents)
            ep = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, ep_cmd, EnableProfileResp)
            d = ep.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['enable_profile_resp']))

        dis_prof_parser = argparse.ArgumentParser()
        dis_prof_grp = dis_prof_parser.add_mutually_exclusive_group()
        dis_prof_grp.add_argument('--isdp-aid', help='Profile identified by its ISD-P AID')
        dis_prof_grp.add_argument('--iccid', help='Profile identified by its ICCID')
        dis_prof_parser.add_argument('--refresh-required', action='store_true', help='whether a REFRESH is required')

        @cmd2.with_argparser(dis_prof_parser)
        def do_disable_profile(self, opts):
            """Perform an ES10c DisableProfile function."""
            if opts.isdp_aid:
                p_id = ProfileIdentifier(children=[IsdpAid(decoded=opts.isdp_aid)])
            elif opts.iccid:
                p_id = ProfileIdentifier(children=[Iccid(decoded=opts.iccid)])
            else:
                # this is guaranteed by argparse; but we need this to make pylint happy
                raise ValueError('Either ISD-P AID or ICCID must be given')
            dp_cmd_contents = [p_id, RefreshFlag(decoded=opts.refresh_required)]
            dp_cmd = DisableProfileReq(children=dp_cmd_contents)
            dp = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, dp_cmd, DisableProfileResp)
            d = dp.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['disable_profile_resp']))

        del_prof_parser = argparse.ArgumentParser()
        del_prof_grp = del_prof_parser.add_mutually_exclusive_group()
        del_prof_grp.add_argument('--isdp-aid', help='Profile identified by its ISD-P AID')
        del_prof_grp.add_argument('--iccid', help='Profile identified by its ICCID')

        @cmd2.with_argparser(del_prof_parser)
        def do_delete_profile(self, opts):
            """Perform an ES10c DeleteProfile function."""
            if opts.isdp_aid:
                p_id = IsdpAid(decoded=opts.isdp_aid)
            elif opts.iccid:
                p_id = Iccid(decoded=opts.iccid)
            else:
                # this is guaranteed by argparse; but we need this to make pylint happy
                raise ValueError('Either ISD-P AID or ICCID must be given')
            dp_cmd_contents = [p_id]
            dp_cmd = DeleteProfileReq(children=dp_cmd_contents)
            dp = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, dp_cmd, DeleteProfileResp)
            d = dp.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['delete_profile_resp']))


        def do_get_eid(self, _opts):
            """Perform an ES10c GetEID function."""
            ged_cmd = GetEuiccData(children=[TagList(decoded=[0x5A])])
            ged = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, ged_cmd, GetEuiccData)
            d = ged.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['get_euicc_data']))

        set_nickname_parser = argparse.ArgumentParser()
        set_nickname_parser.add_argument('--profile-nickname', help='Nickname of the profile')
        set_nickname_parser.add_argument('ICCID', help='ICCID of the profile whose nickname to set')

        @cmd2.with_argparser(set_nickname_parser)
        def do_set_nickname(self, opts):
            """Perform an ES10c SetNickname function."""
            nickname = opts.profile_nickname or ''
            sn_cmd_contents = [Iccid(decoded=opts.ICCID), ProfileNickname(decoded=nickname)]
            sn_cmd = SetNicknameReq(children=sn_cmd_contents)
            sn = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, sn_cmd, SetNicknameResp)
            d = sn.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['set_nickname_resp']))

        def do_get_certs(self, _opts):
            """Perform an ES10c GetCerts() function on an IoT eUICC."""
            gc = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, GetCertsReq(), GetCertsResp)
            d = gc.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['get_certs_resp']))

        def do_get_eim_configuration_data(self, _opts):
            """Perform an ES10b GetEimConfigurationData function on an Iot eUICC."""
            gec = CardApplicationISDR.store_data_tlv(self._cmd.lchan.scc, GetEimConfigurationData(),
                                                     GetEimConfigurationData)
            d = gec.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['get_eim_configuration_data']))

class CardApplicationECASD(pySim.global_platform.CardApplicationSD):
    def decode_select_response(self, data_hex: Hexstr) -> object:
        t = FciTemplate()
        t.from_tlv(h2b(data_hex))
        d = t.to_dict()
        return flatten_dict_lists(d['fci_template'])

    def __init__(self):
        super().__init__(name='ADF.ECASD', aid=AID_ECASD,
                         desc='ECASD (eUICC Controlling Authority Security Domain) Application')
        self.adf.decode_select_response = self.decode_select_response
        self.adf.shell_commands += [self.AddlShellCommands()]
        # we attempt to retrieve ECASD key material from CardKeyProvider identified by EID
        self.adf.scp_key_identity = 'EID'

    @with_default_category('Application-Specific Commands')
    class AddlShellCommands(CommandSet):
        pass

class CardProfileEuiccSGP32(CardProfileUICC):
    ORDER = 5

    def __init__(self):
        super().__init__(name='IoT eUICC (SGP.32)')

    @classmethod
    def _try_match_card(cls, scc: SimCardCommands) -> None:
        # try a command only supported by SGP.32
        scc.cla_byte = "00"
        scc.select_adf(AID_ISD_R)
        CardApplicationISDR.store_data_tlv(scc, GetCertsReq(), GetCertsResp)

class CardProfileEuiccSGP22(CardProfileUICC):
    ORDER = 6

    def __init__(self):
        super().__init__(name='Consumer eUICC (SGP.22)')

    @classmethod
    def _try_match_card(cls, scc: SimCardCommands) -> None:
        # try to read EID from ISD-R
        scc.cla_byte = "00"
        scc.select_adf(AID_ISD_R)
        eid = CardApplicationISDR.get_eid(scc)
        # TODO: Store EID identity?

class CardProfileEuiccSGP02(CardProfileUICC):
    ORDER = 7

    def __init__(self):
        super().__init__(name='M2M eUICC (SGP.02)')

    @classmethod
    def _try_match_card(cls, scc: SimCardCommands) -> None:
        scc.cla_byte = "00"
        scc.select_adf(AID_ECASD)
        scc.get_data(0x5a)
        # TODO: Store EID identity?
