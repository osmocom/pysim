# -*- coding: utf-8 -*-

"""
Various definitions related to GSMA eSIM / eUICC

Related Specs: GSMA SGP.22, GSMA SGP.02, etc.
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

from pySim.tlv import *
from pySim.construct import *
from construct import Optional as COptional
from construct import *
import argparse
from cmd2 import cmd2, CommandSet, with_default_category
from pySim.commands import SimCardCommands
from pySim.filesystem import CardADF, CardApplication
from pySim.utils import Hexstr, SwHexstr
import pySim.global_platform

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

sw_isdr = {
    'ISD-R': {
        '6a80': 'Incorrect values in command data',
        '6a82': 'Profile not found',
        '6a88': 'Reference data not found',
        '6985': 'Conditions of use not satisfied',
    }
}

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
class SubjectKeyIdentifier(BER_TLV_IE, tag=0x81):
    _construct = HexAdapter(GreedyBytes)
class SubjectKeyIdentifierSeq(BER_TLV_IE, tag=0x04, nested=[SubjectKeyIdentifier]):
    pass
class EuiccCiPkiListForVerification(BER_TLV_IE, tag=0xa9, nested=[SubjectKeyIdentifierSeq]):
    pass
class EuiccCiPkiListForSigning(BER_TLV_IE, tag=0xaa, nested=[SubjectKeyIdentifierSeq]):
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

class EuiccInfo2(BER_TLV_IE, tag=0xbf22, nested=[ProfileVersion, SVN, EuiccFirmwareVer, ExtCardResource,
                                                 UiccCapability, TS102241Version, GlobalPlatformVersion,
                                                 RspCapability, EuiccCiPkiListForVerification,
                                                 EuiccCiPkiListForSigning, EuiccCategory, PpVersion,
                                                 SsAcreditationNumber]):
    pass


# SGP.22 Section 5.7.9: ListNotification
class ProfileMgmtOperation(BER_TLV_IE, tag=0x81):
    _construct = FlagsEnum(Byte, install=1, enable=2, disable=4, delete=8)
class ListNotificationReq(BER_TLV_IE, tag=0xbf28, nested=[ProfileMgmtOperation]):
    pass
class SeqNumber(BER_TLV_IE, tag=0x80):
    _construct = GreedyInteger
class NotificationAddress(BER_TLV_IE, tag=0x82):
    _construct = Utf8Adapter(GreedyBytes)
class Iccid(BER_TLV_IE, tag=0x5a):
    _construct = HexAdapter(GreedyBytes)
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

# SGP.22 Section 5.7.16:: EnableProfile
class RefreshFlag(BER_TLV_IE, tag=0x88): # FIXME
    _construct = Int8ub # FIXME
class IsdpAid(BER_TLV_IE, tag=0x4f):
    _construct = HexAdapter(GreedyBytes)
class EnableResult(BER_TLV_IE, tag=0x80):
    _construct = Enum(Int8ub, ok=0, iccidOrAidNotFound=1, profileNotInDisabledState=2,
                      disallowedByPolicy=3, wrongProfileReenabling=4, catBusy=5, undefinedError=127)
class EnableProfileReq(BER_TLV_IE, tag=0xbf31, nested=[IsdpAid, Iccid, RefreshFlag]):
    pass
class EnableProfileResp(BER_TLV_IE, tag=0xbf31, nested=[EnableResult]):
    pass

# SGP.22 Section 5.7.17 DisableProfile
class DisableResult(BER_TLV_IE, tag=0x80):
    _construct = Enum(Int8ub, ok=0, iccidOrAidNotFound=1, profileNotInEnabledState=2,
                      disallowedByPolicy=3, catBusy=5, undefinedError=127)
class DisableProfileReq(BER_TLV_IE, tag=0xbf32, nested=[IsdpAid, Iccid, RefreshFlag]):
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
class TagList(BER_TLV_IE, tag=0x5c):
    _construct = GreedyRange(Int8ub)
class EidValue(BER_TLV_IE, tag=0x5a):
    _construct = HexAdapter(GreedyBytes)
class GetEuiccData(BER_TLV_IE, tag=0xbf3e, nested=[TagList, EidValue]):
    pass

# SGP.22 Section 5.7.21: ES10c SetNickname
class ProfileNickname(BER_TLV_IE, tag=0x8f):
    _construct = Utf8Adapter(GreedyBytes)
class SetNicknameReq(BER_TLV_IE, tag=0xbf29, children=[Iccid, ProfileNickname]):
    pass
class SetNicknameResult(BER_TLV_IE, tag=0x80):
    _construct = Enum(Int8ub, ok=0, iccidNotFound=1, undefinedError=127)
class SetNicknameResp(BER_TLV_IE, tag=0xbf29, children=[SetNicknameResult]):
    pass


class ADF_ISDR(CardADF):
    def __init__(self, aid=AID_ISD_R, name='ADF.ISD-R', fid=None, sfid=None,
                 desc='ISD-R (Issuer Security Domain Root) Application'):
        super().__init__(aid=aid, fid=fid, sfid=sfid, name=name, desc=desc)
        self.shell_commands += [self.AddlShellCommands()]

    @staticmethod
    def store_data(scc: SimCardCommands, tx_do: Hexstr) -> Tuple[Hexstr, SwHexstr]:
        """Perform STORE DATA according to Table 47+48 in Section 5.7.2 of SGP.22.
        Only single-block store supported for now."""
        capdu = '%sE29100%02u%s' % (scc.cla4lchan('80'), len(tx_do)//2, tx_do)
        return scc._tp.send_apdu_checksw(capdu)

    @staticmethod
    def store_data_tlv(scc: SimCardCommands, cmd_do, resp_cls, exp_sw='9000'):
        """Transceive STORE DATA APDU with the card, transparently encoding the command data from TLV
        and decoding the response data tlv."""
        if cmd_do:
            cmd_do_enc = cmd_do.to_tlv()
            cmd_do_len = len(cmd_do_enc)
            if cmd_do_len > 255:
                return ValueError('DO > 255 bytes not supported yet')
        else:
            cmd_do_enc = b''
        (data, sw) = ADF_ISDR.store_data(scc, b2h(cmd_do_enc))
        if data:
            if resp_cls:
                resp_do = resp_cls()
                resp_do.from_tlv(h2b(data))
                return resp_do
            else:
                return data
        else:
            return None

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
            (data, sw) = ADF_ISDR.store_data(self._cmd.lchan.scc, opts.TX_DO)

        def do_get_euicc_configured_addresses(self, opts):
            """Perform an ES10a GetEuiccConfiguredAddresses function."""
            eca = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, EuiccConfiguredAddresses(), EuiccConfiguredAddresses)
            d = eca.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['euicc_configured_addresses']))

        set_def_dp_addr_parser = argparse.ArgumentParser()
        set_def_dp_addr_parser.add_argument('DP_ADDRESS', help='Default SM-DP+ address as UTF-8 string')

        @cmd2.with_argparser(set_def_dp_addr_parser)
        def do_set_default_dp_address(self, opts):
            """Perform an ES10a SetDefaultDpAddress function."""
            sdda_cmd = SetDefaultDpAddress(children=[DefaultDpAddress(decoded=opts.DP_ADDRESS)])
            sdda = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, sdda_cmd, SetDefaultDpAddress)
            d = sdda.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['set_default_dp_address']))

        def do_get_euicc_challenge(self, opts):
            """Perform an ES10b GetEUICCChallenge function."""
            gec = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, GetEuiccChallenge(), GetEuiccChallenge)
            d = gec.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['get_euicc_challenge']))

        def do_get_euicc_info1(self, opts):
            """Perform an ES10b GetEUICCInfo (1) function."""
            ei1 = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, EuiccInfo1(), EuiccInfo1)
            d = ei1.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['euicc_info1']))

        def do_get_euicc_info2(self, opts):
            """Perform an ES10b GetEUICCInfo (2) function."""
            ei2 = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, EuiccInfo2(), EuiccInfo2)
            d = ei2.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['euicc_info2']))

        def do_list_notification(self, opts):
            """Perform an ES10b ListNotification function."""
            ln = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, ListNotificationReq(), ListNotificationResp)
            d = ln.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['list_notification_resp']))

        rem_notif_parser = argparse.ArgumentParser()
        rem_notif_parser.add_argument('SEQ_NR', type=int, help='Sequence Number of the to-be-removed notification')

        @cmd2.with_argparser(rem_notif_parser)
        def do_remove_notification_from_list(self, opts):
            """Perform an ES10b RemoveNotificationFromList function."""
            rn_cmd = NotificationSentReq(children=[SeqNumber(decoded=opts.SEQ_NR)])
            rn = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, rn_cmd, NotificationSentResp)
            d = rn.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['notification_sent_resp']))

        en_prof_parser = argparse.ArgumentParser()
        en_prof_grp = en_prof_parser.add_mutually_exclusive_group()
        en_prof_grp.add_argument('--isdp-aid', help='Profile identified by its ISD-P AID')
        en_prof_grp.add_argument('--iccid', help='Profile identified by its ICCID')
        en_prof_parser.add_argument('--refresh-required', action='store_true', help='whether a REFRESH is required')

        @cmd2.with_argparser(en_prof_parser)
        def do_enable_profile(self, opts):
            """Perform an ES10c EnableProfile function."""
            ep_cmd_contents = []
            if opts.isdp_aid:
                ep_cmd_contents.append(IsdpAid(decoded=opts.isdp_aid))
            if opts.iccid:
                ep_cmd_contents.append(Iccid(decoded=opts.iccid))
            if opts.refresh_required:
                ep_cmd_contents.append(RefreshFlag())
            ep_cmd = EnableProfileReq(children=ep_cmd_contents)
            ep = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, ep_cmd, EnableProfileResp)
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
            dp_cmd_contents = []
            if opts.isdp_aid:
                dp_cmd_contents.append(IsdpAid(decoded=opts.isdp_aid))
            if opts.iccid:
                dp_cmd_contents.append(Iccid(decoded=opts.iccid))
            if opts.refresh_required:
                dp_cmd_contents.append(RefreshFlag())
            dp_cmd = DisableProfileReq(children=dp_cmd_contents)
            dp = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, dp_cmd, DisableProfileResp)
            d = dp.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['disable_profile_resp']))

        del_prof_parser = argparse.ArgumentParser()
        del_prof_grp = del_prof_parser.add_mutually_exclusive_group()
        del_prof_grp.add_argument('--isdp-aid', help='Profile identified by its ISD-P AID')
        del_prof_grp.add_argument('--iccid', help='Profile identified by its ICCID')

        @cmd2.with_argparser(del_prof_parser)
        def do_delete_profile(self, opts):
            """Perform an ES10c DeleteProfile function."""
            dp_cmd_contents = []
            if opts.isdp_aid:
                dp_cmd_contents.append(IsdpAid(decoded=opts.isdp_aid))
            if opts.iccid:
                dp_cmd_contents.append(Iccid(decoded=opts.iccid))
            dp_cmd = DeleteProfileReq(children=dp_cmd_contents)
            dp = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, dp_cmd, DeleteProfileResp)
            d = dp.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['delete_profile_resp']))


        def do_get_eid(self, opts):
            """Perform an ES10c GetEID function."""
            (data, sw) = ADF_ISDR.store_data(self._cmd.lchan.scc, 'BF3E035C015A')
            ged_cmd = GetEuiccData(children=[TagList(decoded=[0x5A])])
            ged = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, ged_cmd, GetEuiccData)
            d = ged.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['get_euicc_data']))

        set_nickname_parser = argparse.ArgumentParser()
        set_nickname_parser.add_argument('ICCID', help='ICCID of the profile whose nickname to set')
        set_nickname_parser.add_argument('--profile-nickname', help='Nickname of the profile')

        @cmd2.with_argparser(set_nickname_parser)
        def do_set_nickname(self, opts):
            """Perform an ES10c SetNickname function."""
            nickname = opts.profile_nickname or ''
            sn_cmd_contents = [Iccid(decoded=opts.ICCID), ProfileNickname(decoded=nickname)]
            sn_cmd = SetNicknameReq(children=sn_cmd_contents)
            sn = ADF_ISDR.store_data_tlv(self._cmd.lchan.scc, sn_cmd, SetNicknameResp)
            d = sn.to_dict()
            self._cmd.poutput_json(flatten_dict_lists(d['set_nickname_resp']))

class ADF_ECASD(CardADF):
    def __init__(self, aid=AID_ECASD, name='ADF.ECASD', fid=None, sfid=None,
                 desc='ECASD (eUICC Controlling Authority Security Domain) Application'):
        super().__init__(aid=aid, fid=fid, sfid=sfid, name=name, desc=desc)
        self.shell_commands += [self.AddlShellCommands()]

    def decode_select_response(self, data_hex: Hexstr) -> object:
        t = FciTemplate()
        t.from_tlv(h2b(data_hex))
        d = t.to_dict()
        return flatten_dict_lists(d['fci_template'])

    @with_default_category('Application-Specific Commands')
    class AddlShellCommands(CommandSet):
        pass



class CardApplicationISDR(CardApplication):
    def __init__(self):
        super().__init__('ISD-R', adf=ADF_ISDR(), sw=sw_isdr)

class CardApplicationECASD(CardApplication):
    def __init__(self):
        super().__init__('ECASD', adf=ADF_ECASD(), sw=sw_isdr)
