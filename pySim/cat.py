"""Code related to the Card Application Toolkit (CAT) as described in
mainly) ETSI TS 102 223, ETSI TS 101 220 and USIM Application Toolkit (SAT)
as described in 3GPP TS 31.111."""

# (C) 2021-2022 by Harald Welte <laforge@osmocom.org>
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


from typing import List
from bidict import bidict
from construct import Int8ub, Int16ub, Byte, BitsInteger
from construct import Struct, Enum, BitStruct, this
from construct import Switch, GreedyRange, FlagsEnum
from osmocom.tlv import TLV_IE, COMPR_TLV_IE, BER_TLV_IE, TLV_IE_Collection
from osmocom.construct import PlmnAdapter, BcdAdapter, HexAdapter, GsmStringAdapter, TonNpi, GsmString, Bytes, GreedyBytes
from osmocom.utils import b2h
from pySim.utils import dec_xplmn_w_act

# Tag values as per TS 101 220 Table 7.23

# TS 102 223 Section 8.1
class Address(COMPR_TLV_IE, tag=0x86):
    _construct = Struct('ton_npi'/TonNpi,
                        'call_number'/BcdAdapter(GreedyBytes))

# TS 102 223 Section 8.2
class AlphaIdentifier(COMPR_TLV_IE, tag=0x85):
    # FIXME: like EF.ADN
    pass

# TS 102 223 Section 8.3
class Subaddress(COMPR_TLV_IE, tag=0x88):
    pass

# TS 102 223 Section 8.4 + TS 31.111 Section 8.4
class CapabilityConfigParams(COMPR_TLV_IE, tag=0x87):
    pass

# TS 31.111 Section 8.5
class CBSPage(COMPR_TLV_IE, tag=0x8C):
    pass

# TS 102 223 V15.3.0 Section 9.4
TypeOfCommand = Enum(Int8ub, refresh=0x01, more_time=0x02, poll_interval=0x03, polling_off=0x04,
                     set_up_event_list=0x05, set_up_call=0x10, send_ss=0x11, send_ussd=0x12,
                     send_short_message=0x13, send_dtmf=0x14, launch_browser=0x15, geo_location_req=0x16,
                     play_tone=0x20, display_text=0x21, get_inkey=0x22, get_input=0x23, select_item=0x24,
                     set_up_menu=0x25, provide_local_info=0x26, timer_management=0x27,
                     set_up_idle_mode_text=0x28, perform_card_apdu=0x30, power_on_card=0x31,
                     power_off_card=0x32, get_reader_status=0x33, run_at_command=0x34,
                     language_notification=0x35, open_channel=0x40, close_channel=0x41, receive_data=0x42,
                     send_data=0x43, get_channel_status=0x44, service_search=0x45, get_service_info=0x46,
                     declare_service=0x47, set_frames=0x50, get_frames_status=0x51, retrieve_mms=0x60,
                     submit_mms=0x61, display_mms=0x62, activate=0x70, contactless_state_changed=0x71,
                     command_container=0x72, encapsulated_session_control=0x73)

# TS 102 223 Section 8.6 + TS 31.111 Section 8.6
class CommandDetails(COMPR_TLV_IE, tag=0x81):
    _construct = Struct('command_number'/Int8ub,
                        'type_of_command'/TypeOfCommand,
                        'command_qualifier'/Int8ub)

# TS 102 223 Section 8.7
class DeviceIdentities(COMPR_TLV_IE, tag=0x82):
    DEV_IDS = bidict({
        0x01: 'keypad',
        0x02: 'display',
        0x03: 'earpiece',
        0x10: 'addl_card_reader_0',
        0x11: 'addl_card_reader_1',
        0x12: 'addl_card_reader_2',
        0x13: 'addl_card_reader_3',
        0x14: 'addl_card_reader_4',
        0x15: 'addl_card_reader_5',
        0x16: 'addl_card_reader_6',
        0x17: 'addl_card_reader_7',
        0x21: 'channel_1',
        0x22: 'channel_2',
        0x23: 'channel_3',
        0x24: 'channel_4',
        0x25: 'channel_5',
        0x26: 'channel_6',
        0x27: 'channel_7',
        0x31: 'ecat_client_1',
        0x32: 'ecat_client_2',
        0x33: 'ecat_client_3',
        0x34: 'ecat_client_4',
        0x35: 'ecat_client_5',
        0x36: 'ecat_client_6',
        0x37: 'ecat_client_7',
        0x38: 'ecat_client_8',
        0x39: 'ecat_client_9',
        0x3a: 'ecat_client_a',
        0x3b: 'ecat_client_b',
        0x3c: 'ecat_client_c',
        0x3d: 'ecat_client_d',
        0x3e: 'ecat_client_e',
        0x3f: 'ecat_client_f',
        0x81: 'uicc',
        0x82: 'terminal',
        0x83: 'network',
    })

    def _from_bytes(self, do: bytes):
        return {'source_dev_id': self.DEV_IDS[do[0]], 'dest_dev_id': self.DEV_IDS[do[1]]}

    def _to_bytes(self):
        src = self.DEV_IDS.inverse[self.decoded['source_dev_id']]
        dst = self.DEV_IDS.inverse[self.decoded['dest_dev_id']]
        return bytes([src, dst])

# TS 102 223 Section 8.8
class Duration(COMPR_TLV_IE, tag=0x84):
    _construct = Struct('time_unit'/Enum(Int8ub, minutes=0, seconds=1, tenths_of_seconds=2),
                        'time_interval'/Int8ub)

# TS 102 223 Section 8.9
class Item(COMPR_TLV_IE, tag=0x8f):
    _construct = Struct('identifier'/Int8ub,
                        'text_string'/GsmStringAdapter(GreedyBytes))

# TS 102 223 Section 8.10
class ItemIdentifier(COMPR_TLV_IE, tag=0x90):
    _construct = Struct('identifier'/Int8ub)

# TS 102 223 Section 8.11
class ResponseLength(COMPR_TLV_IE, tag=0x91):
    _construct = Struct('minimum_length'/Int8ub,
                        'maximum_length'/Int8ub)

# TS 102 223 Section 8.12
class Result(COMPR_TLV_IE, tag=0x83):
    GeneralResult = Enum(Int8ub,
                         # '0X' and '1X' indicate that the command has been performed
                         performed_successfully=0,
                         performed_with_partial_comprehension=1,
                         performed_with_missing_information=2,
                         refresh_performed_with_addl_efs_read=3,
                         porformed_successfully_but_reqd_item_not_displayed=4,
                         performed_but_modified_by_call_control_by_naa=5,
                         performed_successfully_limited_service=6,
                         performed_with_modification=7,
                         refresh_performed_but_indicated_naa_was_not_active=8,
                         performed_successfully_tone_not_played=9,
                         proactive_uicc_session_terminated_by_user=0x10,
                         backward_move_in_proactive_uicc_session_requested_by_user=0x11,
                         no_response_from_user=0x12,
                         help_information_required_by_user=0x13,
                         # '2X' indicate to the UICC that it may be worth re-trying later
                         terminal_currently_unable_to_process=0x20,
                         network_currently_unable_to_process=0x21,
                         user_did_not_accept_proactive_cmd=0x22,
                         user_cleared_down_call_before_release=0x23,
                         action_in_contradiction_with_current_timer_state=0x24,
                         interaction_with_call_control_by_naa_temporary=0x25,
                         launch_browser_generic_error=0x26,
                         mms_temporary_problem=0x27,
                         # '3X' indicate that it is not worth the UICC re-trying with an identical command
                         command_beyond_terminal_capability=0x30,
                         command_type_not_understood_by_terminal=0x31,
                         command_data_not_understood_by_terminal=0x32,
                         command_number_not_known_by_terminal=0x33,
                         error_required_values_missing=0x36,
                         multiple_card_commands_error=0x38,
                         #interaction_with_call_control_by_naa_permanent=0x39, # see below 3GPP
                         bearer_independent_protocol_error=0x3a,
                         access_technology_unable_to_process_command=0x3b,
                         frames_error=0x3c,
                         mms_error=0x3d,
                         # 3GPP TS 31.111 Section 8.12
                         ussd_or_ss_transaction_terminated_by_user=0x14,
                         ss_return_error=0x34,
                         sms_rp_error=0x35,
                         ussd_return_error=0x37,
                         interaction_with_cc_by_usim_or_mo_sm_by_usim_permanent=0x39)
    # TS 102 223 Section 8.12.2
    AddlInfoTermProblem = Enum(Int8ub,
                                no_specific_cause=0x00,
                                screen_is_busy=0x01,
                                terminal_currently_busy_on_call=0x02,
                                no_service=0x04,
                                access_control_class_bar=0x05,
                                radio_resource_not_granted=0x06,
                                not_in_speech_call=0x07,
                                terminal_currently_busy_on_send_dtmf=0x09,
                                no_naa_active=0x10,
                                # TS 31.111 section 8.12
                                me_currently_busy_on_ss_transaction=0x03,
                                me_currently_busy_on_ussd_transaction=0x08)
    # TS 102 223 Section 8.12.8 / TS 31.111 Section 8.12.8
    AddlInfoCallControl= Enum(Int8ub,
                                no_specific_cause=0x00,
                                action_not_allowed=0x01,
                                the_type_of_request_has_changed=0x02)
    # TS 102 223 Section 8.12.9
    AddlInfoMultipleCard = Enum(Int8ub,
                                no_specific_cause=0x00,
                                card_reader_removed_or_not_present=0x01,
                                card_removed_or_not_present=0x02,
                                card_reader_busy=0x03,
                                card_powered_off=0x04,
                                capdu_format_error=0x05,
                                mute_card=0x06,
                                transmission_error=0x07,
                                protocol_not_supported=0x08,
                                specified_reader_not_valid=0x09)
    # TS 102 223 Section 8.12.10
    AddlInfoLaunchBrowser = Enum(Int8ub,
                                no_specific_cause=0x00,
                                bearer_unavailable=0x01,
                                browser_unavailable=0x02,
                                terminal_unable_to_read_provisioning_data=0x03,
                                default_url_unavailable=0x04)
    # TS 102 223 Section 8.12.11
    AddlInfoBip = Enum(Int8ub,  no_specific_cause=0x00,
                                no_channel_availabile=0x01,
                                channel_closed=0x02,
                                channel_id_not_valid=0x03,
                                requested_buffer_size_not_available=0x04,
                                security_error=0x05,
                                requested_uicc_if_transp_level_not_available=0x06,
                                remote_device_not_reachable=0x07,
                                service_error=0x08,
                                service_identifer_unknown=0x09,
                                port_not_available=0x10,
                                launch_parameters_missing_or_incorrect=0x11,
                                application_launch_failed=0x12)
    # TS 102 223 Section 8.12.11
    AddlInfoFrames = Enum(Int8ub,
                                no_specific_cause=0x00,
                                frame_identifier_not_valid=0x01,
                                num_of_frames_beyond_terminal_capabilities=0x02,
                                no_frame_defined=0x03,
                                requested_size_not_supported=0x04,
                                default_active_frame_not_valid=0x05)

    _construct = Struct('general_result'/GeneralResult,
                        'additional_information'/Switch(this.general_result,
                        {
                            'terminal_currently_unable_to_process': AddlInfoTermProblem,
                            'interaction_with_cc_by_usim_or_mo_sm_by_usim_permanent': AddlInfoCallControl,
                            'multiple_card_commands_error': AddlInfoMultipleCard,
                            'launch_browser_generic_error': AddlInfoLaunchBrowser,
                            'bearer_independent_protocol_error': AddlInfoBip,
                            'frames_error': AddlInfoFrames
                        }, default=HexAdapter(GreedyBytes)))

# TS 102 223 Section 8.13  + TS 31.111 Section 8.13
class SMS_TPDU(COMPR_TLV_IE, tag=0x8B):
    _construct = Struct('tpdu'/HexAdapter(GreedyBytes))

# TS 31.111 Section 8.14
class SsString(COMPR_TLV_IE, tag=0x89):
    _construct = Struct('ton_npi'/TonNpi, 'ss_string'/HexAdapter(GreedyBytes))


# TS 102 223 Section 8.15
class TextString(COMPR_TLV_IE, tag=0x8D):
    _test_de_encode = [
        ( '8d090470617373776f7264', {'dcs': 4, 'text_string': '70617373776f7264'} ),
    ]
    _construct = Struct('dcs'/Int8ub, # TS 03.38
                        'text_string'/HexAdapter(GreedyBytes))

# TS 102 223 Section 8.16
class Tone(COMPR_TLV_IE, tag=0x8E):
    _construct = Struct('tone'/Enum(Int8ub, dial_tone=0x01,
                                            called_subscriber_busy=0x02,
                                            congestion=0x03,
                                            radio_path_acknowledge=0x04,
                                            radio_path_not_available=0x05,
                                            error_special_info=0x06,
                                            call_waiting_tone=0x07,
                                            ringing_tone=0x08,
                                            general_beep=0x10,
                                            positive_ack_tone=0x11,
                                            negative_ack_or_error_tone=0x12,
                                            ringing_tone_speech=0x13,
                                            alert_tone_sms=0x14,
                                            critical_alert=0x15,
                                            vibrate_only=0x20,
                                            happy_tone=0x30,
                                            sad_tone=0x31,
                                            urgent_action_tone=0x32,
                                            question_tone=0x33,
                                            message_received_tone=0x34,
                                            melody_1=0x40,
                                            melody_2=0x41,
                                            melody_3=0x42,
                                            melody_4=0x43,
                                            melody_5=0x44,
                                            melody_6=0x45,
                                            melody_7=0x46,
                                            melody_8=0x47))

# TS 31 111 Section 8.17
class USSDString(COMPR_TLV_IE, tag=0x8A):
    _construct = Struct('dcs'/Int8ub,
                        'ussd_string'/HexAdapter(GreedyBytes))

# TS 102 223 Section 8.18
class FileList(COMPR_TLV_IE, tag=0x92):
    FileId=HexAdapter(Bytes(2))
    _construct = Struct('number_of_files'/Int8ub,
                        'files'/GreedyRange(FileId))

# TS 102 223 Secton 8.19
class LocationInformation(COMPR_TLV_IE, tag=0x93):
    pass

# TS 102 223 Secton 8.20
class IMEI(COMPR_TLV_IE, tag=0x94):
    _construct = BcdAdapter(GreedyBytes)

# TS 102 223 Secton 8.21
class HelpRequest(COMPR_TLV_IE, tag=0x95):
    pass

# TS 102 223 Secton 8.22
class NetworkMeasurementResults(COMPR_TLV_IE, tag=0x96):
    _construct = BcdAdapter(GreedyBytes)

# TS 102 223 Section 8.23
class DefaultText(COMPR_TLV_IE, tag=0x97):
    _construct = Struct('dcs'/Int8ub,
                        'text_string'/HexAdapter(GreedyBytes))

# TS 102 223 Section 8.24
class ItemsNextActionIndicator(COMPR_TLV_IE, tag=0x98):
    _construct = GreedyRange(Int8ub)

class EventList(COMPR_TLV_IE, tag=0x99):
    Event = Enum(Int8ub,    mt_call=0x00,
                            call_connected=0x01,
                            call_disconnected=0x02,
                            location_status=0x03,
                            user_activity=0x04,
                            idle_screen_available=0x05,
                            card_reader_status=0x06,
                            language_selection=0x07,
                            browser_termination=0x08,
                            data_available=0x09,
                            channel_status=0x0a,
                            access_technology_change=0x0b,
                            display_parameters_changed=0x0c,
                            local_connection=0x0d,
                            network_search_mode_change=0x0e,
                            browsing_status=0x0f,
                            frames_informtion_change=0x10,
                            hci_connectivity_event=0x13,
                            access_technology_change_multiple=0x14,
                            contactless_state_request=0x16,
                            profile_container=0x19,
                            secured_profile_container=0x1b,
                            poll_interval_negotation=0x1c,
                            # TS 31.111 Section 8.25
                            wlan_access_status=0x11,
                            network_rejection=0x12,
                            csg_cell_selection=0x15,
                            ims_registration=0x17,
                            incoming_ims_data=0x18,
                            data_connection_status_change=0x1d)
    _construct = GreedyRange(Event)

# TS 102 223 Section 8.26
class Cause(COMPR_TLV_IE, tag=0x9a):
    pass

# TS 102 223 Section 8.27
class LocationStatus(COMPR_TLV_IE, tag=0x9b):
    _construct = Enum(Int8ub, normal_service=0, limited_service=1, no_service=2)

# TS 102 223 Section 8.31
class IconIdentifier(COMPR_TLV_IE, tag=0x9e):
    _construct = Struct('icon_qualifier'/FlagsEnum(Int8ub, not_self_explanatory=1),
                        'icon_identifier'/Int8ub)

# TS 102 223 Section 8.32
class ItemIconIdentifierList(COMPR_TLV_IE, tag=0x9f):
    _construct = Struct('icon_list_qualifier'/FlagsEnum(Int8ub, not_self_explanatory=1),
                        'icon_identifiers'/GreedyRange(Int8ub))

# TS 102 223 Section 8.35
class CApdu(COMPR_TLV_IE, tag=0xA2):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.37
class TimerIdentifier(COMPR_TLV_IE, tag=0xA4):
    _construct = Int8ub

# TS 102 223 Section 8.38
class TimerValue(COMPR_TLV_IE, tag=0xA5):
    _construct = Struct('hour'/Int8ub, 'minute'/Int8ub, 'second'/Int8ub)

# TS 102 223 Section 8.40
class AtCommand(COMPR_TLV_IE, tag=0xA8):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.43
class ImmediateResponse(COMPR_TLV_IE, tag=0xAB):
    pass

# TS 102 223 Section 8.44
class DtmfString(COMPR_TLV_IE, tag=0xAC):
    _construct = BcdAdapter(GreedyBytes)

# TS 102 223 Section 8.45
class Language(COMPR_TLV_IE, tag=0xAD):
    _construct = HexAdapter(GreedyBytes)

# TS 31.111 Section 8.46
class TimingAdvance(COMPR_TLV_IE, tag=0xC6):
    _construct = Struct('me_status'/Enum(Int8ub, in_idle_state=0, not_in_idle_state=1),
                        'timing_advance'/Int8ub)

# TS 31.111 Section 8.47
class BrowserIdentity(COMPR_TLV_IE, tag=0xB0):
    _construct = Enum(Int8ub, default=0, wml=1, html=2, xhtml=3, chtml=4)

# TS 31.111 Section 8.48
class Url(COMPR_TLV_IE, tag=0xB1):
    _construct = GsmString(GreedyBytes)

# TS 31.111 Section 8.49
class Bearer(COMPR_TLV_IE, tag=0xB2):
    SingleBearer = Enum(Int8ub, sms=0, csd=1, ussd=2, packet_Service=3)
    _construct = GreedyRange(SingleBearer)

# TS 102 223 Section 8.50
class ProvisioningFileReference(COMPR_TLV_IE, tag=0xB3):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.51
class BrowserTerminationCause(COMPR_TLV_IE, tag=0xB4):
    _construct = Enum(Int8ub, user_termination=0, error_termination=1)

# TS 102 223 Section 8.52
class BearerDescription(COMPR_TLV_IE, tag=0xB5):
    _test_de_encode = [
        ( 'b50103', {'bearer_parameters': '', 'bearer_type': 'default'} ),
    ]
    # TS 31.111 Section 8.52.1
    BearerParsCs = Struct('data_rate'/Int8ub,
                          'bearer_service'/Int8ub,
                          'connection_element'/Int8ub)
    # TS 31.111 Section 8.52.2
    BearerParsPacket = Struct('precendence_class'/Int8ub,
                              'delay'/Int8ub,
                              'reliability'/Int8ub,
                              'peak_throughput'/Int8ub,
                              'mean_throughput'/Int8ub,
                              'pdp_type'/Enum(Int8ub, ip=0x02, non_ip=0x07))
    # TS 31.111 Section 8.52.3
    BearerParsPacketExt = Struct('traffic_class'/Int8ub,
                                 'max_bitrate_ul'/Int16ub,
                                 'max_bitrate_dl'/Int16ub,
                                 'guaranteed_bitrate_ul'/Int16ub,
                                 'guaranteed_bitrate_dl'/Int16ub,
                                 'delivery_order'/Int8ub,
                                 'max_sdu_size'/Int8ub,
                                 'sdu_err_ratio'/Int8ub,
                                 'residual_ber'/Int8ub,
                                 'delivery_of_erroneous_sdu'/Int8ub,
                                 'transfer_delay'/Int8ub,
                                 'traffic_handling_priority'/Int8ub,
                                 'pdp_type'/Enum(Int8ub, ip=0x02, non_ip=0x07)) # 24.008
    # TODO: TS 31.111 Section 8.52.4 I-WLAN
    # TODO: TS 31.111 Section 8.52.5 E-UTRAN / mapped UTRAN packet service
    # TS 31.111 Section 8.52.6
    BearerParsNgRan = Struct('pdu_session_type'/Int8ub)
    _construct = Struct('bearer_type'/Enum(Int8ub,
                            # TS 31.111 section 8.52
                            csd=1, packet_grps_utran_eutran=2, packet_with_extd_params=9, wlan=0x0a,
                            packet_eutran_mapped_utran=0x0b, ng_ran=0x0c,
                            # TS 102 223 Section 8.52
                            default=3, local_link=4, bluetooth=5, irda=6, rs232=7, cdma2000=8,
                            usb=10),
                        'bearer_parameters'/Switch(this.bearer_type,{
                                                        'csd': BearerParsCs,
                                                        'packet_grps_utran_eutran': BearerParsPacket,
                                                        'packet_with_extd_params': BearerParsPacketExt,
                                                        'ng_ran': BearerParsNgRan,
                                                    }, default=HexAdapter(GreedyBytes)))

# TS 102 223 Section 8.53
class ChannelData(COMPR_TLV_IE, tag = 0xB6):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.54
class ChannelDataLength(COMPR_TLV_IE, tag = 0xB7):
    _construct = Int8ub

# TS 102 223 Section 8.55
class BufferSize(COMPR_TLV_IE, tag = 0xB9):
    _construct = Int16ub

# TS 102 223 Section 8.56 + TS 31.111 Section 8.56
class ChannelStatus(COMPR_TLV_IE, tag = 0xB8):
    # complex decoding, depends on out-of-band context/knowledge :(
    # for default / TCP Client mode: bit 8 of first byte indicates connected, 3 LSB indicate channel nr
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.58
class OtherAddress(COMPR_TLV_IE, tag = 0xBE):
    _test_de_encode = [
        ( 'be052101020304', {'address': '01020304', 'type_of_address': 'ipv4'} ),
    ]
    _construct = Struct('type_of_address'/Enum(Int8ub, ipv4=0x21, ipv6=0x57),
                        'address'/HexAdapter(GreedyBytes))

# TS 102 223 Section 8.59
class UiccTransportLevel(COMPR_TLV_IE, tag = 0xBC):
    _test_de_encode = [
        ( 'bc03028000', {'port_number': 32768, 'protocol_type': 'tcp_uicc_client_remote'} ),
    ]
    _construct = Struct('protocol_type'/Enum(Int8ub, udp_uicc_client_remote=1, tcp_uicc_client_remote=2,
                                             tcp_uicc_server=3, udp_uicc_client_local=4,
                                             tcp_uicc_client_local=5, direct_channel=6),
                        'port_number'/Int16ub)

# TS 102 223 Section 8.60
class Aid(COMPR_TLV_IE, tag=0xAF):
    _construct = Struct('aid'/HexAdapter(GreedyBytes))

# TS 102 223 Section 8.61
class AccessTechnology(COMPR_TLV_IE, tag=0xBF):
    SingleAccessTech = Enum(Int8ub, gsm=0, tia_eia_533=1, tia_eia_136_270=2, utran=3, tetra=4,
                                    tia_eia_95_b=5, cdma1000_1x=6, cdma2000_hrpd=7, eutran=8,
                                    ehrpd=9, nr=0x0a)
    _construct = GreedyRange(SingleAccessTech)

# TS 102 223 Section 8.63
class ServiceRecord(COMPR_TLV_IE, tag=0xC1):
    BearerTechId = Enum(Int8ub, technology_independent=0, bluetooth=1, irda=2, rs232=3, usb=4)
    _construct = Struct('local_bearer_technology'/BearerTechId,
                        'service_identifier'/Int8ub,
                        'service_record'/HexAdapter(GreedyBytes))

# TS 102 223 Section 8.64
class DeviceFilter(COMPR_TLV_IE, tag=0xC2):
    _construct = Struct('local_bearer_technology'/ServiceRecord.BearerTechId,
                        'device_filter'/HexAdapter(GreedyBytes))

# TS 102 223 Section 8.65
class ServiceSearchIE(COMPR_TLV_IE, tag=0xC3):
    _construct = Struct('local_bearer_technology'/ServiceRecord.BearerTechId,
                        'service_search'/HexAdapter(GreedyBytes))

# TS 102 223 Section 8.66
class AttributeInformation(COMPR_TLV_IE, tag=0xC4):
    _construct = Struct('local_bearer_technology'/ServiceRecord.BearerTechId,
                        'attribute_information'/HexAdapter(GreedyBytes))


# TS 102 223 Section 8.68
class RemoteEntityAddress(COMPR_TLV_IE, tag=0xC9):
    _construct = Struct('coding_type'/Enum(Int8ub, ieee802_16=0, irda=1),
                        'address'/HexAdapter(GreedyBytes))

# TS 102 223 Section 8.70
class NetworkAccessName(COMPR_TLV_IE, tag=0xC7):
    _test_de_encode = [
        ( 'c704036e6161', '036e6161' ),
    ]
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.72
class TextAttribute(COMPR_TLV_IE, tag=0xD0):
    pass

# TS 31.111 Section 8.72
class PdpContextActivationParams(COMPR_TLV_IE, tag=0xD2):
    pass

# TS 31.111 Section 8.73
class UtranEutranMeasurementQualifier(COMPR_TLV_IE, tag=0xE9):
    _construct = Enum(Int8ub,   utran_intra_freq=0x01,
                                utran_inter_freq=0x02,
                                utran_inter_rat_geran=0x03,
                                utran_inter_rat_eutran=0x04,
                                eutran_intra_freq=0x05,
                                eutran_inter_freq=0x06,
                                eutran_inter_rat_geran=0x07,
                                eutran_inter_rat_utran=0x08,
                                eutran_inter_rat_nr=0x09)

# TS 102 223 Section 8.75
class NetworkSearchMode(COMPR_TLV_IE, tag=0xE5):
    _construct = Enum(Int8ub, manual=0, automatic=1)

# TS 102 223 Section 8.76
class BatteryState(COMPR_TLV_IE, tag=0xE3):
    _construct = Enum(Int8ub, very_low=0, low=1, average=2, good=3, full=5)

# TS 102 223 Section 8.78
class FrameLayout(COMPR_TLV_IE, tag=0xE6):
    _construct = Struct('layout'/Enum(Int8ub, horizontal=1, vertical=2),
                        'relative_sized_frame'/GreedyRange(Int8ub))

class ItemTextAttributeList(COMPR_TLV_IE, tag=0xD1):
    _construct = GreedyRange(Int8ub)

# TS 102 223 Section 8.80
class FrameIdentifier(COMPR_TLV_IE, tag=0xE8):
    _construct = Struct('identifier'/Int8ub)

# TS 102 223 Section 8.82
class MultimediaMessageReference(COMPR_TLV_IE, tag=0xEA):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.83
class MultimediaMessageIdentifier(COMPR_TLV_IE, tag=0xEB):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.85
class MmContentIdentifier(COMPR_TLV_IE, tag=0xEE):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.89
class ActivateDescriptor(COMPR_TLV_IE, tag=0xFB):
    _construct = Struct('target'/Int8ub)

# TS 31.111 Section 8.90
class PlmnWactList(COMPR_TLV_IE, tag=0xF2):
    def _from_bytes(self, do: bytes):
        r = []
        i = 0
        while i < len(do):
            r.append(dec_xplmn_w_act(b2h(do[i:i+5])))
            i += 5
        return r

# TS 102 223 Section 8.92
class ContactlessFunctionalityState(COMPR_TLV_IE, tag=0xD4):
    _construct = Enum(Int8ub, enabled=0, disabled=1)

# TS 31.111 Section 8.91
class RoutingAreaIdentification(COMPR_TLV_IE, tag=0xF3):
    _construct = Struct('mcc_mnc'/PlmnAdapter(Bytes(3)),
                        'lac'/HexAdapter(Bytes(2)),
                        'rac'/Int8ub)

# TS 31.111 Section 8.92
class UpdateAttachRegistrationType(COMPR_TLV_IE, tag=0xF4):
    _construct = Enum(Int8ub,   normal_location_updating_lu=0x00,
                                periodic_updating_lu=0x01,
                                imsi_attach_lu=0x02,
                                gprs_attach=0x03,
                                combined_gprs_imsi_attach=0x04,
                                ra_updating_rau=0x05,
                                combined_ra_la_updting_rau=0x06,
                                combined_ra_la_updting_with_imsi_attach_rau=0x07,
                                periodic_updating_rau=0x08,
                                eps_attach_emm=0x09,
                                combined_eps_imsi_attach_emm=0x0a,
                                ta_updating_tau=0x0b,
                                combined_ta_la_updating_tau=0x0c,
                                combined_ta_la_updating_with_imsi_attach_tau=0x0d,
                                periodic_updating_tau=0x0e,
                                initial_registration_5grr=0x0f,
                                mobility_registration_updating_5grr=0x10,
                                periodic_registration_updating_5grr=0x11)

# TS 31.111 Section 8.93
class RejectionCauseCode(COMPR_TLV_IE, tag=0xF5):
    _construct = Int8ub

# TS 31.111 Section 8.94
class GeographicalLocationParameters(COMPR_TLV_IE, tag=0xF6):
    _construct = Struct('horizontal_accuracy'/Int8ub,
                        'vertical_coordinate'/Int8ub,
                        'velocity'/FlagsEnum(Int8ub, horizontal_requested=0, vertical_requested=1,
                                             horizontal_uncertainty_requested=2,
                                             vertical_uncertainty_requested=4),
                        'preferred_gad_shapes'/FlagsEnum(Int8ub, ellipsoid_point=0,
                                                         ellipsoid_point_with_uncertainty_circle=1,
                                                         ellipsoid_point_with_uncertainty_ellipse=2,
                                                         ellipsoid_point_with_altitude=3,
                                                         polygon=4,
                                                         ellipsoid_point_with_altitude_and_uncertainty_ellipsoid=5,
                                                         ellipsoid_arc=6),
                        'preferred_nmea_sentences'/FlagsEnum(Int8ub, rmc=0, gga=1, gll=2, gns=3),
                        'preferred_maximum_response_time'/Int8ub)

# TS 31.111 Section 8.97
class PlmnList(COMPR_TLV_IE, tag=0xF9):
    _construct = GreedyRange('mcc_mnc'/PlmnAdapter(Bytes(3)))

# TS 102 223 Section 8.98
class EcatSequenceNumber(COMPR_TLV_IE, tag=0xA1):
    CmdTypeIndicator = Enum(BitsInteger(2), command_container=0,
                                            terminal_response=1,
                                            envelope_profile_container_event=2,
                                            envelope_profile_container_response=3)
    _construct = BitStruct('command_type_indicator'/CmdTypeIndicator,
                           'counter'/BitsInteger(22))

# TS 102 223 Section 8.99
class EncryptedTlvList(COMPR_TLV_IE, tag=0xA2):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.100
class Mac(COMPR_TLV_IE, tag=0xE0):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.101
class SaTemplate(COMPR_TLV_IE, tag=0xA3):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.103
class RefreshEnforcementPolicy(COMPR_TLV_IE, tag=0xBA):
    _construct = FlagsEnum(Byte, even_if_navigating_menus=0, even_if_data_call=1, even_if_voice_call=2)

# TS 102 223 Section 8.104
class DnsServerAddress(COMPR_TLV_IE, tag=0xC0):
    _construct = HexAdapter(GreedyBytes)

# TS 102 223 Section 8.105
class SupportedRadioAccessTechnologies(COMPR_TLV_IE, tag=0xB4):
    AccessTechTuple = Struct('technology'/AccessTechnology.SingleAccessTech,
                             'state'/FlagsEnum(Int8ub, enabled=0))
    _construct = GreedyRange(AccessTechTuple)

# TS 102 223 Section 8.107
class ApplicationSpecificRefreshData(COMPR_TLV_IE, tag=0xBB):
    pass

# TS 31.111 Section 8.108
class ImsUri(COMPR_TLV_IE, tag=0xB1):
    pass

# TS 31.111 Section 8.132
class MediaType(COMPR_TLV_IE, tag=0xFE):
    _construct = FlagsEnum(Int8ub, voice=0, video=1)

# TS 31.111 Section 8.137
class DataConnectionStatus(COMPR_TLV_IE, tag=0x9D):
    _construct = Enum(Int8ub, successful=0, rejected=1, dropped_or_deactivated=2)

# TS 31.111 Section 8.138
class DataConnectionType(COMPR_TLV_IE, tag=0xAA):
    _construct = Enum(Int8ub, pdp=0, pdn=1, pdu=2)

# TS 31.111 Section 8.139
class SmCause(COMPR_TLV_IE, tag=0xAE):
    _construct = Int8ub


# TS 101 220 Table 7.17 + 31.111 7.1.1.2
class SMSPPDownload(BER_TLV_IE, tag=0xD1,
                    nested=[DeviceIdentities, Address, SMS_TPDU]):
    pass

# TS 101 220 Table 7.17 + 31.111 7.1.1.3
class SMSCBDownload(BER_TLV_IE, tag=0xD2,
                    nested=[DeviceIdentities, CBSPage]):
    pass

# TS 101 220 Table 7.17
class MenuSelection(BER_TLV_IE, tag=0xD3,
                    nested=[DeviceIdentities, ItemIdentifier, HelpRequest]):
    pass

class BcRepeatIndicator(BER_TLV_IE, tag=0x2A):
    pass

# TS 101 220 Table 7.17
class CallControl(BER_TLV_IE, tag=0xD4,
                  nested=[DeviceIdentities, Address, CapabilityConfigParams, Subaddress,
                          LocationInformation, BcRepeatIndicator]):
    pass

# TS 101 220 Table 7.17
class MoShortMessageControl(BER_TLV_IE, tag=0xD5):
    pass


# TS 101 220 Table 7.23
class TransactionIdentifier(BER_TLV_IE, tag=0x1C):
    pass

# TS 101 220 Table 7.23
class ImsURI(BER_TLV_IE, tag=0x31):
    pass

# TS 101 220 Table 7.23
class UriTruncated(BER_TLV_IE, tag=0x73):
    pass

# TS 101 220 Table 7.23
class TrackingAreaIdentification(BER_TLV_IE, tag=0x7D):
    pass

# TS 101 220 Table 7.23
class ExtendedRejectionCauseCode(BER_TLV_IE, tag=0x57):
    pass

# TS 101 220 Table 7.23
class CsgCellSelectionStatus(BER_TLV_IE, tag=0x55):
    pass

# TS 101 220 Table 7.23
class CsgId(BER_TLV_IE, tag=0x56):
    pass

# TS 101 220 Table 7.23
class HnbName(BER_TLV_IE, tag=0x57):
    pass

# TS 101 220 Table 7.23
class PlmnId(BER_TLV_IE, tag=0x09):
    pass

# TS 101 220 Table 7.23
class ImsCallDisconnectionStatus(BER_TLV_IE, tag=0x55):
    pass

# TS 101 220 Table 7.23
class Iari(BER_TLV_IE, tag=0x76):
    pass

# TS 101 220 Table 7.23
class ImpuList(BER_TLV_IE, tag=0x77):
    pass

# TS 101 220 Table 7.23
class ImsStatusCode(BER_TLV_IE, tag=0x77):
    pass

# TS 101 220 Table 7.23
class DateTimeAndTimezone(BER_TLV_IE, tag=0x26):
    pass

# TS 101 220 Table 7.23
class PdpPdnPduType(BER_TLV_IE, tag=0x0B):
    pass

# TS 101 220 Table 7.23
class GadShape(BER_TLV_IE, tag=0x77):
    pass

# TS 101 220 Table 7.23
class NmeaSentence(BER_TLV_IE, tag=0x78):
    pass

# TS 101 220 Table 7.23
class WlanAccessStatus(BER_TLV_IE, tag=0x4B):
    pass

# TS 101 220 Table 7.17
class EventDownload(BER_TLV_IE, tag=0xD6,
                    nested=[EventList, DeviceIdentities,
                            # 7.5.1.2 (I-)WLAN Access Status
                            WlanAccessStatus,
                            # 7.5.1A.2 MT Call
                            TransactionIdentifier, Address,
                            Subaddress, ImsURI, MediaType, UriTruncated,
                            # 7.5.2.2 Network Rejection
                            LocationInformation, RoutingAreaIdentification, TrackingAreaIdentification,
                            AccessTechnology, UpdateAttachRegistrationType, RejectionCauseCode,
                            ExtendedRejectionCauseCode,
                            # 7.5.2A.2 Call Connected
                            # TransactionIdentifier, MediaType
                            # 7.5.3.2 CSG Cell Selection
                            # AccessTechnology
                            CsgCellSelectionStatus, CsgId, HnbName, PlmnId,
                            # 7.5.3A.2 CAll Disconnected
                            # TransactionIdentifier, MediaType,
                            ImsCallDisconnectionStatus,
                            # TS 102 223 7.5.4 LocationStatusEvent
                            # TS 102 223 7.5.5 UserActivityEvent
                            # TS 102 223 7.5.6 IdleScreenAvailableEvent
                            # TS 102 223 7.5.7 CardReaderStatusEvent
                            # TS 102 223 7.5.8 LanguageSelectionEvent
                            # TS 102 223 7.5.9 BrowserTerminationEvent
                            # TS 102 223 7.5.10 DataAvailableEvent
                            ChannelStatus, ChannelDataLength,
                            # TS 102 223 7.5.11 ChannelStatusEvent
                            # TS 102 223 7.5.12 AccessTechnologyChangeEvent
                            # TS 102 223 7.5.13 DisplayParametersChangedEvent
                            # TS 102 223 7.5.14 LocalConnectionEvent
                            # TS 102 223 7.5.15 NetworkSearchModeChangeEvent
                            # TS 102 223 7.5.16 BrowsingStatusEvent
                            # TS 102 223 7.5.17 FramesInformationChangedEvent
                            # 7.5.20 Incoming IMS Data
                            Iari,
                            # 7.5.21 MS Registration Event
                            ImpuList, ImsStatusCode,
                            # 7.5.24 / TS 102 223 7.5.22 PollIntervalNegotiation
                            # 7.5.25 DataConnectionStatusChangeEvent
                            DataConnectionStatus, DataConnectionType, SmCause,
                            # TransactionIdentifier, LocationInformation, AccessTechnology
                            DateTimeAndTimezone, LocationStatus, NetworkAccessName, PdpPdnPduType,
                            # 7.7 / TS 102 223 7.6 MMS Transfer Status
                            # 7.8 / TS 102 223 MMS Notification Download
                            # 7.9 / TS 102 223 8.8 Terminal Applications
                    ]):
    pass

# TS 101 220 Table 7.17
class TimerExpiration(BER_TLV_IE, tag=0xD7):
    pass

# TS 101 220 Table 7.17 + TS 31.111 7.6.2
class USSDDownload(BER_TLV_IE, tag=0xD9,
                   nested=[DeviceIdentities, USSDString]):
    pass

# TS 101 220 Table 7.17 + TS 102 223 7.6
class MmsTransferStatus(BER_TLV_IE, tag=0xDA):
    pass

# TS 101 220 Table 7.17 + 102 223
class MmsNotificationDownload(BER_TLV_IE, tag=0xDB):
    pass

# TS 101 220 Table 7.17 + 102 223 7.8
class TerminalApplication(BER_TLV_IE, tag=0xDC):
    pass

# TS 101 220 Table 7.17 + TS 31.111 7.10.2
class GeographicalLocation(BER_TLV_IE, tag=0xDD,
                           nested=[DeviceIdentities, GadShape, NmeaSentence]):
    pass

# TS 101 220 Table 7.17
class EnvelopeContainer(BER_TLV_IE, tag=0xDE):
    pass

# TS 101 220 Table 7.17
class ProSeReport(BER_TLV_IE, tag=0xDF):
    pass

# TS 101 220 Table 7.17
class ProactiveCmd(BER_TLV_IE):
    def _compute_tag(self) -> int:
        return 0xD0


class EventCollection(TLV_IE_Collection,
                      nested=[SMSPPDownload, SMSCBDownload,
                              EventDownload, CallControl, MoShortMessageControl,
                              USSDDownload, GeographicalLocation, ProSeReport]):
    pass


# TS 101 220 Table 7.17 + 102 223 6.6.13/9.4 + TS 31.111 6.6.13
class Refresh(ProactiveCmd, tag=0x01,
              nested=[CommandDetails, DeviceIdentities, FileList, Aid, AlphaIdentifier,
                      IconIdentifier, TextAttribute, FrameIdentifier, RefreshEnforcementPolicy,
                      ApplicationSpecificRefreshData, PlmnWactList, PlmnList]):
    pass

# TS 102 223 Section 6.6.4
class MoreTime(ProactiveCmd, tag=0x02,
        nested=[CommandDetails, DeviceIdentities]):
    pass

# TS 102 223 Section 6.6.5
class PollInterval(ProactiveCmd, tag=0x03,
        nested=[CommandDetails, DeviceIdentities, Duration]):
    pass

# TS 102 223 Section 6.6.14
class PollingOff(ProactiveCmd, tag=0x04,
        nested=[CommandDetails, DeviceIdentities]):
    pass

# TS 102 223 Section 6.6.16
class SetUpEventList(ProactiveCmd, tag=0x05,
        nested=[CommandDetails, DeviceIdentities, EventList]):
    pass

# TS 31.111 Section 6.6.12
class SetUpCall(ProactiveCmd, tag=0x10,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, Address, ImsUri,
                CapabilityConfigParams, Subaddress, Duration, IconIdentifier, AlphaIdentifier,
                TextAttribute, FrameIdentifier, MediaType]):
    pass

# TS 31.111 Section 6.6.10
class SendSS(ProactiveCmd, tag=0x11,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, SsString, IconIdentifier,
                TextAttribute, FrameIdentifier]):
    pass

# TS 31.111 Section 6.6.11
class SendUSSD(ProactiveCmd, tag=0x12,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, USSDString, IconIdentifier,
                TextAttribute, FrameIdentifier]):
    pass

# TS 101 220 Table 7.17 + 102 223 6.6.9/9.4 + TS 31.111 Section 6.6.9
class SendShortMessage(ProactiveCmd, tag=0x13,
                       nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, Address,
                               SMS_TPDU, IconIdentifier, TextAttribute, FrameIdentifier]):
    pass

# TS 102 223 6.6.24
class SendDTMF(ProactiveCmd, tag=0x14,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier,
                DtmfString, IconIdentifier, TextAttribute, FrameIdentifier]):
    pass

# TS 102 223 6.6.26
class LaunchBrowser(ProactiveCmd, tag=0x15,
        nested=[CommandDetails, DeviceIdentities, BrowserIdentity, Url, Bearer, ProvisioningFileReference,
                TextString, AlphaIdentifier, IconIdentifier, TextAttribute, FrameIdentifier,
                NetworkAccessName]):
    pass

class GeographicalLocationRequest(ProactiveCmd, tag=0x16,
        nested=[CommandDetails]):
    pass

# TS 102 223 6.6.5
class PlayTone(ProactiveCmd, tag=0x20,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier,
                Tone, Duration, IconIdentifier, TextAttribute, FrameIdentifier]):
    pass

# TS 101 220 Table 7.17 + 102 223 6.6.1/9.4 CMD=0x21
class DisplayText(ProactiveCmd, tag=0x21,
                  nested=[CommandDetails, DeviceIdentities, TextString, IconIdentifier,
                          ImmediateResponse, Duration, TextAttribute, FrameIdentifier]):
    pass

# TS 102 223 6.6.2
class GetInkey(ProactiveCmd, tag=0x22,
        nested=[CommandDetails, DeviceIdentities, TextString, IconIdentifier, Duration,
                TextAttribute, FrameIdentifier]):
    pass

# TS 102 223 6.6.3
class GetInput(ProactiveCmd, tag=0x23,
        nested=[CommandDetails, DeviceIdentities, TextString, ResponseLength, DefaultText,
                IconIdentifier, TextAttribute, FrameIdentifier, Duration]):
    pass

# TS 102 223 6.6.8
class SelectItem(ProactiveCmd, tag=0x24,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, #
                ItemsNextActionIndicator, ItemIdentifier, IconIdentifier, ItemIconIdentifierList,
                TextAttribute, ItemTextAttributeList, FrameIdentifier]):
    pass

# TS 102 223 6.6.7
class SetUpMenu(ProactiveCmd, tag=0x25,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, #
                ItemsNextActionIndicator, IconIdentifier, ItemIconIdentifierList,
                TextAttribute, ItemTextAttributeList]):
    pass

# TS 102 223 6.6.15
class ProvideLocalInformation(ProactiveCmd, tag=0x26,
        nested=[CommandDetails, DeviceIdentities]):
    pass

# TS 102 223 6.6.21
class TimerManagement(ProactiveCmd, tag=0x27,
        nested=[CommandDetails, DeviceIdentities, TimerIdentifier, TimerValue]):
    pass

# TS 102 223 6.6.22
class SetUpIdleModeText(ProactiveCmd, tag=0x28,
        nested=[CommandDetails, DeviceIdentities, TextString, IconIdentifier, TextAttribute,
                FrameIdentifier]):
    pass

# TS 102 223 6.6.17
class PerformCardApdu(ProactiveCmd, tag=0x30,
        nested=[CommandDetails, DeviceIdentities, CApdu]):
    pass

# TS 102 223 6.6.19
class PowerOnCard(ProactiveCmd, tag=0x31,
        nested=[CommandDetails, DeviceIdentities]):
    pass

# TS 102 223 6.6.18
class PowerOffCard(ProactiveCmd, tag=0x32,
        nested=[CommandDetails, DeviceIdentities]):
    pass

# TS 102 223 6.6.20
class GetReaderStatus(ProactiveCmd, tag=0x33,
        nested=[CommandDetails, DeviceIdentities]):
    pass

# TS 102 223 6.6.23
class RunAtCommand(ProactiveCmd, tag=0x34,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, AtCommand, IconIdentifier,
                TextAttribute, FrameIdentifier]):
    pass

# TS 102 223 6.6.25
class LanguageNotification(ProactiveCmd, tag=0x35,
        nested=[CommandDetails, DeviceIdentities, Language]):
    pass

# TS 102 223 6.6.27
class OpenChannel(ProactiveCmd, tag=0x40,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, IconIdentifier, Address, Subaddress,
                Duration, BearerDescription, BufferSize, NetworkAccessName, OtherAddress,
                TextString, UiccTransportLevel, RemoteEntityAddress, TextAttribute,
                FrameIdentifier]):
    pass

# TS 102 223 6.6.28
class CloseChannel(ProactiveCmd, tag=0x41,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, IconIdentifier, TextAttribute,
                FrameIdentifier]):
    pass

# TS 102 223 6.6.29
class ReceiveData(ProactiveCmd, tag=0x42,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, IconIdentifier, ChannelDataLength,
                TextAttribute, FrameIdentifier]):
    pass

# TS 102 223 6.6.30
class SendData(ProactiveCmd, tag=0x43,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, IconIdentifier, ChannelData,
                TextAttribute, FrameIdentifier]):
    pass

# TS 102 223 6.6.31
class GetChannelStatus(ProactiveCmd, tag=0x44,
        nested=[CommandDetails, DeviceIdentities]):
    pass

# TS 102 223 6.6.32
class ServiceSearch(ProactiveCmd, tag=0x45,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, IconIdentifier, ServiceSearchIE,
                DeviceFilter, TextAttribute, FrameIdentifier]):
    pass

# TS 102 223 6.6.33
class GetServiceInformation(ProactiveCmd, tag=0x46,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, IconIdentifier, AttributeInformation,
                TextAttribute, FrameIdentifier]):
    pass

# TS 102 223 6.6.34
class DeclareService(ProactiveCmd, tag=0x47,
        nested=[CommandDetails, DeviceIdentities, ServiceRecord, UiccTransportLevel]):
    pass

# TS 102 223 6.6.35
class SetFrames(ProactiveCmd, tag=0x50,
        nested=[CommandDetails, DeviceIdentities, FrameIdentifier, FrameLayout]):
    pass

# TS 102 223 6.6.36
class GetFramesStatus(ProactiveCmd, tag=0x51,
        nested=[CommandDetails, DeviceIdentities]):
    pass

# TS 102 223 6.6.37
class RetrieveMultimediaMessage(ProactiveCmd, tag=0x60,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, MultimediaMessageReference,
                FileList, MmContentIdentifier, MultimediaMessageIdentifier, TextAttribute,
                FrameIdentifier]):
    pass

# TS 102 223 6.6.38
class SubmitMultimediaMessage(ProactiveCmd, tag=0x61,
        nested=[CommandDetails, DeviceIdentities, AlphaIdentifier, IconIdentifier, FileList,
                MultimediaMessageIdentifier, TextAttribute, FrameIdentifier]):
    pass

# TS 102 223 6.6.39
class DisplayMultimediaMessage(ProactiveCmd, tag=0x62,
        nested=[CommandDetails, DeviceIdentities, FileList, MultimediaMessageIdentifier,
                ImmediateResponse, FrameIdentifier]):
    pass

# TS 102 223 6.6.40
class Activate(ProactiveCmd, tag=0x70,
        nested=[CommandDetails, DeviceIdentities, ActivateDescriptor]):
    pass

# TS 102 223 6.6.41
class ContactlessStateChanged(ProactiveCmd, tag=0x71,
        nested=[CommandDetails, DeviceIdentities, ContactlessFunctionalityState]):
    pass

# TS 102 223 6.6.42
class CommandContainer(ProactiveCmd, tag=0x72,
        nested=[CommandDetails, DeviceIdentities, EcatSequenceNumber, Mac, EncryptedTlvList]):
    pass

# TS 102 223 6.6.43
class EncapsulatedSessionControl(ProactiveCmd, tag=0x73,
        nested=[CommandDetails, DeviceIdentities, SaTemplate]):
    pass



# TS 101 220 Table 7.17: FIXME: Merge all nested?
class ProactiveCommandBase(BER_TLV_IE, tag=0xD0, nested=[CommandDetails]):
    def find_cmd_details(self):
        for c in self.children:
            if type(c).__name__ == 'CommandDetails':
                return c
            else:
                return None

class ProactiveCommand(TLV_IE_Collection,
                       nested=[Refresh, MoreTime, PollInterval, PollingOff, SetUpEventList, SetUpCall,
                               SendSS, SendUSSD, SendShortMessage, SendDTMF, LaunchBrowser,
                               GeographicalLocationRequest, PlayTone, DisplayText, GetInkey, GetInput,
                               SelectItem, SetUpMenu, ProvideLocalInformation, TimerManagement,
                               SetUpIdleModeText, PerformCardApdu, PowerOnCard, PowerOffCard,
                               GetReaderStatus, RunAtCommand, LanguageNotification, OpenChannel,
                               CloseChannel, ReceiveData, SendData, GetChannelStatus, ServiceSearch,
                               GetServiceInformation, DeclareService, SetFrames, GetFramesStatus,
                               RetrieveMultimediaMessage, SubmitMultimediaMessage, DisplayMultimediaMessage,
                               Activate, ContactlessStateChanged, CommandContainer,
                               EncapsulatedSessionControl]):
    """Class representing a CAT proactive command, as (for example) sent via a FETCH response. Parsing this is
    more difficult than any normal TLV IE Collection, because the content of one of the IEs defines the
    definitions of all the other IEs.  So we first need to find the CommandDetails, and then parse according
    to the command type indicated in that IE data."""
    def from_bytes(self, binary: bytes, context: dict = {}) -> List[TLV_IE]:
        # do a first parse step to get the CommandDetails
        pcmd = ProactiveCommandBase()
        pcmd.from_tlv(binary)
        cmd_details = pcmd.find_cmd_details()
        # then do a second decode stage for the specific
        cmd_type = TypeOfCommand.encmapping[cmd_details.decoded['type_of_command']]
        if cmd_type in self.members_by_tag:
            cls = self.members_by_tag[cmd_type]
            inst = cls()
            _dec, remainder = inst.from_tlv(binary)
            self.decoded = inst
        else:
            self.decoded = pcmd
        return self.decoded

    #def from_dict(self, decoded):
    #    pass

    def to_dict(self):
        return self.decoded.to_dict()

    def to_bytes(self, context: dict = {}):
        return self.decoded.to_tlv()

# TS 101 223 Section 6.8.0
class TerminalResponse(TLV_IE_Collection,
                       nested=[CommandDetails, DeviceIdentities, Result,
                               Duration, TextString, ItemIdentifier,
                               #TODO: LocalInformation and other optional/conditional IEs
                               ChannelData, ChannelDataLength,
                               ChannelStatus, BufferSize, BearerDescription,
                               ]):
    pass

# reasonable default for playing with OTA
# 010203040506070809101112131415161718192021222324252627282930313233
# '7fe1e10e000000000000001f43000000ff00000000000000000000000000000000'

# TS 102 223 Section 5.2
term_prof_bits = {
    # first byte
    1: 'Profile download',
    2: 'SMS-PP data download',
    3: 'Cell Broadcast data download',
    4: 'Menu selection',
    5: 'SMS-PP data download',
    6: 'Timer expiration',
    7: 'USSD string DO support in CC by USIM',
    8: 'Call Control by NAA',

    # first byte
    9: 'Command result',
    10: 'Call Control by NAA',
    11: 'Call Control by NAA',
    12: 'MO short message control support',
    13: 'Call Control by NAA',
    14: 'UCS2 Entry supported',
    15: 'UCS2 Display supported',
    16: 'Display Text',

    # third byte
    17: 'Proactive UICC: DISPLAY TEXT',
    18: 'Proactive UICC: GET INKEY',
    19: 'Proactive UICC: GET INPUT',
    20: 'Proactive UICC: MORE TIME',
    21: 'Proactive UICC: PLAY TONE',
    22: 'Proactive UICC: POLL INTERVAL',
    23: 'Proactive UICC: POLLING OFF',
    24: 'Proactive UICC: REFRESH',

    # fourth byte
    25: 'Proactive UICC: SELECT ITEM',
    26: 'Proactive UICC: SEND SHORT MESSAGE with 3GPP-SMS-TPDU',
    27: 'Proactive UICC: SEND SS',
    28: 'Proactive UICC: SEND USSD',
    29: 'Proactive UICC: SET UP CALL',
    30: 'Proactive UICC: SET UP MENU',
    31: 'Proactive UICC: PROVIDE LOCAL INFORMATION (MCC, MNC, LAC, Cell ID & IMEI)',
    32: 'Proactive UICC: PROVIDE LOCAL INFORMATION (NMR)',

    # fifth byte
    33: 'Proactive UICC: SET UP EVENT LIST',
    34: 'Event: MT call',
    35: 'Event: Call connected',
    36: 'Event: Call disconnected',
    37: 'Event: Location status',
    38: 'Event: User activity',
    39: 'Event: Idle screen available',
    40: 'Event: Card reader status',

    # sixth byte
    41: 'Event: Language selection',
    42: 'Event: Browser Termination',
    43: 'Event: Data aailable',
    44: 'Event: Channel status',
    45: 'Event: Access Technology Change',
    46: 'Event: Display parameters changed',
    47: 'Event: Local Connection',
    48: 'Event: Network Search Mode Change',

    # seventh byte
    49: 'Proactive UICC: POWER ON CARD',
    50: 'Proactive UICC: POWER OFF CARD',
    51: 'Proactive UICC: PERFORM CARD RESET',
    52: 'Proactive UICC: GET READER STATUS (Card reader status)',
    53: 'Proactive UICC: GET READER STATUS (Card reader identifier)',
    # RFU: 3 bit (54,55,56)

    # eighth byte
    57: 'Proactive UICC: TIMER MANAGEMENT (start, stop)',
    58: 'Proactive UICC: TIMER MANAGEMENT (get current value)',
    59: 'Proactive UICC: PROVIDE LOCAL INFORMATION (date, time and time zone)',
    60: 'GET INKEY',
    61: 'SET UP IDLE MODE TEXT',
    62: 'RUN AT COMMAND',
    63: 'SETUP CALL',
    64: 'Call Control by NAA',

    # ninth byte
    65: 'DISPLAY TEXT',
    66: 'SEND DTMF command',
    67: 'Proactive UICC: PROVIDE LOCAL INFORMATION (NMR)',
    68: 'Proactive UICC: PROVIDE LOCAL INFORMATION (language)',
    69: 'Proactive UICC: PROVIDE LOCAL INFORMATION (Timing Advance)',
    70: 'Proactive UICC: LANGUAGE NOTIFICATION',
    71: 'Proactive UICC: LAUNCH BROWSER',
    72: 'Proactive UICC: PROVIDE LOCAL INFORMATION (Access Technology)',

    # tenth byte
    73: 'Soft keys support for SELECT ITEM',
    74: 'Soft keys support for SET UP MENU ITEM',
    # RFU: 6 bit (75-80)

    # eleventh byte: max number of soft keys as 8bit value (81..88)

    # twelfth byte
    89: 'Proactive UICC: OPEN CHANNEL',
    90: 'Proactive UICC: CLOSE CHANNEL',
    91: 'Proactive UICC: RECEIVE DATA',
    92: 'Proactive UICC: SEND DATA',
    93: 'Proactive UICC: GET CHANNEL STATUS',
    94: 'Proactive UICC: SERVICE SEARCH',
    95: 'Proactive UICC: GET SERVICE INFORMATION',
    96: 'Proactive UICC: DECLARE SERVICE',

    # thirteenth byte
    97: 'BIP supported Bearer: CSD',
    98: 'BIP supported Bearer: GPRS',
    99: 'BIP supported Bearer: Bluetooth',
    100: 'BIP supported Bearer: IrDA',
    101: 'BIP supported Bearer: RS232',
    # 3 bits: number of channels supported (102..104)

    # fourtheenth byte (screen height)
    # fifteenth byte (screen width)
    # sixeenth byte (screen effects)
    # seventeenth byte (BIP supported bearers)
    129: 'BIP: TCP, UICC in client mode, remote connection',
    130: 'BIP: UDP, UICC in client mode, remote connection',
    131: 'BIP: TCP, UICC in server mode',
    132: 'BIP: TCP, UICC in client mode, local connection',
    133: 'BIP: UDP, UICC in client mode, local connection',
    134: 'BIP: direct communication channel',
    # 2 bits reserved: 135, 136

    # FIXME: remainder
}
