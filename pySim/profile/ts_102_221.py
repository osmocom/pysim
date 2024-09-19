# coding=utf-8
"""Card Profile of ETSI TS 102 221, the core UICC spec.

(C) 2021-2024 by Harald Welte <laforge@osmocom.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from construct import Struct, FlagsEnum, GreedyString

from osmocom.construct import *
from osmocom.utils import *
from osmocom.tlv import BER_TLV_IE

from pySim.utils import *
from pySim.filesystem import *
from pySim.profile import CardProfile
from pySim import iso7816_4
from pySim.ts_102_221 import decode_select_response, ts_102_22x_cmdset
from pySim.ts_102_221 import AM_DO_EF, SC_DO, AdditionalInterfacesSupport, AdditionalTermCapEuicc
from pySim.ts_102_221 import TerminalPowerSupply, ExtendedLchanTerminalSupport, TerminalCapability

# A UICC will usually also support 2G functionality. If this is the case, we
# need to add DF_GSM and DF_TELECOM along with the UICC related files
from pySim.profile.ts_51_011 import AddonSIM, EF_ICCID, EF_PL
from pySim.profile.gsm_r import AddonGSMR
from pySim.profile.cdma_ruim import AddonRUIM


# TS 102 221 Section 13.1
class EF_DIR(LinFixedEF):
    _test_de_encode = [
        ( '61294f10a0000000871002ffffffff890709000050055553696d31730ea00c80011781025f608203454150',
          { "application_template": [ { "application_id": h2b("a0000000871002ffffffff8907090000") },
                                      { "application_label": "USim1" },
                                      { "discretionary_template": h2b("a00c80011781025f608203454150") } ] }
        ),
        ( '61194f10a0000000871004ffffffff890709000050054953696d31',
          { "application_template": [ { "application_id": h2b("a0000000871004ffffffff8907090000") },
                                      { "application_label": "ISim1" } ] }
        ),
    ]
    class ApplicationLabel(BER_TLV_IE, tag=0x50):
        # TODO: UCS-2 coding option as per Annex A of TS 102 221
        _construct = GreedyString('ascii')

    # see https://github.com/PyCQA/pylint/issues/5794
    #pylint: disable=undefined-variable
    class ApplicationTemplate(BER_TLV_IE, tag=0x61,
                              nested=[iso7816_4.ApplicationId, ApplicationLabel, iso7816_4.FileReference,
                                      iso7816_4.CommandApdu, iso7816_4.DiscretionaryData,
                                      iso7816_4.DiscretionaryTemplate, iso7816_4.URL,
                                      iso7816_4.ApplicationRelatedDOSet]):
        pass

    def __init__(self, fid='2f00', sfid=0x1e, name='EF.DIR', desc='Application Directory'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=(5, 54))
        self._tlv = EF_DIR.ApplicationTemplate


# TS 102 221 Section 13.4
class EF_ARR(LinFixedEF):
    _test_de_encode = [
        ( '800101a40683010a950108800106900080016097008401d4a40683010a950108',
         [ [ { "access_mode": [ "read_search_compare" ] },
             { "control_reference_template": "ADM1" } ],
           [ { "access_mode": [ "write_append", "update_erase" ] },
             { "always": None } ],
           [ { "access_mode": [ "delete_file", "terminate_ef" ] },
             { "never": None } ],
           [ { "command_header": { "INS": 212 } },
             { "control_reference_template": "ADM1" } ]
         ] ),
        ( '80010190008001029700800118a40683010a9501088401d4a40683010a950108',
         [ [ { "access_mode": [ "read_search_compare" ] },
             { "always": None } ],
           [ { "access_mode": [ "update_erase" ] },
             { "never": None } ],
           [ { "access_mode": [ "activate_file_or_record", "deactivate_file_or_record" ] },
             { "control_reference_template": "ADM1" } ],
           [ { "command_header": { "INS": 212 } },
             { "control_reference_template": "ADM1" } ]
         ] ),
    ]
    def __init__(self, fid='2f06', sfid=0x06, name='EF.ARR', desc='Access Rule Reference'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc)
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [self.AddlShellCommands()]

    @staticmethod
    def flatten(inp: list):
        """Flatten the somewhat deep/complex/nested data returned from decoder."""
        def sc_abbreviate(sc):
            if 'always' in sc:
                return 'always'
            elif 'never' in sc:
                return 'never'
            elif 'control_reference_template' in sc:
                return sc['control_reference_template']
            else:
                return sc

        by_mode = {}
        for t in inp:
            am = t[0]
            sc = t[1]
            sc_abbr = sc_abbreviate(sc)
            if 'access_mode' in am:
                for m in am['access_mode']:
                    by_mode[m] = sc_abbr
            elif 'command_header' in am:
                ins = am['command_header']['INS']
                if 'CLA' in am['command_header']:
                    cla = am['command_header']['CLA']
                else:
                    cla = None
                cmd = ts_102_22x_cmdset.lookup(ins, cla)
                if cmd:
                    name = cmd.name.lower().replace(' ', '_')
                    by_mode[name] = sc_abbr
                else:
                    raise ValueError
            else:
                raise ValueError
        return by_mode

    def _decode_record_bin(self, raw_bin_data, **kwargs):
        # we can only guess if we should decode for EF or DF here :(
        arr_seq = DataObjectSequence('arr', sequence=[AM_DO_EF, SC_DO])
        dec = arr_seq.decode_multi(raw_bin_data)
        # we cannot pass the result through flatten() here, as we don't have a related
        # 'un-flattening' decoder, and hence would be unable to encode :(
        return dec[0]

    def _encode_record_bin(self, in_json, **kwargs):
        # we can only guess if we should decode for EF or DF here :(
        arr_seq = DataObjectSequence('arr', sequence=[AM_DO_EF, SC_DO])
        return arr_seq.encode_multi(in_json)

    @with_default_category('File-Specific Commands')
    class AddlShellCommands(CommandSet):
        @cmd2.with_argparser(LinFixedEF.ShellCommands.read_rec_dec_parser)
        def do_read_arr_record(self, opts):
            """Read one EF.ARR record in flattened, human-friendly form."""
            (data, _sw) = self._cmd.lchan.read_record_dec(opts.record_nr)
            data = self._cmd.lchan.selected_file.flatten(data)
            self._cmd.poutput_json(data, opts.oneline)

        @cmd2.with_argparser(LinFixedEF.ShellCommands.read_recs_dec_parser)
        def do_read_arr_records(self, opts):
            """Read + decode all EF.ARR records in flattened, human-friendly form."""
            num_of_rec = self._cmd.lchan.selected_file_num_of_rec()
            # collect all results in list so they are rendered as JSON list when printing
            data_list = []
            for recnr in range(1, 1 + num_of_rec):
                (data, _sw) = self._cmd.lchan.read_record_dec(recnr)
                data = self._cmd.lchan.selected_file.flatten(data)
                data_list.append(data)
            self._cmd.poutput_json(data_list, opts.oneline)


# TS 102 221 Section 13.6
class EF_UMPC(TransparentEF):
    _test_de_encode = [
        ( '3cff02', { "max_current_mA": 60, "t_op_s": 255,
                      "addl_info": { "req_inc_idle_current": False, "support_uicc_suspend": True } } ),
        ( '320500', { "max_current_mA": 50, "t_op_s": 5, "addl_info": {"req_inc_idle_current": False,
                                                                       "support_uicc_suspend": False } } ),
    ]
    def __init__(self, fid='2f08', sfid=0x08, name='EF.UMPC', desc='UICC Maximum Power Consumption'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=(5, 5))
        addl_info = FlagsEnum(Byte, req_inc_idle_current=1,
                              support_uicc_suspend=2)
        self._construct = Struct(
            'max_current_mA'/Int8ub, 't_op_s'/Int8ub, 'addl_info'/addl_info)


class CardProfileUICC(CardProfile):

    ORDER = 10

    def __init__(self, name='UICC'):
        files = [
            EF_DIR(),
            EF_ICCID(),
            EF_PL(),
            EF_ARR(),
            # FIXME: DF.CD
            EF_UMPC(),
        ]
        addons = [
            AddonSIM,
            AddonGSMR,
            AddonRUIM,
        ]
        sw = {
            'Normal': {
                '9000': 'Normal ending of the command',
                '91xx': 'Normal ending of the command, with extra information from the proactive UICC containing a command for the terminal',
                '92xx': 'Normal ending of the command, with extra information concerning an ongoing data transfer session',
            },
            'Postponed processing': {
                '9300': 'SIM Application Toolkit is busy. Command cannot be executed at present, further normal commands are allowed',
            },
            'Warnings': {
                '6200': 'No information given, state of non-volatile memory unchanged',
                '6281': 'Part of returned data may be corrupted',
                '6282': 'End of file/record reached before reading Le bytes or unsuccessful search',
                '6283': 'Selected file invalidated/disabled; needs to be activated before use',
                '6284': 'Selected file in termination state',
                '62f1': 'More data available',
                '62f2': 'More data available and proactive command pending',
                '62f3': 'Response data available',
                '63f1': 'More data expected',
                '63f2': 'More data expected and proactive command pending',
                '63cx': 'Command successful but after using an internal update retry routine X times',
            },
            'Execution errors': {
                '6400': 'No information given, state of non-volatile memory unchanged',
                '6500': 'No information given, state of non-volatile memory changed',
                '6581': 'Memory problem',
            },
            'Checking errors': {
                '6700': 'Wrong length',
                '67xx': 'The interpretation of this status word is command dependent',
                '6b00': 'Wrong parameter(s) P1-P2',
                '6d00': 'Instruction code not supported or invalid',
                '6e00': 'Class not supported',
                '6f00': 'Technical problem, no precise diagnosis',
                '6fxx': 'The interpretation of this status word is command dependent',
            },
            'Functions in CLA not supported': {
                '6800': 'No information given',
                '6881': 'Logical channel not supported',
                '6882': 'Secure messaging not supported',
            },
            'Command not allowed': {
                '6900': 'No information given',
                '6981': 'Command incompatible with file structure',
                '6982': 'Security status not satisfied',
                '6983': 'Authentication/PIN method blocked',
                '6984': 'Referenced data invalidated',
                '6985': 'Conditions of use not satisfied',
                '6986': 'Command not allowed (no EF selected)',
                '6989': 'Command not allowed - secure channel - security not satisfied',
            },
            'Wrong parameters': {
                '6a80': 'Incorrect parameters in the data field',
                '6a81': 'Function not supported',
                '6a82': 'File not found',
                '6a83': 'Record not found',
                '6a84': 'Not enough memory space',
                '6a86': 'Incorrect parameters P1 to P2',
                '6a87': 'Lc inconsistent with P1 to P2',
                '6a88': 'Referenced data not found',
            },
            'Application errors': {
                '9850': 'INCREASE cannot be performed, max value reached',
                '9862': 'Authentication error, application specific',
                '9863': 'Security session or association expired',
                '9864': 'Minimum UICC suspension time is too long',
            },
        }

        super().__init__(name, desc='ETSI TS 102 221', cla="00",
                         sel_ctrl="0004", files_in_mf=files, sw=sw,
                         shell_cmdsets = [self.AddlShellCommands()], addons = addons)

    @staticmethod
    def decode_select_response(data_hex: str) -> object:
        """ETSI TS 102 221 Section 11.1.1.3"""
        return decode_select_response(data_hex)

    @classmethod
    def _try_match_card(cls, scc: SimCardCommands) -> None:
        """ Try to access MF via UICC APDUs (3GPP TS 102.221), if this works, the
        card is considered a UICC card."""
        cls._mf_select_test(scc, "00", "0004", ["3f00"])

    @with_default_category('TS 102 221 Specific Commands')
    class AddlShellCommands(CommandSet):
        suspend_uicc_parser = argparse.ArgumentParser()
        suspend_uicc_parser.add_argument('--min-duration-secs', type=int, default=60,
                                         help='Proposed minimum duration of suspension')
        suspend_uicc_parser.add_argument('--max-duration-secs', type=int, default=24*60*60,
                                         help='Proposed maximum duration of suspension')

        # not ISO7816-4 but TS 102 221
        @cmd2.with_argparser(suspend_uicc_parser)
        def do_suspend_uicc(self, opts):
            """Perform the SUSPEND UICC command. Only supported on some UICC (check EF.UMPC)."""
            (duration, token, sw) = self._cmd.card._scc.suspend_uicc(min_len_secs=opts.min_duration_secs,
                                                                     max_len_secs=opts.max_duration_secs)
            self._cmd.poutput(
                'Negotiated Duration: %u secs, Token: %s, SW: %s' % (duration, token, sw))

        resume_uicc_parser = argparse.ArgumentParser()
        resume_uicc_parser.add_argument('TOKEN', type=str, help='Token provided during SUSPEND')

        @cmd2.with_argparser(resume_uicc_parser)
        def do_resume_uicc(self, opts):
            """Perform the REUSME UICC operation. Only supported on some UICC. Also: A power-cycle
            of the card is required between SUSPEND and RESUME, and only very few non-RESUME
            commands are permitted between SUSPEND and RESUME.  See TS 102 221 Section 11.1.22."""
            self._cmd.card._scc.resume_uicc(opts.TOKEN)

        term_cap_parser = argparse.ArgumentParser()
        # power group
        tc_power_grp = term_cap_parser.add_argument_group('Terminal Power Supply')
        tc_power_grp.add_argument('--used-supply-voltage-class', type=str, choices=['a','b','c','d','e'],
                                  help='Actual used Supply voltage class')
        tc_power_grp.add_argument('--maximum-available-power-supply', type=auto_uint8,
                                  help='Maximum available power supply of the terminal')
        tc_power_grp.add_argument('--actual-used-freq-100k', type=auto_uint8,
                                  help='Actual used clock frequency (in units of 100kHz)')
        # no separate groups for those two
        tc_elc_grp = term_cap_parser.add_argument_group('Extended logical channels terminal support')
        tc_elc_grp.add_argument('--extended-logical-channel', action='store_true',
                                help='Extended Logical Channel supported')
        tc_aif_grp = term_cap_parser.add_argument_group('Additional interfaces support')
        tc_aif_grp.add_argument('--uicc-clf', action='store_true',
                                help='Local User Interface in the Device (LUId) supported')
        # eUICC group
        tc_euicc_grp = term_cap_parser.add_argument_group('Additional Terminal capability indications related to eUICC')
        tc_euicc_grp.add_argument('--lui-d', action='store_true',
                                  help='Local User Interface in the Device (LUId) supported')
        tc_euicc_grp.add_argument('--lpd-d', action='store_true',
                                  help='Local Profile Download in the Device (LPDd) supported')
        tc_euicc_grp.add_argument('--lds-d', action='store_true',
                                  help='Local Discovery Service in the Device (LPDd) supported')
        tc_euicc_grp.add_argument('--lui-e-scws', action='store_true',
                                  help='LUIe based on SCWS supported')
        tc_euicc_grp.add_argument('--metadata-update-alerting', action='store_true',
                                  help='Metadata update alerting supported')
        tc_euicc_grp.add_argument('--enterprise-capable-device', action='store_true',
                                  help='Enterprise Capable Device')
        tc_euicc_grp.add_argument('--lui-e-e4e', action='store_true',
                                  help='LUIe using E4E (ENVELOPE tag E4) supported')
        tc_euicc_grp.add_argument('--lpr', action='store_true',
                                  help='LPR (LPA Proxy) supported')

        @cmd2.with_argparser(term_cap_parser)
        def do_terminal_capability(self, opts):
            """Perform the TERMINAL CAPABILITY function. Used to inform the UICC about terminal capability."""
            ps_flags = {}
            addl_if_flags = {}
            euicc_flags = {}

            opts_dict = vars(opts)

            power_items = ['used_supply_voltage_class', 'maximum_available_power_supply', 'actual_used_freq_100k']
            if any(opts_dict[x] for x in power_items):
                if not all(opts_dict[x] for x in power_items):
                    raise argparse.ArgumentTypeError('If any of the Terminal Power Supply group options are used, all must be specified')

            for k, v in opts_dict.items():
                if k in AdditionalInterfacesSupport._construct.flags.keys():
                    addl_if_flags[k] = v
                elif k in AdditionalTermCapEuicc._construct.flags.keys():
                    euicc_flags[k] = v
                elif k in [f.name for f in TerminalPowerSupply._construct.subcons]:
                    if k == 'used_supply_voltage_class' and v:
                        v = {v: True}
                    ps_flags[k] = v

            child_list = []
            if any(x for x in ps_flags.values()):
                child_list.append(TerminalPowerSupply(decoded=ps_flags))

            if opts.extended_logical_channel:
                child_list.append(ExtendedLchanTerminalSupport())
            if any(x for x in addl_if_flags.values()):
                child_list.append(AdditionalInterfacesSupport(decoded=addl_if_flags))
            if any(x for x in euicc_flags.values()):
                child_list.append(AdditionalTermCapEuicc(decoded=euicc_flags))

            print(child_list)
            tc = TerminalCapability(children=child_list)
            self.terminal_capability(b2h(tc.to_tlv()))

        def terminal_capability(self, data:Hexstr):
            cmd_hex = "80AA0000%02x%s" % (len(data)//2, data)
            _rsp_hex, _sw = self._cmd.lchan.scc.send_apdu_checksw(cmd_hex)
