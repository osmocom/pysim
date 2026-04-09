#!/usr/bin/env python3

# (C) 2026 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Philipp Maier
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

import logging
from pathlib import Path
from pySim.log import PySimLogger
from argparse import Namespace
from pySim.global_platform import GpCardKeyset, SCP02, ADF_SD
from Cryptodome.Random import get_random_bytes
from osmocom.utils import h2b, b2h
from rcp_module_utils import rcpm_setup_argparse, rcpm_run_module, RcpModule, RcpModuleHdlr

log = PySimLogger.get(Path(__file__).stem)
option_parser = rcpm_setup_argparse("Example Module")

class ExmpleModule(RcpModule):

    def __init__(self, *args, **kwargs):
        log.info("rcpm_run_module was called with the following additional arguments:")
        log.info("%s, %s", str(args), str(kwargs))

    name = 'rcp_module'
    cmd_descr = [{'name' : 'reset',
                  'help': 'reset the card',
                  'args' : []},
                 {'name' : 'read_binary',
                  'help': 'read binary data from a transparent file.',
                  'args' : [{ 'name' : '--fid',
                               'spec' : {'required' : True,
                                         'help' : 'File identifier to of the file to read',
                                         'action' : 'append',
                                         'pytype' : 'str'},
                             }
                            ]},
                 {'name' : 'read_record',
                  'help': 'read binary data from a transparent file.',
                  'args' : [{ 'name' : '--fid',
                               'spec' : {'required' : True,
                                         'help' : 'File identifier to of the file to read',
                                         'action' : 'append',
                                         'pytype' : 'str'},
                             },
                            { 'name' : '--record',
                               'spec' : {'required' : True,
                                         'help' : 'File record to read',
                                         'default' : 1,
                                         'pytype' : 'int'},
                              }
                            ]},
                 {'name' : 'unlock_aram',
                  'help': 'unlock a locked ARA-M applet on a sysmoISIM-SJA5',
                  'args' : [],
                  'get_keys' : {'uicc' : ['KIC', 'KID', 'KIK']}}
                 ]
    suitable_for = [{'atr' : '3b9f96801f878031e073fe211b674a357530350265f8'}]

    def cmd_reset(self, hdlr: RcpModuleHdlr) -> int:
        hdlr.print("resetting UICC/eUICC ...")
        hdlr.card._scc.reset_card()
        hdlr.print("ATR is: %s" % hdlr.card._scc.get_atr())
        return 0

    def cmd_read_binary(self, hdlr: RcpModuleHdlr) -> int:
        fid = hdlr.cmd_args.fid
        hdlr.print("reading transparent file: %s ..." % fid)
        (res, _) = hdlr.card._scc.read_binary(fid)
        hdlr.print("file content is: %s" % res)
        return 0

    def cmd_read_record(self, hdlr: RcpModuleHdlr) -> int:
        fid = hdlr.cmd_args.fid
        record = hdlr.cmd_args.record
        hdlr.print("reading linear-fixed file: %s ..." % fid)
        (res, _) = hdlr.card._scc.read_record(fid, record)
        hdlr.print("file content is: %s" % res)
        return 0

    def cmd_unlock_aram(self, hdlr: RcpModuleHdlr) -> int:
        # Select ADF.ISD
        hdlr.print("Selecting ADF.ISD ...")
        hdlr.lchan.scc.send_apdu_checksw("00a4040408a00000000300000000")

        # Establish secure channel
        hdlr.print("Establishing secure channel ...")
        key_ver = 112
        key_enc = hdlr.keys_uicc['KIC']
        key_mac = hdlr.keys_uicc['KID']
        key_dek = hdlr.keys_uicc['KIK']
        security_level = 3
        host_challenge_len = 8
        host_challenge = get_random_bytes(host_challenge_len)
        kset = GpCardKeyset(key_ver, h2b(key_enc), h2b(key_mac), h2b(key_dek))
        scp = SCP02(card_keys=kset)
        ADF_SD.establish_scp(hdlr.lchan.scc, scp, host_challenge, security_level)

        # To prove that it works, we need to do something that actually requires to be authenticated
        # via a secure channel. In this example we will send an unlock command to the ARA-M applet
        # found on any sysmoISIM-SJA5 card. (see also: https://gitea.osmocom.org/sim-card/aram-applet)
        hdlr.print("Unlocking ARA-M applet ...")
        ara_m_aid = "a00000015141434c00"
        ADF_SD.install(hdlr.lchan.scc, 0x20, 0x00, "0000%02x%s000000" % (len(ara_m_aid) // 2, ara_m_aid))
        ADF_SD.store_data(hdlr.lchan.scc, h2b("A2"), structure = 'ber_tlv')

        # Release the secure channel
        hdlr.print("Done, releasing secure channel ...")
        ADF_SD.release_scp(hdlr.lchan.scc)
        return 0

if __name__ == '__main__':
    opts = option_parser.parse_args()
    rcpm_run_module(opts, ExmpleModule,
                    "arg1", "arg2", "arg3",
                    kwarg1="kwarg1", kwarg2="kwarg2", kwarg3="kwarg3")
