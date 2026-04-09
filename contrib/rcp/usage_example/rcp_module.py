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
from rcp_module_utils import rcpm_setup_argparse, rcpm_run_module, RcpModule, RcpmCmdSrvConnHdlr

log = PySimLogger.get(Path(__file__).stem)

class ExmpleModule(RcpModule):

    name = Path(__file__).stem
    cmd_descr = [{"name" : "reset",
                  "help": "reset the card",
                  "args" : []},
                 {"name" : "read_binary",
                  "help": "read binary data from a transparent file.",
                  "args" : [{ "name" : "--fid",
                               "spec" : {"required" : True,
                                         "help" : "File identifier to of the file to read",
                                         "action" : "append",
                                         "pytype" : "str"},
                             }
                            ]},
                 {"name" : "read_record",
                  "help": "read binary data from a transparent file.",
                  "args" : [{ "name" : "--fid",
                               "spec" : {"required" : True,
                                         "help" : "File identifier to of the file to read",
                                         "action" : "append",
                                         "pytype" : "str"},
                             },
                            { "name" : "--record",
                               "spec" : {"required" : True,
                                         "help" : "File record to read",
                                         "default" : 1,
                                         "pytype" : "int"},
                              }
                            ]}
                 ]
    suitable_for = [{"atr" : "3b9f96803f87828031e073fe211f574543753130136502"}]

    def cmd_reset(self, hdlr: RcpmCmdSrvConnHdlr) -> int:
        hdlr.print("resetting UICC/eUICC")
        hdlr.scc.reset_card()
        hdlr.print("ATR is: %s" % hdlr.scc.get_atr())
        return 0

    def cmd_read_binary(self, hdlr: RcpmCmdSrvConnHdlr) -> int:
        fid = hdlr.cmd_args.fid
        hdlr.print("reading transparent file: %s" % fid)
        (res, _) = hdlr.scc.read_binary(fid)
        hdlr.print("file content is: %s" % res)
        return 0

    def cmd_read_record(self, hdlr: RcpmCmdSrvConnHdlr) -> int:
        fid = hdlr.cmd_args.fid
        record = hdlr.cmd_args.record
        hdlr.print("reading linear-fixed file: %s" % fid)
        (res, _) = hdlr.scc.read_record(fid, record)
        hdlr.print("file content is: %s" % res)
        return 0

if __name__ == '__main__':
    option_parser = rcpm_setup_argparse("Example Module")
    opts = option_parser.parse_args()
    rcpm_run_module(opts, ExmpleModule)
