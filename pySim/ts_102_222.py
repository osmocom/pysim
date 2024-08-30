#!/usr/bin/env python3

# Interactive shell for working with SIM / UICC / USIM / ISIM cards
#
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

from typing import List
import argparse
import cmd2
from cmd2 import CommandSet, with_default_category
from osmocom.utils import b2h, auto_uint8, auto_uint16, is_hexstr

from pySim.ts_102_221 import *

@with_default_category('TS 102 222 Administrative Commands')
class Ts102222Commands(CommandSet):
    """Administrative commands for telecommunication applications."""

    delfile_parser = argparse.ArgumentParser()
    delfile_parser.add_argument('--force-delete', action='store_true',
            help='I really want to permanently delete the file. I know pySim cannot re-create it yet!')
    delfile_parser.add_argument('NAME', type=str, help='File name or FID to delete')

    @cmd2.with_argparser(delfile_parser)
    def do_delete_file(self, opts):
        """Delete the specified file. DANGEROUS!  See TS 102 222 Section 6.4.
        This will permanently delete the specified file from the card.
        pySim has no support to re-create files yet, and even if it did, your card may not allow it!"""
        if not opts.force_delete:
            self._cmd.perror("Refusing to permanently delete the file, please read the help text.")
            return
        f = self._cmd.lchan.get_file_for_filename(opts.NAME)
        (_data, _sw) = self._cmd.lchan.scc.delete_file(f.fid)

    def complete_delete_file(self, text, line, begidx, endidx) -> List[str]:
        """Command Line tab completion for DELETE FILE"""
        index_dict = {1: self._cmd.lchan.selected_file.get_selectable_names()}
        return self._cmd.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)

    termdf_parser = argparse.ArgumentParser()
    termdf_parser.add_argument('--force', action='store_true',
            help='I really want to terminate the file. I know I can not recover from it!')
    termdf_parser.add_argument('NAME', type=str, help='File name or FID')

    @cmd2.with_argparser(termdf_parser)
    def do_terminate_df(self, opts):
        """Terminate the specified DF. DANGEROUS!  See TS 102 222 6.7.
        This is a permanent, one-way operation on the card. There is no undo, you can not recover
        a terminated DF.  The only permitted command for a terminated DF is the DLETE FILE command."""
        if not opts.force:
            self._cmd.perror("Refusing to terminate the file, please read the help text.")
            return
        f = self._cmd.lchan.get_file_for_filename(opts.NAME)
        (_data, _sw) = self._cmd.lchan.scc.terminate_df(f.fid)

    def complete_terminate_df(self, text, line, begidx, endidx) -> List[str]:
        """Command Line tab completion for TERMINATE DF"""
        index_dict = {1: self._cmd.lchan.selected_file.get_selectable_names()}
        return self._cmd.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)

    @cmd2.with_argparser(termdf_parser)
    def do_terminate_ef(self, opts):
        """Terminate the specified EF. DANGEROUS!  See TS 102 222 6.8.
        This is a permanent, one-way operation on the card. There is no undo, you can not recover
        a terminated EF.  The only permitted command for a terminated EF is the DLETE FILE command."""
        if not opts.force:
            self._cmd.perror("Refusing to terminate the file, please read the help text.")
            return
        f = self._cmd.lchan.get_file_for_filename(opts.NAME)
        (_data, _sw) = self._cmd.lchan.scc.terminate_ef(f.fid)

    def complete_terminate_ef(self, text, line, begidx, endidx) -> List[str]:
        """Command Line tab completion for TERMINATE EF"""
        index_dict = {1: self._cmd.lchan.selected_file.get_selectable_names()}
        return self._cmd.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)

    tcard_parser = argparse.ArgumentParser()
    tcard_parser.add_argument('--force-terminate-card', action='store_true',
            help='I really want to permanently terminate the card. It will not be usable afterwards!')

    @cmd2.with_argparser(tcard_parser)
    def do_terminate_card_usage(self, opts):
        """Terminate the Card. SUPER DANGEROUS!  See TS 102 222 Section 6.9.
        This will permanently brick the card and can NOT be recovered from!"""
        if not opts.force_terminate_card:
            self._cmd.perror("Refusing to permanently terminate the card, please read the help text.")
            return
        (_data, _sw) = self._cmd.lchan.scc.terminate_card_usage()

    create_parser = argparse.ArgumentParser()
    create_parser._action_groups.pop()
    create_required = create_parser.add_argument_group('required arguments')
    create_optional = create_parser.add_argument_group('optional arguments')
    create_required.add_argument('--ef-arr-file-id', required=True, type=str, help='Referenced Security: File Identifier of EF.ARR')
    create_required.add_argument('--ef-arr-record-nr', required=True, type=auto_uint8, help='Referenced Security: Record Number within EF.ARR')
    create_required.add_argument('--file-size', required=True, type=auto_uint16, help='Size of file in octets')
    create_required.add_argument('--structure', required=True, type=str, choices=['transparent', 'linear_fixed', 'ber_tlv'],
                                 help='Structure of the to-be-created EF')
    create_optional.add_argument('--short-file-id', type=str, help='Short File Identifier as 2-digit hex string')
    create_optional.add_argument('--shareable', action='store_true', help='Should the file be shareable?')
    create_optional.add_argument('--record-length', type=auto_uint16, help='Length of each record in octets')
    create_parser.add_argument('FILE_ID', type=is_hexstr, help='File Identifier as 4-character hex string')

    @cmd2.with_argparser(create_parser)
    def do_create_ef(self, opts):
        """Create a new EF below the currently selected DF.  Requires related privileges."""
        file_descriptor = {
            'file_descriptor_byte': {
                'shareable': opts.shareable,
                'file_type': 'working_ef',
                'structure': opts.structure,
            }
        }
        if opts.structure == 'linear_fixed':
            if not opts.record_length:
                self._cmd.perror("you must specify the --record-length for linear fixed EF")
                return
            file_descriptor['record_len'] = opts.record_length
            file_descriptor['num_of_rec'] = opts.file_size // opts.record_length
            if file_descriptor['num_of_rec'] * file_descriptor['record_len'] != opts.file_size:
                raise ValueError("File size not evenly divisible by record length")
        elif opts.structure == 'ber_tlv':
            self._cmd.perror("BER-TLV creation not yet fully supported, sorry")
            return
        ies = [FileDescriptor(decoded=file_descriptor), FileIdentifier(decoded=opts.FILE_ID),
               LifeCycleStatusInteger(decoded='operational_activated'),
               SecurityAttribReferenced(decoded={'ef_arr_file_id': opts.ef_arr_file_id,
                                                 'ef_arr_record_nr': opts.ef_arr_record_nr }),
               FileSize(decoded=opts.file_size),
               ShortFileIdentifier(decoded=opts.short_file_id),
            ]
        fcp = FcpTemplate(children=ies)
        (_data, _sw) = self._cmd.lchan.scc.create_file(b2h(fcp.to_tlv()))
        # the newly-created file is automatically selected but our runtime state knows nothing of it
        self._cmd.lchan.select_file(self._cmd.lchan.selected_file)

    createdf_parser = argparse.ArgumentParser()
    createdf_parser._action_groups.pop()
    createdf_required = createdf_parser.add_argument_group('required arguments')
    createdf_optional = createdf_parser.add_argument_group('optional arguments')
    createdf_sja_optional = createdf_parser.add_argument_group('sysmoISIM-SJA optional arguments')
    createdf_required.add_argument('--ef-arr-file-id', required=True, type=str, help='Referenced Security: File Identifier of EF.ARR')
    createdf_required.add_argument('--ef-arr-record-nr', required=True, type=auto_uint8, help='Referenced Security: Record Number within EF.ARR')
    createdf_optional.add_argument('--shareable', action='store_true', help='Should the file be shareable?')
    createdf_optional.add_argument('--aid', type=is_hexstr, help='Application ID (creates an ADF, instead of a DF)')
    # mandatory by spec, but ignored by several OS, so don't force the user
    createdf_optional.add_argument('--total-file-size', type=auto_uint16, help='Physical memory allocated for DF/ADi in octets')
    createdf_sja_optional.add_argument('--permit-rfm-create', action='store_true')
    createdf_sja_optional.add_argument('--permit-rfm-delete-terminate', action='store_true')
    createdf_sja_optional.add_argument('--permit-other-applet-create', action='store_true')
    createdf_sja_optional.add_argument('--permit-other-applet-delete-terminate', action='store_true')
    createdf_parser.add_argument('FILE_ID', type=is_hexstr, help='File Identifier as 4-character hex string')

    @cmd2.with_argparser(createdf_parser)
    def do_create_df(self, opts):
        """Create a new DF below the currently selected DF.  Requires related privileges."""
        file_descriptor = {
            'file_descriptor_byte': {
                'shareable': opts.shareable,
                'file_type': 'df',
                'structure': 'no_info_given',
            }
        }
        ies = []
        ies.append(FileDescriptor(decoded=file_descriptor))
        ies.append(FileIdentifier(decoded=opts.FILE_ID))
        if opts.aid:
            ies.append(DfName(decoded=opts.aid))
        ies.append(LifeCycleStatusInteger(decoded='operational_activated'))
        ies.append(SecurityAttribReferenced(decoded={'ef_arr_file_id': opts.ef_arr_file_id,
                                                     'ef_arr_record_nr': opts.ef_arr_record_nr }))
        if opts.total_file_size:
            ies.append(TotalFileSize(decoded=opts.total_file_size))
        # TODO: Spec states PIN Status Template DO is mandatory
        if opts.permit_rfm_create or opts.permit_rfm_delete_terminate or opts.permit_other_applet_create or opts.permit_other_applet_delete_terminate:
            toolkit_ac = {
               'rfm_create': opts.permit_rfm_create,
               'rfm_delete_terminate': opts.permit_rfm_delete_terminate,
               'other_applet_create': opts.permit_other_applet_create,
               'other_applet_delete_terminate': opts.permit_other_applet_delete_terminate,
               }
            ies.append(ProprietaryInformation(children=[ToolkitAccessConditions(decoded=toolkit_ac)]))
        fcp = FcpTemplate(children=ies)
        (_data, _sw) = self._cmd.lchan.scc.create_file(b2h(fcp.to_tlv()))
        # the newly-created file is automatically selected but our runtime state knows nothing of it
        self._cmd.lchan.select_file(self._cmd.lchan.selected_file)

    resize_ef_parser = argparse.ArgumentParser()
    resize_ef_parser._action_groups.pop()
    resize_ef_required = resize_ef_parser.add_argument_group('required arguments')
    resize_ef_required.add_argument('--file-size', required=True, type=auto_uint16, help='Size of file in octets')
    resize_ef_parser.add_argument('NAME', type=str, help='Name or FID of file to be resized')

    @cmd2.with_argparser(resize_ef_parser)
    def do_resize_ef(self, opts):
        """Resize an existing EF below the currently selected DF.  Requires related privileges."""
        f = self._cmd.lchan.get_file_for_filename(opts.NAME)
        ies = [FileIdentifier(decoded=f.fid),
               FileSize(decoded=opts.file_size)]
        fcp = FcpTemplate(children=ies)
        (_data, _sw) = self._cmd.lchan.scc.resize_file(b2h(fcp.to_tlv()))
        # the resized file is automatically selected but our runtime state knows nothing of it
        self._cmd.lchan.select_file(self._cmd.lchan.selected_file)

    def complete_resize_ef(self, text, line, begidx, endidx) -> List[str]:
        """Command Line tab completion for RESIZE EF"""
        index_dict = {1: self._cmd.lchan.selected_file.get_selectable_names()}
        return self._cmd.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)
