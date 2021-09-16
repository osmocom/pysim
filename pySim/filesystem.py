# coding=utf-8
"""Representation of the ISO7816-4 filesystem model.

The File (and its derived classes) represent the structure / hierarchy
of the ISO7816-4 smart card file system with the MF, DF, EF and ADF
entries, further sub-divided into the EF sub-types Transparent, Linear Fixed, etc.

The classes are intended to represent the *specification* of the filesystem,
not the actual contents / runtime state of interacting with a given smart card.
"""

# (C) 2021 by Harald Welte <laforge@osmocom.org>
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

import code
import tempfile
import json
import abc
import inspect

import cmd2
from cmd2 import CommandSet, with_default_category, with_argparser
import argparse

from typing import cast, Optional, Iterable, List, Any, Dict, Tuple

from smartcard.util import toBytes

from pySim.utils import sw_match, h2b, b2h, i2h, is_hex, auto_int, bertlv_parse_one, Hexstr
from pySim.construct import filter_dict, parse_construct
from pySim.exceptions import *
from pySim.jsonpath import js_path_find, js_path_modify
from pySim.commands import SimCardCommands

class CardFile(object):
    """Base class for all objects in the smart card filesystem.
    Serve as a common ancestor to all other file types; rarely used directly.
    """
    RESERVED_NAMES = ['..', '.', '/', 'MF']
    RESERVED_FIDS = ['3f00']

    def __init__(self, fid:str=None, sfid:str=None, name:str=None, desc:str=None,
                 parent:Optional['CardDF']=None):
        """
        Args:
            fid : File Identifier (4 hex digits)
            sfid : Short File Identifier (2 hex digits, optional)
            name : Brief name of the file, lik EF_ICCID
            desc : Description of the file
            parent : Parent CardFile object within filesystem hierarchy
        """
        if not isinstance(self, CardADF) and fid == None:
            raise ValueError("fid is mandatory")
        if fid:
            fid = fid.lower()
        self.fid = fid           # file identifier
        self.sfid = sfid         # short file identifier
        self.name = name         # human readable name
        self.desc = desc         # human readable description
        self.parent = parent
        if self.parent and self.parent != self and self.fid:
            self.parent.add_file(self)
        self.shell_commands = [] # type: List[CommandSet]

	# Note: the basic properties (fid, name, ect.) are verified when
	# the file is attached to a parent file. See method add_file() in
	# class Card DF

    def __str__(self):
        if self.name:
            return self.name
        else:
            return self.fid

    def _path_element(self, prefer_name:bool) -> Optional[str]:
        if prefer_name and self.name:
            return self.name
        else:
            return self.fid

    def fully_qualified_path(self, prefer_name:bool=True) -> List[str]:
        """Return fully qualified path to file as list of FID or name strings.

        Args:
            prefer_name : Preferably build path of names; fall-back to FIDs as required
        """
        if self.parent and self.parent != self:
            ret = self.parent.fully_qualified_path(prefer_name)
        else:
            ret = []
        elem = self._path_element(prefer_name)
        if elem:
            ret.append(elem)
        return ret

    def get_mf(self) -> Optional['CardMF']:
        """Return the MF (root) of the file system."""
        if self.parent == None:
            return None
        # iterate towards the top. MF has parent == self
        node = self
        while node.parent and node.parent != node:
            node = node.parent
        return cast(CardMF, node)

    def _get_self_selectables(self, alias:str=None, flags = []) -> Dict[str, 'CardFile']:
        """Return a dict of {'identifier': self} tuples.

        Args:
            alias : Add an alias with given name to 'self' 
            flags : Specify which selectables to return 'FIDS' and/or 'NAMES';
                    If not specified, all selectables will be returned.
        Returns:
            dict containing reference to 'self' for all identifiers.
        """
        sels = {}
        if alias:
            sels.update({alias: self})
        if self.fid and (flags == [] or 'FIDS' in flags):
            sels.update({self.fid: self})
        if self.name and (flags == [] or 'FNAMES' in flags):
            sels.update({self.name: self})
        return sels

    def get_selectables(self, flags = []) -> Dict[str, 'CardFile']:
        """Return a dict of {'identifier': File} that is selectable from the current file.

        Args:
            flags : Specify which selectables to return 'FIDS' and/or 'NAMES';
                    If not specified, all selectables will be returned.
        Returns:
            dict containing all selectable items. Key is identifier (string), value
            a reference to a CardFile (or derived class) instance.
        """
        sels = {}
        # we can always select ourself
        if flags == [] or 'SELF' in flags:
            sels = self._get_self_selectables('.', flags)
        # we can always select our parent
        if flags == [] or 'PARENT' in flags:
            if self.parent:
                sels = self.parent._get_self_selectables('..', flags)
        # if we have a MF, we can always select its applications
        if flags == [] or 'MF' in flags:
            mf = self.get_mf()
            if mf:
                sels.update(mf._get_self_selectables(flags = flags))
                sels.update(mf.get_app_selectables(flags = flags))
        return sels

    def get_selectable_names(self, flags = []) -> List[str]:
        """Return a dict of {'identifier': File} that is selectable from the current file.

        Args:
            flags : Specify which selectables to return 'FIDS' and/or 'NAMES';
                    If not specified, all selectables will be returned.
        Returns:
            list containing all selectable names.
        """
        sels = self.get_selectables(flags)
        return list(sels.keys())

    def decode_select_response(self, data_hex:str):
        """Decode the response to a SELECT command."""
        if self.parent:
            return self.parent.decode_select_response(data_hex)


class CardDF(CardFile):
    """DF (Dedicated File) in the smart card filesystem.  Those are basically sub-directories."""

    @with_default_category('DF/ADF Commands')
    class ShellCommands(CommandSet):
        def __init__(self):
            super().__init__()

    def __init__(self, **kwargs):
        if not isinstance(self, CardADF):
            if not 'fid' in kwargs:
                raise TypeError('fid is mandatory for all DF')
        super().__init__(**kwargs)
        self.children = dict()
        self.shell_commands = [self.ShellCommands()]

    def __str__(self):
        return "DF(%s)" % (super().__str__())

    def add_file(self, child:CardFile, ignore_existing:bool=False):
        """Add a child (DF/EF) to this DF.
        Args:
            child: The new DF/EF to be added
            ignore_existing: Ignore, if file with given FID already exists. Old one will be kept.
        """
        if not isinstance(child, CardFile):
            raise TypeError("Expected a File instance")
        if not is_hex(child.fid, minlen = 4, maxlen = 4):
            raise ValueError("File name %s is not a valid fid" % (child.fid))
        if child.name in CardFile.RESERVED_NAMES:
            raise ValueError("File name %s is a reserved name" % (child.name))
        if child.fid in CardFile.RESERVED_FIDS:
            raise ValueError("File fid %s is a reserved fid" % (child.fid))
        if child.fid in self.children:
            if ignore_existing:
                return
            raise ValueError("File with given fid %s already exists in %s" % (child.fid, self))
        if self.lookup_file_by_sfid(child.sfid):
            raise ValueError("File with given sfid %s already exists in %s" % (child.sfid, self))
        if self.lookup_file_by_name(child.name):
            if ignore_existing:
                return
            raise ValueError("File with given name %s already exists in %s" % (child.name, self))
        self.children[child.fid] = child
        child.parent = self

    def add_files(self, children:Iterable[CardFile], ignore_existing:bool=False):
        """Add a list of child (DF/EF) to this DF

        Args:
            children: List of new DF/EFs to be added
            ignore_existing: Ignore, if file[s] with given FID already exists. Old one[s] will be kept.
        """
        for child in children:
            self.add_file(child, ignore_existing)

    def get_selectables(self, flags = []) -> dict:
        """Return a dict of {'identifier': File} that is selectable from the current DF.

        Args:
            flags : Specify which selectables to return 'FIDS' and/or 'NAMES';
                    If not specified, all selectables will be returned.
        Returns:
            dict containing all selectable items. Key is identifier (string), value
            a reference to a CardFile (or derived class) instance.
        """
        # global selectables + our children
        sels = super().get_selectables(flags)
        if flags == [] or 'FIDS' in flags:
                sels.update({x.fid: x for x in self.children.values() if x.fid})
        if flags == [] or 'FNAMES' in flags:
                sels.update({x.name: x for x in self.children.values() if x.name})
        return sels

    def lookup_file_by_name(self, name:Optional[str]) -> Optional[CardFile]:
        """Find a file with given name within current DF."""
        if name == None:
            return None
        for i in self.children.values():
            if i.name and i.name == name:
                return i
        return None

    def lookup_file_by_sfid(self, sfid:Optional[str]) -> Optional[CardFile]:
        """Find a file with given short file ID within current DF."""
        if sfid == None:
            return None
        for i in self.children.values():
            if i.sfid == int(str(sfid)):
                return i
        return None

    def lookup_file_by_fid(self, fid:str) -> Optional[CardFile]:
        """Find a file with given file ID within current DF."""
        if fid in self.children:
            return self.children[fid]
        return None


class CardMF(CardDF):
    """MF (Master File) in the smart card filesystem"""
    def __init__(self, **kwargs):
        # can be overridden; use setdefault
        kwargs.setdefault('fid', '3f00')
        kwargs.setdefault('name', 'MF')
        kwargs.setdefault('desc', 'Master File (directory root)')
        # cannot be overridden; use assignment
        kwargs['parent'] = self
        super().__init__(**kwargs)
        self.applications = dict()

    def __str__(self):
        return "MF(%s)" % (self.fid)

    def add_application_df(self, app:'CardADF'):
        """Add an Application to the MF"""
        if not isinstance(app, CardADF):
            raise TypeError("Expected an ADF instance")
        if app.aid in self.applications:
            raise ValueError("AID %s already exists" % (app.aid))
        self.applications[app.aid] = app
        app.parent=self

    def get_app_names(self):
        """Get list of completions (AID names)"""
        return [x.name for x in self.applications]

    def get_selectables(self, flags = []) -> dict:
        """Return a dict of {'identifier': File} that is selectable from the current DF.

        Args:
            flags : Specify which selectables to return 'FIDS' and/or 'NAMES';
                    If not specified, all selectables will be returned.
        Returns:
            dict containing all selectable items. Key is identifier (string), value
            a reference to a CardFile (or derived class) instance.
        """
        sels = super().get_selectables(flags)
        sels.update(self.get_app_selectables(flags))
        return sels

    def get_app_selectables(self, flags = []) -> dict:
        """Get applications by AID + name"""
        sels = {}
        if flags == [] or 'AIDS' in flags:
                sels.update({x.aid: x for x in self.applications.values()})
        if flags == [] or 'ANAMES' in flags:
                sels.update({x.name: x for x in self.applications.values() if x.name})
        return sels

    def decode_select_response(self, data_hex:str) -> Any:
        """Decode the response to a SELECT command.

        This is the fall-back method which doesn't perform any decoding. It mostly
        exists so specific derived classes can overload it for actual decoding.
        """
        return data_hex



class CardADF(CardDF):
    """ADF (Application Dedicated File) in the smart card filesystem"""
    def __init__(self, aid:str, **kwargs):
        super().__init__(**kwargs)
        # reference to CardApplication may be set from CardApplication constructor
        self.application = None  # type: Optional[CardApplication]
        self.aid = aid           # Application Identifier
        mf = self.get_mf()
        if mf:
            mf.add_application_df(self)

    def __str__(self):
        return "ADF(%s)" % (self.aid)

    def _path_element(self, prefer_name:bool):
        if self.name and prefer_name:
            return self.name
        else:
            return self.aid


class CardEF(CardFile):
    """EF (Entry File) in the smart card filesystem"""
    def __init__(self, *, fid, **kwargs):
        kwargs['fid'] = fid
        super().__init__(**kwargs)

    def __str__(self):
        return "EF(%s)" % (super().__str__())

    def get_selectables(self, flags = []) -> dict:
        """Return a dict of {'identifier': File} that is selectable from the current DF.

        Args:
            flags : Specify which selectables to return 'FIDS' and/or 'NAMES';
                    If not specified, all selectables will be returned.
        Returns:
            dict containing all selectable items. Key is identifier (string), value
            a reference to a CardFile (or derived class) instance.
        """
        #global selectable names + those of the parent DF
        sels = super().get_selectables(flags)
        sels.update({x.name:x for x in self.parent.children.values() if x != self})
        return sels


class TransparentEF(CardEF):
    """Transparent EF (Entry File) in the smart card filesystem.

    A Transparent EF is a binary file with no formal structure.  This is contrary to
    Record based EFs which have [fixed size] records that can be individually read/updated."""

    @with_default_category('Transparent EF Commands')
    class ShellCommands(CommandSet):
        """Shell commands specific for transparent EFs."""
        def __init__(self):
            super().__init__()

        read_bin_parser = argparse.ArgumentParser()
        read_bin_parser.add_argument('--offset', type=int, default=0, help='Byte offset for start of read')
        read_bin_parser.add_argument('--length', type=int, help='Number of bytes to read')
        @cmd2.with_argparser(read_bin_parser)
        def do_read_binary(self, opts):
            """Read binary data from a transparent EF"""
            (data, sw) = self._cmd.rs.read_binary(opts.length, opts.offset)
            self._cmd.poutput(data)

        read_bin_dec_parser = argparse.ArgumentParser()
        read_bin_dec_parser.add_argument('--oneline', action='store_true',
                                         help='No JSON pretty-printing, dump as a single line')
        @cmd2.with_argparser(read_bin_dec_parser)
        def do_read_binary_decoded(self, opts):
            """Read + decode data from a transparent EF"""
            (data, sw) = self._cmd.rs.read_binary_dec()
            self._cmd.poutput_json(data, opts.oneline)

        upd_bin_parser = argparse.ArgumentParser()
        upd_bin_parser.add_argument('--offset', type=int, default=0, help='Byte offset for start of read')
        upd_bin_parser.add_argument('data', help='Data bytes (hex format) to write')
        @cmd2.with_argparser(upd_bin_parser)
        def do_update_binary(self, opts):
            """Update (Write) data of a transparent EF"""
            (data, sw) = self._cmd.rs.update_binary(opts.data, opts.offset)
            if data:
                self._cmd.poutput(data)

        upd_bin_dec_parser = argparse.ArgumentParser()
        upd_bin_dec_parser.add_argument('data', help='Abstract data (JSON format) to write')
        upd_bin_dec_parser.add_argument('--json-path', type=str,
                                        help='JSON path to modify specific element of file only')
        @cmd2.with_argparser(upd_bin_dec_parser)
        def do_update_binary_decoded(self, opts):
            """Encode + Update (Write) data of a transparent EF"""
            if opts.json_path:
                (data_json, sw) = self._cmd.rs.read_binary_dec()
                js_path_modify(data_json, opts.json_path, json.loads(opts.data))
            else:
                data_json = json.loads(opts.data)
            (data, sw) = self._cmd.rs.update_binary_dec(data_json)
            if data:
                self._cmd.poutput_json(data)

        def do_edit_binary_decoded(self, opts):
            """Edit the JSON representation of the EF contents in an editor."""
            (orig_json, sw) = self._cmd.rs.read_binary_dec()
            with tempfile.TemporaryDirectory(prefix='pysim_') as dirname:
                filename = '%s/file' % dirname
                # write existing data as JSON to file
                with open(filename, 'w') as text_file:
                    json.dump(orig_json, text_file, indent=4)
                # run a text editor
                self._cmd._run_editor(filename)
                with open(filename, 'r') as text_file:
                    edited_json = json.load(text_file)
                if edited_json == orig_json:
                    self._cmd.poutput("Data not modified, skipping write")
                else:
                    (data, sw) = self._cmd.rs.update_binary_dec(edited_json)
                    if data:
                        self._cmd.poutput_json(data)


    def __init__(self, fid:str, sfid:str=None, name:str=None, desc:str=None, parent:CardDF=None,
                 size={1,None}):
        """
        Args:
            fid : File Identifier (4 hex digits)
            sfid : Short File Identifier (2 hex digits, optional)
            name : Brief name of the file, lik EF_ICCID
            desc : Description of the file
            parent : Parent CardFile object within filesystem hierarchy
            size : tuple of (minimum_size, recommended_size)
        """
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent)
        self._construct = None
        self._tlv = None
        self.size = size
        self.shell_commands = [self.ShellCommands()]

    def decode_bin(self, raw_bin_data:bytearray) -> dict:
        """Decode raw (binary) data into abstract representation.

        A derived class would typically provide a _decode_bin() or _decode_hex() method
        for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            raw_bin_data : binary encoded data
        Returns:
            abstract_data; dict representing the decoded data
        """
        method = getattr(self, '_decode_bin', None)
        if callable(method):
            return method(raw_bin_data)
        method = getattr(self, '_decode_hex', None)
        if callable(method):
            return method(b2h(raw_bin_data))
        if self._construct:
            return parse_construct(self._construct, raw_bin_data)
        elif self._tlv:
            self._tlv.from_tlv(raw_bin_data)
            return self._tlv.to_dict()
        return {'raw': raw_bin_data.hex()}

    def decode_hex(self, raw_hex_data:str) -> dict:
        """Decode raw (hex string) data into abstract representation.

        A derived class would typically provide a _decode_bin() or _decode_hex() method
        for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            raw_hex_data : hex-encoded data
        Returns:
            abstract_data; dict representing the decoded data
        """
        method = getattr(self, '_decode_hex', None)
        if callable(method):
            return method(raw_hex_data)
        raw_bin_data = h2b(raw_hex_data)
        method = getattr(self, '_decode_bin', None)
        if callable(method):
            return method(raw_bin_data)
        if self._construct:
            return parse_construct(self._construct, raw_bin_data)
        elif self._tlv:
            self._tlv.from_tlv(raw_bin_data)
            return self._tlv.to_dict()
        return {'raw': raw_bin_data.hex()}

    def encode_bin(self, abstract_data:dict) -> bytearray:
        """Encode abstract representation into raw (binary) data.

        A derived class would typically provide an _encode_bin() or _encode_hex() method
        for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
        Returns:
            binary encoded data
        """
        method = getattr(self, '_encode_bin', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_hex', None)
        if callable(method):
            return h2b(method(abstract_data))
        if self._construct:
            return self._construct.build(abstract_data)
        elif self._tlv:
            self._tlv.from_dict(abstract_data)
            return self._tlv.to_tlv()
        raise NotImplementedError("%s encoder not yet implemented. Patches welcome." % self)

    def encode_hex(self, abstract_data:dict) -> str:
        """Encode abstract representation into raw (hex string) data.

        A derived class would typically provide an _encode_bin() or _encode_hex() method
        for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
        Returns:
            hex string encoded data
        """
        method = getattr(self, '_encode_hex', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_bin', None)
        if callable(method):
            raw_bin_data = method(abstract_data)
            return b2h(raw_bin_data)
        if self._construct:
            return b2h(self._construct.build(abstract_data))
        elif self._tlv:
            self._tlv.from_dict(abstract_data)
            return b2h(self._tlv.to_tlv())
        raise NotImplementedError("%s encoder not yet implemented. Patches welcome." % self)


class LinFixedEF(CardEF):
    """Linear Fixed EF (Entry File) in the smart card filesystem.

    Linear Fixed EFs are record oriented files.  They consist of a number of fixed-size
    records.  The records can be individually read/updated."""

    @with_default_category('Linear Fixed EF Commands')
    class ShellCommands(CommandSet):
        """Shell commands specific for Linear Fixed EFs."""
        def __init__(self):
            super().__init__()

        read_rec_parser = argparse.ArgumentParser()
        read_rec_parser.add_argument('record_nr', type=int, help='Number of record to be read')
        read_rec_parser.add_argument('--count', type=int, default=1, help='Number of records to be read, beginning at record_nr')
        @cmd2.with_argparser(read_rec_parser)
        def do_read_record(self, opts):
            """Read one or multiple records from a record-oriented EF"""
            for r in range(opts.count):
                recnr = opts.record_nr + r
                (data, sw) = self._cmd.rs.read_record(recnr)
                if (len(data) > 0):
                   recstr = str(data)
                else:
                   recstr = "(empty)"
                self._cmd.poutput("%03d %s" % (recnr, recstr))

        read_rec_dec_parser = argparse.ArgumentParser()
        read_rec_dec_parser.add_argument('record_nr', type=int, help='Number of record to be read')
        read_rec_dec_parser.add_argument('--oneline', action='store_true',
                                         help='No JSON pretty-printing, dump as a single line')
        @cmd2.with_argparser(read_rec_dec_parser)
        def do_read_record_decoded(self, opts):
            """Read + decode a record from a record-oriented EF"""
            (data, sw) = self._cmd.rs.read_record_dec(opts.record_nr)
            self._cmd.poutput_json(data, opts.oneline)

        read_recs_parser = argparse.ArgumentParser()
        @cmd2.with_argparser(read_recs_parser)
        def do_read_records(self, opts):
            """Read all records from a record-oriented EF"""
            num_of_rec = self._cmd.rs.selected_file_fcp['file_descriptor']['num_of_rec']
            for recnr in range(1, 1 + num_of_rec):
                (data, sw) = self._cmd.rs.read_record(recnr)
                if (len(data) > 0):
                   recstr = str(data)
                else:
                   recstr = "(empty)"
                self._cmd.poutput("%03d %s" % (recnr, recstr))

        read_recs_dec_parser = argparse.ArgumentParser()
        read_recs_dec_parser.add_argument('--oneline', action='store_true',
                                         help='No JSON pretty-printing, dump as a single line')
        @cmd2.with_argparser(read_recs_dec_parser)
        def do_read_records_decoded(self, opts):
            """Read + decode all records from a record-oriented EF"""
            num_of_rec = self._cmd.rs.selected_file_fcp['file_descriptor']['num_of_rec']
            # collect all results in list so they are rendered as JSON list when printing
            data_list = []
            for recnr in range(1, 1 + num_of_rec):
                (data, sw) = self._cmd.rs.read_record_dec(recnr)
                data_list.append(data)
            self._cmd.poutput_json(data_list, opts.oneline)

        upd_rec_parser = argparse.ArgumentParser()
        upd_rec_parser.add_argument('record_nr', type=int, help='Number of record to be read')
        upd_rec_parser.add_argument('data', help='Data bytes (hex format) to write')
        @cmd2.with_argparser(upd_rec_parser)
        def do_update_record(self, opts):
            """Update (write) data to a record-oriented EF"""
            (data, sw) = self._cmd.rs.update_record(opts.record_nr, opts.data)
            if data:
                self._cmd.poutput(data)

        upd_rec_dec_parser = argparse.ArgumentParser()
        upd_rec_dec_parser.add_argument('record_nr', type=int, help='Number of record to be read')
        upd_rec_dec_parser.add_argument('data', help='Abstract data (JSON format) to write')
        upd_rec_dec_parser.add_argument('--json-path', type=str,
                                        help='JSON path to modify specific element of record only')
        @cmd2.with_argparser(upd_rec_dec_parser)
        def do_update_record_decoded(self, opts):
            """Encode + Update (write) data to a record-oriented EF"""
            if opts.json_path:
                (data_json, sw) = self._cmd.rs.read_record_dec(opts.record_nr)
                js_path_modify(data_json, opts.json_path, json.loads(opts.data))
            else:
                data_json = json.loads(opts.data)
            (data, sw) = self._cmd.rs.update_record_dec(opts.record_nr, data_json)
            if data:
                self._cmd.poutput(data)

        edit_rec_dec_parser = argparse.ArgumentParser()
        edit_rec_dec_parser.add_argument('record_nr', type=int, help='Number of record to be edited')
        @cmd2.with_argparser(edit_rec_dec_parser)
        def do_edit_record_decoded(self, opts):
            """Edit the JSON representation of one record in an editor."""
            (orig_json, sw) = self._cmd.rs.read_record_dec(opts.record_nr)
            with tempfile.TemporaryDirectory(prefix='pysim_') as dirname:
                filename = '%s/file' % dirname
                # write existing data as JSON to file
                with open(filename, 'w') as text_file:
                    json.dump(orig_json, text_file, indent=4)
                # run a text editor
                self._cmd._run_editor(filename)
                with open(filename, 'r') as text_file:
                    edited_json = json.load(text_file)
                if edited_json == orig_json:
                    self._cmd.poutput("Data not modified, skipping write")
                else:
                    (data, sw) = self._cmd.rs.update_record_dec(opts.record_nr, edited_json)
                    if data:
                        self._cmd.poutput_json(data)


    def __init__(self, fid:str, sfid:str=None, name:str=None, desc:str=None,
                 parent:Optional[CardDF]=None, rec_len={1,None}):
        """
        Args:
            fid : File Identifier (4 hex digits)
            sfid : Short File Identifier (2 hex digits, optional)
            name : Brief name of the file, lik EF_ICCID
            desc : Description of the file
            parent : Parent CardFile object within filesystem hierarchy
            rec_len : set of {minimum_length, recommended_length}
        """
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent)
        self.rec_len = rec_len
        self.shell_commands = [self.ShellCommands()]
        self._construct = None
        self._tlv = None

    def decode_record_hex(self, raw_hex_data:str) -> dict:
        """Decode raw (hex string) data into abstract representation.

        A derived class would typically provide a _decode_record_bin() or _decode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            raw_hex_data : hex-encoded data
        Returns:
            abstract_data; dict representing the decoded data
        """
        method = getattr(self, '_decode_record_hex', None)
        if callable(method):
            return method(raw_hex_data)
        raw_bin_data = h2b(raw_hex_data)
        method = getattr(self, '_decode_record_bin', None)
        if callable(method):
            return method(raw_bin_data)
        if self._construct:
            return parse_construct(self._construct, raw_bin_data)
        elif self._tlv:
            self._tlv.from_tlv(raw_bin_data)
            return self._tlv.to_dict()
        return {'raw': raw_bin_data.hex()}

    def decode_record_bin(self, raw_bin_data:bytearray) -> dict:
        """Decode raw (binary) data into abstract representation.

        A derived class would typically provide a _decode_record_bin() or _decode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            raw_bin_data : binary encoded data
        Returns:
            abstract_data; dict representing the decoded data
        """
        method = getattr(self, '_decode_record_bin', None)
        if callable(method):
            return method(raw_bin_data)
        raw_hex_data = b2h(raw_bin_data)
        method = getattr(self, '_decode_record_hex', None)
        if callable(method):
            return method(raw_hex_data)
        if self._construct:
            return parse_construct(self._construct, raw_bin_data)
        elif self._tlv:
            self._tlv.from_tlv(raw_bin_data)
            return self._tlv.to_dict()
        return {'raw': raw_hex_data}

    def encode_record_hex(self, abstract_data:dict) -> str:
        """Encode abstract representation into raw (hex string) data.

        A derived class would typically provide an _encode_record_bin() or _encode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
        Returns:
            hex string encoded data
        """
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            raw_bin_data = method(abstract_data)
            return b2h(raw_bin_data)
        if self._construct:
            return b2h(self._construct.build(abstract_data))
        elif self._tlv:
            self._tlv.from_dict(abstract_data)
            return b2h(self._tlv.to_tlv())
        raise NotImplementedError("%s encoder not yet implemented. Patches welcome." % self)

    def encode_record_bin(self, abstract_data:dict) -> bytearray:
        """Encode abstract representation into raw (binary) data.

        A derived class would typically provide an _encode_record_bin() or _encode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
        Returns:
            binary encoded data
        """
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return h2b(method(abstract_data))
        if self._construct:
            return self._construct.build(abstract_data)
        elif self._tlv:
            self._tlv.from_dict(abstract_data)
            return self._tlv.to_tlv()
        raise NotImplementedError("%s encoder not yet implemented. Patches welcome." % self)

class CyclicEF(LinFixedEF):
    """Cyclic EF (Entry File) in the smart card filesystem"""
    # we don't really have any special support for those; just recycling LinFixedEF here
    def __init__(self, fid:str, sfid:str=None, name:str=None, desc:str=None, parent:CardDF=None,
                 rec_len={1,None}):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent, rec_len=rec_len)

class TransRecEF(TransparentEF):
    """Transparent EF (Entry File) containing fixed-size records.

    These are the real odd-balls and mostly look like mistakes in the specification:
    Specified as 'transparent' EF, but actually containing several fixed-length records
    inside.
    We add a special class for those, so the user only has to provide encoder/decoder functions
    for a record, while this class takes care of split / merge of records.
    """
    def __init__(self, fid:str, rec_len:int, sfid:str=None, name:str=None, desc:str=None,
                 parent:Optional[CardDF]=None, size={1,None}):
        """
        Args:
            fid : File Identifier (4 hex digits)
            sfid : Short File Identifier (2 hex digits, optional)
            name : Brief name of the file, like EF_ICCID
            desc : Description of the file
            parent : Parent CardFile object within filesystem hierarchy
            rec_len : Length of the fixed-length records within transparent EF
            size : tuple of (minimum_size, recommended_size)
        """
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent, size=size)
        self.rec_len = rec_len

    def decode_record_hex(self, raw_hex_data:str) -> dict:
        """Decode raw (hex string) data into abstract representation.

        A derived class would typically provide a _decode_record_bin() or _decode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            raw_hex_data : hex-encoded data
        Returns:
            abstract_data; dict representing the decoded data
        """
        method = getattr(self, '_decode_record_hex', None)
        if callable(method):
            return method(raw_hex_data)
        raw_bin_data = h2b(raw_hex_data)
        method = getattr(self, '_decode_record_bin', None)
        if callable(method):
            return method(raw_bin_data)
        if self._construct:
            return parse_construct(self._construct, raw_bin_data)
        elif self._tlv:
            self._tlv.from_tlv(raw_bin_data)
            return self._tlv.to_dict()
        return {'raw': raw_hex_data}

    def decode_record_bin(self, raw_bin_data:bytearray) -> dict:
        """Decode raw (binary) data into abstract representation.

        A derived class would typically provide a _decode_record_bin() or _decode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            raw_bin_data : binary encoded data
        Returns:
            abstract_data; dict representing the decoded data
        """
        method = getattr(self, '_decode_record_bin', None)
        if callable(method):
            return method(raw_bin_data)
        raw_hex_data = b2h(raw_bin_data)
        method = getattr(self, '_decode_record_hex', None)
        if callable(method):
            return method(raw_hex_data)
        if self._construct:
            return parse_construct(self._construct, raw_bin_data)
        elif self._tlv:
            self._tlv.from_tlv(raw_bin_data)
            return self._tlv.to_dict()
        return {'raw': raw_hex_data}

    def encode_record_hex(self, abstract_data:dict) -> str:
        """Encode abstract representation into raw (hex string) data.

        A derived class would typically provide an _encode_record_bin() or _encode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
        Returns:
            hex string encoded data
        """
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            return b2h(method(abstract_data))
        if self._construct:
            return b2h(filter_dict(self._construct.build(abstract_data)))
        elif self._tlv:
            self._tlv.from_dict(abstract_data)
            return b2h(self._tlv.to_tlv())
        raise NotImplementedError("%s encoder not yet implemented. Patches welcome." % self)

    def encode_record_bin(self, abstract_data:dict) -> bytearray:
        """Encode abstract representation into raw (binary) data.

        A derived class would typically provide an _encode_record_bin() or _encode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
        Returns:
            binary encoded data
        """
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return h2b(method(abstract_data))
        if self._construct:
            return filter_dict(self._construct.build(abstract_data))
        elif self._tlv:
            self._tlv.from_dict(abstract_data)
            return self._tlv.to_tlv()
        raise NotImplementedError("%s encoder not yet implemented. Patches welcome." % self)

    def _decode_bin(self, raw_bin_data:bytearray):
        chunks = [raw_bin_data[i:i+self.rec_len] for i in range(0, len(raw_bin_data), self.rec_len)]
        return [self.decode_record_bin(x) for x in chunks]

    def _encode_bin(self, abstract_data) -> bytes:
        chunks = [self.encode_record_bin(x) for x in abstract_data]
        # FIXME: pad to file size
        return b''.join(chunks)


class BerTlvEF(CardEF):
    """BER-TLV EF (Entry File) in the smart card filesystem.
    A BER-TLV EF is a binary file with a BER (Basic Encoding Rules) TLV structure

    NOTE: We currently don't really support those, this class is simply a wrapper
    around TransparentEF as a place-holder, so we can already define EFs of BER-TLV
    type without fully supporting them."""

    @with_default_category('BER-TLV EF Commands')
    class ShellCommands(CommandSet):
        """Shell commands specific for BER-TLV EFs."""
        def __init__(self):
            super().__init__()

        retrieve_data_parser = argparse.ArgumentParser()
        retrieve_data_parser.add_argument('tag', type=auto_int, help='BER-TLV Tag of value to retrieve')
        @cmd2.with_argparser(retrieve_data_parser)
        def do_retrieve_data(self, opts):
            """Retrieve (Read) data from a BER-TLV EF"""
            (data, sw) = self._cmd.rs.retrieve_data(opts.tag)
            self._cmd.poutput(data)

        def do_retrieve_tags(self, opts):
            """List tags available in a given BER-TLV EF"""
            tags = self._cmd.rs.retrieve_tags()
            self._cmd.poutput(tags)

        set_data_parser = argparse.ArgumentParser()
        set_data_parser.add_argument('tag', type=auto_int, help='BER-TLV Tag of value to set')
        set_data_parser.add_argument('data', help='Data bytes (hex format) to write')
        @cmd2.with_argparser(set_data_parser)
        def do_set_data(self, opts):
            """Set (Write) data for a given tag in a BER-TLV EF"""
            (data, sw) = self._cmd.rs.set_data(opts.tag, opts.data)
            if data:
                self._cmd.poutput(data)

        del_data_parser = argparse.ArgumentParser()
        del_data_parser.add_argument('tag', type=auto_int, help='BER-TLV Tag of value to set')
        @cmd2.with_argparser(del_data_parser)
        def do_delete_data(self, opts):
            """Delete  data for a given tag in a BER-TLV EF"""
            (data, sw) = self._cmd.rs.set_data(opts.tag, None)
            if data:
                self._cmd.poutput(data)


    def __init__(self, fid:str, sfid:str=None, name:str=None, desc:str=None, parent:CardDF=None,
                 size={1,None}):
        """
        Args:
            fid : File Identifier (4 hex digits)
            sfid : Short File Identifier (2 hex digits, optional)
            name : Brief name of the file, lik EF_ICCID
            desc : Description of the file
            parent : Parent CardFile object within filesystem hierarchy
            size : tuple of (minimum_size, recommended_size)
        """
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent)
        self._construct = None
        self.size = size
        self.shell_commands = [self.ShellCommands()]


class RuntimeState(object):
    """Represent the runtime state of a session with a card."""
    def __init__(self, card, profile:'CardProfile'):
        """
        Args:
            card : pysim.cards.Card instance
            profile : CardProfile instance
        """
        self.mf = CardMF()
        self.card = card
        self.selected_file = self.mf # type: CardDF
        self.profile = profile
        # add application ADFs + MF-files from profile
        apps = self._match_applications()
        for a in apps:
            if a.adf:
                self.mf.add_application_df(a.adf)
        for f in self.profile.files_in_mf:
            self.mf.add_file(f)
        self.conserve_write = True

    def _match_applications(self):
        """match the applications from the profile with applications on the card"""
        apps_profile = self.profile.applications
        aids_card = self.card.read_aids()
        apps_taken = []
        if aids_card:
            aids_taken = []
            print("AIDs on card:")
            for a in aids_card:
                for f in apps_profile:
                    if f.aid in a:
                        print(" %s: %s" % (f.name, a))
                        aids_taken.append(a)
                        apps_taken.append(f)
            aids_unknown = set(aids_card) - set(aids_taken)
            for a in aids_unknown:
                print(" unknown: %s" % a)
        else:
            print("error: could not determine card applications")
        return apps_taken

    def reset(self, cmd_app=None) -> Hexstr:
        """Perform physical card reset and obtain ATR.
        Args:
            cmd_app : Command Application State (for unregistering old file commands)
        """
        self.card._scc._tp.reset_card()
        atr = i2h(self.card._scc._tp.get_atr())
        # select MF to reset internal state and to verify card really works
        self.select('MF', cmd_app)
        return atr

    def get_cwd(self) -> CardDF:
        """Obtain the current working directory.

        Returns:
            CardDF instance
        """
        if isinstance(self.selected_file, CardDF):
            return self.selected_file
        else:
            return self.selected_file.parent

    def get_application_df(self) -> Optional[CardADF]:
        """Obtain the currently selected application DF (if any).

        Returns:
            CardADF() instance or None"""
        # iterate upwards from selected file; check if any is an ADF
        node = self.selected_file
        while node.parent != node:
            if isinstance(node, CardADF):
                return node
            node = node.parent
        return None

    def interpret_sw(self, sw:str):
        """Interpret a given status word relative to the currently selected application
        or the underlying card profile.

        Args:
            sw : Status word as string of 4 hex digits

        Returns:
            Tuple of two strings
        """
        res = None
        adf = self.get_application_df()
        if adf:
            app = adf.application
            # The application either comes with its own interpret_sw
            # method or we will use the interpret_sw method from the
            # card profile.
            if app and hasattr(app, "interpret_sw"):
                res = app.interpret_sw(sw)
        return res or self.profile.interpret_sw(sw)

    def probe_file(self, fid:str, cmd_app=None):
        """Blindly try to select a file and automatically add a matching file
	       object if the file actually exists."""
        if not is_hex(fid, 4, 4):
            raise ValueError("Cannot select unknown file by name %s, only hexadecimal 4 digit FID is allowed" % fid)

        try:
            (data, sw) = self.card._scc.select_file(fid)
        except SwMatchError as swm:
            k = self.interpret_sw(swm.sw_actual)
            if not k:
                raise(swm)
            raise RuntimeError("%s: %s - %s" % (swm.sw_actual, k[0], k[1]))

        select_resp = self.selected_file.decode_select_response(data)
        if (select_resp['file_descriptor']['file_type'] == 'df'):
            f = CardDF(fid=fid, sfid=None, name="DF." + str(fid).upper(), desc="dedicated file, manually added at runtime")
        else:
            if (select_resp['file_descriptor']['structure'] == 'transparent'):
                f = TransparentEF(fid=fid, sfid=None, name="EF." + str(fid).upper(), desc="elementary file, manually added at runtime")
            else:
                f = LinFixedEF(fid=fid, sfid=None, name="EF." + str(fid).upper(), desc="elementary file, manually added at runtime")

        self.selected_file.add_files([f])
        self.selected_file = f
        return select_resp

    def select(self, name:str, cmd_app=None):
        """Select a file (EF, DF, ADF, MF, ...).

        Args:
            name : Name of file to select
            cmd_app : Command Application State (for unregistering old file commands)
        """
        sels = self.selected_file.get_selectables()
        if is_hex(name):
            name = name.lower()

        # unregister commands of old file
        if cmd_app and self.selected_file.shell_commands:
            for c in self.selected_file.shell_commands:
                cmd_app.unregister_command_set(c)

        if name in sels:
            f = sels[name]
            try:
                if isinstance(f, CardADF):
                    (data, sw) = self.card.select_adf_by_aid(f.aid)
                else:
                    (data, sw) = self.card._scc.select_file(f.fid)
                self.selected_file = f
            except SwMatchError as swm:
                k = self.interpret_sw(swm.sw_actual)
                if not k:
                    raise(swm)
                raise RuntimeError("%s: %s - %s" % (swm.sw_actual, k[0], k[1]))
            select_resp = f.decode_select_response(data)
        else:
            select_resp = self.probe_file(name, cmd_app)
        # store the decoded FCP for later reference
        self.selected_file_fcp = select_resp

        # register commands of new file
        if cmd_app and self.selected_file.shell_commands:
            for c in self.selected_file.shell_commands:
                cmd_app.register_command_set(c)

        return select_resp

    def status(self):
        """Request STATUS (current selected file FCP) from card."""
        (data, sw) = self.card._scc.status()
        return self.selected_file.decode_select_response(data)

    def activate_file(self, name:str):
        """Request ACTIVATE FILE of specified file."""
        sels = self.selected_file.get_selectables()
        f = sels[name]
        data, sw = self.card._scc.activate_file(f.fid)
        return data, sw

    def read_binary(self, length:int=None, offset:int=0):
        """Read [part of] a transparent EF binary data.

        Args:
            length : Amount of data to read (None: as much as possible)
            offset : Offset into the file from which to read 'length' bytes
        Returns:
            binary data read from the file
        """
        if not isinstance(self.selected_file, TransparentEF):
            raise TypeError("Only works with TransparentEF")
        return self.card._scc.read_binary(self.selected_file.fid, length, offset)

    def read_binary_dec(self) -> Tuple[dict, str]:
        """Read [part of] a transparent EF binary data and decode it.

        Args:
            length : Amount of data to read (None: as much as possible)
            offset : Offset into the file from which to read 'length' bytes
        Returns:
            abstract decode data read from the file
        """
        (data, sw) = self.read_binary()
        dec_data = self.selected_file.decode_hex(data)
        return (dec_data, sw)

    def update_binary(self, data_hex:str, offset:int=0):
        """Update transparent EF binary data.

        Args:
            data_hex : hex string of data to be written
            offset : Offset into the file from which to write 'data_hex'
        """
        if not isinstance(self.selected_file, TransparentEF):
            raise TypeError("Only works with TransparentEF")
        return self.card._scc.update_binary(self.selected_file.fid, data_hex, offset, conserve=self.conserve_write)

    def update_binary_dec(self, data:dict):
        """Update transparent EF from abstract data. Encodes the data to binary and
        then updates the EF with it.

        Args:
            data : abstract data which is to be encoded and written
        """
        data_hex = self.selected_file.encode_hex(data)
        return self.update_binary(data_hex)

    def read_record(self, rec_nr:int=0):
        """Read a record as binary data.

        Args:
            rec_nr : Record number to read
        Returns:
            hex string of binary data contained in record
        """
        if not isinstance(self.selected_file, LinFixedEF):
            raise TypeError("Only works with Linear Fixed EF")
        # returns a string of hex nibbles
        return self.card._scc.read_record(self.selected_file.fid, rec_nr)

    def read_record_dec(self, rec_nr:int=0) -> Tuple[dict, str]:
        """Read a record and decode it to abstract data.

        Args:
            rec_nr : Record number to read
        Returns:
            abstract data contained in record
        """
        (data, sw) = self.read_record(rec_nr)
        return (self.selected_file.decode_record_hex(data), sw)

    def update_record(self, rec_nr:int, data_hex:str):
        """Update a record with given binary data

        Args:
            rec_nr : Record number to read
            data_hex : Hex string binary data to be written
        """
        if not isinstance(self.selected_file, LinFixedEF):
            raise TypeError("Only works with Linear Fixed EF")
        return self.card._scc.update_record(self.selected_file.fid, rec_nr, data_hex, conserve=self.conserve_write)

    def update_record_dec(self, rec_nr:int, data:dict):
        """Update a record with given abstract data.  Will encode abstract to binary data
        and then write it to the given record on the card.

        Args:
            rec_nr : Record number to read
            data_hex : Abstract data to be written
        """
        data_hex = self.selected_file.encode_record_hex(data)
        return self.update_record(rec_nr, data_hex)

    def retrieve_data(self, tag:int=0):
        """Read a DO/TLV as binary data.

        Args:
            tag : Tag of TLV/DO to read
        Returns:
            hex string of full BER-TLV DO including Tag and Length
        """
        if not isinstance(self.selected_file, BerTlvEF):
            raise TypeError("Only works with BER-TLV EF")
        # returns a string of hex nibbles
        return self.card._scc.retrieve_data(self.selected_file.fid, tag)

    def retrieve_tags(self):
        """Retrieve tags available on BER-TLV EF.

        Returns:
            list of integer tags contained in EF
        """
        if not isinstance(self.selected_file, BerTlvEF):
            raise TypeError("Only works with BER-TLV EF")
        data, sw = self.card._scc.retrieve_data(self.selected_file.fid, 0x5c)
        tag, length, value, remainder = bertlv_parse_one(h2b(data))
        return list(value)

    def set_data(self, tag:int, data_hex:str):
        """Update a TLV/DO with given binary data

        Args:
            tag : Tag of TLV/DO to be written
            data_hex : Hex string binary data to be written (value portion)
        """
        if not isinstance(self.selected_file, BerTlvEF):
            raise TypeError("Only works with BER-TLV EF")
        return self.card._scc.set_data(self.selected_file.fid, tag, data_hex, conserve=self.conserve_write)

    def unregister_cmds(self, cmd_app=None):
        """Unregister all file specific commands."""
        if cmd_app and self.selected_file.shell_commands:
            for c in self.selected_file.shell_commands:
                cmd_app.unregister_command_set(c)



class FileData(object):
    """Represent the runtime, on-card data."""
    def __init__(self, fdesc):
        self.desc = fdesc
        self.fcp = None


def interpret_sw(sw_data:dict, sw:str):
    """Interpret a given status word.

    Args:
        sw_data : Hierarchical dict of status word matches
        sw : status word to match (string of 4 hex digits)
    Returns:
        tuple of two strings (class_string, description)
    """
    for class_str, swdict in sw_data.items():
        # first try direct match
        if sw in swdict:
            return (class_str, swdict[sw])
        # next try wildcard matches
        for pattern, descr in swdict.items():
            if sw_match(sw, pattern):
                return (class_str, descr)
    return None

class CardApplication(object):
    """A card application is represented by an ADF (with contained hierarchy) and optionally
       some SW definitions."""
    def __init__(self, name, adf:Optional[CardADF]=None, aid:str=None, sw:dict=None):
        """
        Args:
            adf : ADF name
            sw : Dict of status word conversions
        """
        self.name = name
        self.adf = adf
        self.sw = sw or dict()
        # back-reference from ADF to Applicaiton
        if self.adf:
            self.aid = aid or self.adf.aid
            self.adf.application = self
        else:
            self.aid = aid

    def __str__(self):
        return "APP(%s)" % (self.name)

    def interpret_sw(self, sw):
        """Interpret a given status word within the application.

        Args:
            sw : Status word as string of 4 hex digits

        Returns:
            Tuple of two strings
        """
        return interpret_sw(self.sw, sw)

class CardProfile(object):
    """A Card Profile describes a card, it's filesystem hierarchy, an [initial] list of
       applications as well as profile-specific SW and shell commands.  Every card has
       one card profile, but there may be multiple applications within that profile."""
    def __init__(self, name, **kw):
        """
        Args:
            desc (str) : Description
            files_in_mf : List of CardEF instances present in MF
            applications : List of CardApplications present on card
            sw : List of status word definitions
            shell_cmdsets : List of cmd2 shell command sets of profile-specific commands
        """
        self.name = name
        self.desc = kw.get("desc", None)
        self.files_in_mf = kw.get("files_in_mf", [])
        self.sw = kw.get("sw", [])
        self.applications = kw.get("applications", [])
        self.shell_cmdsets = kw.get("shell_cmdsets", [])

    def __str__(self):
        return self.name

    def add_application(self, app:CardApplication):
        """Add an application to a card profile.

        Args:
            app : CardApplication instance to be added to profile
        """
        self.applications.append(app)

    def interpret_sw(self, sw:str):
        """Interpret a given status word within the profile.

        Args:
            sw : Status word as string of 4 hex digits

        Returns:
            Tuple of two strings
        """
        return interpret_sw(self.sw, sw)


class CardModel(abc.ABC):
    """A specific card model, typically having some additional vendor-specific files. All
    you need to do is to define a sub-class with a list of ATRs or an overridden match
    method."""
    _atrs = []

    @classmethod
    @abc.abstractmethod
    def add_files(cls, rs:RuntimeState):
        """Add model specific files to given RuntimeState."""

    @classmethod
    def match(cls, scc:SimCardCommands) -> bool:
        """Test if given card matches this model."""
        card_atr = scc.get_atr()
        for atr in cls._atrs:
            atr_bin = toBytes(atr)
            if atr_bin == card_atr:
                print("Detected CardModel:", cls.__name__)
                return True
        return False

    @staticmethod
    def apply_matching_models(scc:SimCardCommands, rs:RuntimeState):
        """Check if any of the CardModel sub-classes 'match' the currently inserted card
        (by ATR or overriding the 'match' method). If so, call their 'add_files'
        method."""
        for m in CardModel.__subclasses__():
            if m.match(scc):
                m.add_files(rs)
