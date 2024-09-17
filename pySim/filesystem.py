# coding=utf-8
"""Representation of the ISO7816-4 filesystem model.

The File (and its derived classes) represent the structure / hierarchy
of the ISO7816-4 smart card file system with the MF, DF, EF and ADF
entries, further sub-divided into the EF sub-types Transparent, Linear Fixed, etc.

The classes are intended to represent the *specification* of the filesystem,
not the actual contents / runtime state of interacting with a given smart card.
"""

# (C) 2021-2024 by Harald Welte <laforge@osmocom.org>
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

from typing import cast, Optional, Iterable, List, Dict, Tuple, Union
import argparse
import tempfile
import json
import abc
import inspect

import cmd2
from cmd2 import CommandSet, with_default_category
from smartcard.util import toBytes

from osmocom.utils import h2b, b2h, is_hex, auto_int, auto_uint8, auto_uint16, is_hexstr, JsonEncoder
from osmocom.tlv import bertlv_parse_one
from osmocom.construct import filter_dict, parse_construct, build_construct

from pySim.utils import sw_match
from pySim.jsonpath import js_path_modify
from pySim.commands import SimCardCommands
from pySim.exceptions import SwMatchError

# int: a single service is associated with this file
# list: any of the listed services requires this file
# tuple: logical-and of the listed services requires this file
CardFileService = Union[int, List[int], Tuple[int, ...]]

Size = Tuple[int, Optional[int]]

class CardFile:
    """Base class for all objects in the smart card filesystem.
    Serve as a common ancestor to all other file types; rarely used directly.
    """
    RESERVED_NAMES = ['..', '.', '/', 'MF']
    RESERVED_FIDS = ['3f00']

    def __init__(self, fid: str = None, sfid: str = None, name: str = None, desc: str = None,
                 parent: Optional['CardDF'] = None, profile: Optional['CardProfile'] = None,
                 service: Optional[CardFileService] = None):
        """
        Args:
            fid : File Identifier (4 hex digits)
            sfid : Short File Identifier (2 hex digits, optional)
            name : Brief name of the file, like EF_ICCID
            desc : Description of the file
            parent : Parent CardFile object within filesystem hierarchy
            profile : Card profile that this file should be part of
            service : Service (SST/UST/IST) associated with the file
        """
        if not isinstance(self, CardADF) and fid is None:
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
        self.profile = profile
        self.service = service
        self.shell_commands = []  # type: List[CommandSet]

        # Note: the basic properties (fid, name, ect.) are verified when
        # the file is attached to a parent file. See method add_file() in
        # class Card DF

    def __str__(self):
        if self.name:
            return self.name
        else:
            return self.fid

    def _path_element(self, prefer_name: bool) -> Optional[str]:
        if prefer_name and self.name:
            return self.name
        else:
            return self.fid

    def fully_qualified_path_str(self, prefer_name: bool = True) -> str:
        """Return fully qualified path to file as string.

        Args:
            prefer_name : Preferably build path of names; fall-back to FIDs as required
        """
        return '/'.join(self.fully_qualified_path(prefer_name))

    def fully_qualified_path(self, prefer_name: bool = True) -> List[str]:
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

    def fully_qualified_path_fobj(self) -> List['CardFile']:
        """Return fully qualified path to file as list of CardFile instance references."""
        if self.parent and self.parent != self:
            ret = self.parent.fully_qualified_path_fobj()
        else:
            ret = []
        if self:
            ret.append(self)
        return ret

    def build_select_path_to(self, target: 'CardFile') -> Optional[List['CardFile']]:
        """Build the relative sequence of files we need to traverse to get from us to 'target'."""

        # special-case handling for applications. Applications may be selected
        # any time from any location. If there is an ADF somewhere in the path,
        # we may clip everything before that ADF.
        def clip_path(inter_path):
            for i in reversed(range(0, len(inter_path))):
                if isinstance(inter_path[i], CardADF):
                    return inter_path[i:]
            return inter_path

        # special-case handling for selecting MF while the MF is selected
        if target == target.get_mf():
            return [target]
        cur_fqpath = self.fully_qualified_path_fobj()
        target_fqpath = target.fully_qualified_path_fobj()
        inter_path = []
        cur_fqpath.reverse()
        for ce in cur_fqpath:
            inter_path.append(ce)
            for i in range(0, len(target_fqpath)-1):
                te = target_fqpath[i]
                if te == ce:
                    for te2 in target_fqpath[i+1:]:
                        inter_path.append(te2)
                    # we found our common ancestor
                    return clip_path(inter_path[1:])
        return None

    def get_mf(self) -> Optional['CardMF']:
        """Return the MF (root) of the file system."""
        if self.parent is None:
            return None
        # iterate towards the top. MF has parent == self
        node = self
        while node.parent and node.parent != node:
            node = node.parent
        return cast(CardMF, node)

    def _get_self_selectables(self, alias: str = None, flags=[]) -> Dict[str, 'CardFile']:
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

    def _get_parent_selectables(self, alias: Optional[str] = None, flags=[]) -> Dict[str, 'CardFile']:
        sels = {}
        if not self.parent or self.parent == self:
            return sels
        # add our immediate parent
        if alias:
            sels.update({alias: self.parent})
        if self.parent.fid and (flags == [] or 'FIDS' in flags):
            sels.update({self.parent.fid: self.parent})
        if self.parent.name and (flags == [] or 'FNAMES' in flags):
            sels.update({self.parent.name: self.parent})
        # recurse to parents of our parent, but without any alias
        sels.update(self.parent._get_parent_selectables(None, flags))
        return sels

    def get_selectables(self, flags=[]) -> Dict[str, 'CardFile']:
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
            sels.update(self._get_parent_selectables('..', flags))
        # if we have a MF, we can always select its applications
        if flags == [] or 'MF' in flags:
            mf = self.get_mf()
            if mf:
                sels.update(mf._get_self_selectables(flags=flags))
                sels.update(mf.get_app_selectables(flags=flags))
        return sels

    def get_selectable_names(self, flags=[]) -> List[str]:
        """Return a dict of {'identifier': File} that is selectable from the current file.

        Args:
            flags : Specify which selectables to return 'FIDS' and/or 'NAMES';
                    If not specified, all selectables will be returned.
        Returns:
            list containing all selectable names.
        """
        sels = self.get_selectables(flags)
        sel_keys = list(sels.keys())
        sel_keys.sort()
        return sel_keys

    def decode_select_response(self, data_hex: str):
        """Decode the response to a SELECT command.

        Args:
            data_hex: Hex string of the select response
        """

        # When the current file does not implement a custom select response decoder,
        # we just ask the parent file to decode the select response. If this method
        # is not overloaded by the current file we will again ask the parent file.
        # This way we recursively travel up the file system tree until we hit a file
        # that does implement a concrete decoder.
        if self.parent:
            return self.parent.decode_select_response(data_hex)

    def get_profile(self):
        """Get the profile associated with this file. If this file does not have any
        profile assigned, try to find a file above (usually the MF) in the filesystem
        hirarchy that has a profile assigned
        """

        # If we have a profile set, return it
        if self.profile:
            return self.profile

        # Walk up recursively until we hit a parent that has a profile set
        if self.parent:
            return self.parent.get_profile()
        return None

    def should_exist_for_services(self, services: List[int]):
        """Assuming the provided list of activated services, should this file exist and be activated?."""
        if self.service is None:
            return None
        if isinstance(self.service, int):
            # a single service determines the result
            return self.service in services
        if isinstance(self.service, list):
            # any of the services active -> true
            for s in self.service:
                if s in services:
                    return True
            return False
        if isinstance(self.service, tuple):
            # all of the services active -> true
            for s in self.service:
                if not s in services:
                    return False
            return True
        raise ValueError("self.service must be either int or list or tuple")

    @staticmethod
    def export(as_json: bool, lchan):
        """
        Export file contents in the form of commandline script. This method is meant to be overloaded by a subclass in
        case any exportable contents are present. The generated script may contain multiple command lines separated by
        line breaks ("\n"), where the last commandline shall have no line break at the end
        (e.g. "update_record 1 112233\nupdate_record 1 445566"). Naturally this export method will always refer to the
        currently selected file of the presented lchan.
        """
        return "# %s has no exportable contents" % str(lchan.selected_file)


class CardDF(CardFile):
    """DF (Dedicated File) in the smart card filesystem.  Those are basically sub-directories."""

    @with_default_category('DF/ADF Commands')
    class ShellCommands(CommandSet):
        pass

    def __init__(self, **kwargs):
        if not isinstance(self, CardADF):
            if 'fid' not in kwargs:
                raise TypeError('fid is mandatory for all DF')
        super().__init__(**kwargs)
        self.children = {}
        self.shell_commands = [self.ShellCommands()]
        # dict of CardFile affected by service(int), indexed by service
        self.files_by_service = {}

    def __str__(self):
        return "DF(%s)" % (super().__str__())

    def _add_file_services(self, child):
        """Add a child (DF/EF) to the files_by_services of the parent."""
        if not child.service:
            return
        if isinstance(child.service, int):
            self.files_by_service.setdefault(child.service, []).append(child)
        elif isinstance(child.service, list):
            for service in child.service:
                self.files_by_service.setdefault(service, []).append(child)
        elif isinstance(child.service, tuple):
            for service in child.service:
                self.files_by_service.setdefault(service, []).append(child)
        else:
            raise ValueError

    def _has_service(self):
        if self.service:
            return True
        for c in self.children.values():
            if isinstance(c, CardDF):
                if c._has_service():
                    return True

    def add_file(self, child: CardFile, ignore_existing: bool = False):
        """Add a child (DF/EF) to this DF.
        Args:
            child: The new DF/EF to be added
            ignore_existing: Ignore, if file with given FID already exists. Old one will be kept.
        """
        if not isinstance(child, CardFile):
            raise TypeError("Expected a File instance")
        if not is_hex(child.fid, minlen=4, maxlen=4):
            raise ValueError("File name %s is not a valid fid" % (child.fid))
        if child.name in CardFile.RESERVED_NAMES:
            raise ValueError("File name %s is a reserved name" % (child.name))
        if child.fid in CardFile.RESERVED_FIDS:
            raise ValueError("File fid %s is a reserved fid" % (child.fid))
        if child.fid in self.children:
            if ignore_existing:
                return
            raise ValueError(
                "File with given fid %s already exists in %s" % (child.fid, self))
        if self.lookup_file_by_sfid(child.sfid):
            raise ValueError(
                "File with given sfid %s already exists in %s" % (child.sfid, self))
        if self.lookup_file_by_name(child.name):
            if ignore_existing:
                return
            raise ValueError(
                "File with given name %s already exists in %s" % (child.name, self))
        self.children[child.fid] = child
        child.parent = self
        # update the service -> file relationship table
        self._add_file_services(child)
        if isinstance(child, CardDF):
            for c in child.children.values():
                self._add_file_services(c)
                if isinstance(c, CardDF):
                    for gc in c.children.values():
                        if isinstance(gc, CardDF):
                            if gc._has_service():
                                raise ValueError('TODO: implement recursive service -> file mapping')

    def add_files(self, children: Iterable[CardFile], ignore_existing: bool = False):
        """Add a list of child (DF/EF) to this DF

        Args:
            children: List of new DF/EFs to be added
            ignore_existing: Ignore, if file[s] with given FID already exists. Old one[s] will be kept.
        """
        for child in children:
            self.add_file(child, ignore_existing)

    def get_selectables(self, flags=[]) -> dict:
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

    def lookup_file_by_name(self, name: Optional[str]) -> Optional[CardFile]:
        """Find a file with given name within current DF."""
        if name is None:
            return None
        for i in self.children.values():
            if i.name and i.name == name:
                return i
        return None

    def lookup_file_by_sfid(self, sfid: Optional[str]) -> Optional[CardFile]:
        """Find a file with given short file ID within current DF."""
        if sfid is None:
            return None
        for i in self.children.values():
            if i.sfid == int(str(sfid)):
                return i
        return None

    def lookup_file_by_fid(self, fid: str) -> Optional[CardFile]:
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
        self.applications = {}

    def __str__(self):
        return "MF(%s)" % (self.fid)

    def add_application_df(self, app: 'CardADF'):
        """Add an Application to the MF"""
        if not isinstance(app, CardADF):
            raise TypeError("Expected an ADF instance")
        if app.aid in self.applications:
            raise ValueError("AID %s already exists" % (app.aid))
        self.applications[app.aid] = app
        app.parent = self

    def get_app_names(self):
        """Get list of completions (AID names)"""
        return list(self.applications.values())

    def get_selectables(self, flags=[]) -> dict:
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

    def get_app_selectables(self, flags=[]) -> dict:
        """Get applications by AID + name"""
        sels = {}
        if flags == [] or 'AIDS' in flags:
            sels.update({x.aid: x for x in self.applications.values()})
        if flags == [] or 'ANAMES' in flags:
            sels.update(
                {x.name: x for x in self.applications.values() if x.name})
        return sels

    def decode_select_response(self, data_hex: Optional[str]) -> object:
        """Decode the response to a SELECT command.

        This is the fall-back method which automatically defers to the standard decoding
        method defined by the card profile. When no profile is set, then no decoding is
        performed. Specific derived classes (usually ADF) can overload this method to
        install specific decoding.
        """

        if not data_hex:
            return data_hex

        profile = self.get_profile()

        if profile:
            return profile.decode_select_response(data_hex)
        else:
            return data_hex


class CardADF(CardDF):
    """ADF (Application Dedicated File) in the smart card filesystem"""

    def __init__(self, aid: str, has_fs: bool=False, **kwargs):
        super().__init__(**kwargs)
        # reference to CardApplication may be set from CardApplication constructor
        self.application = None  # type: Optional[CardApplication]
        self.aid = aid.lower()   # Application Identifier
        self.has_fs = has_fs     # Flag to tell whether the ADF supports a filesystem or not
        mf = self.get_mf()
        if mf:
            mf.add_application_df(self)

    def __str__(self):
        return "ADF(%s)" % (self.name if self.name else self.aid)

    def _path_element(self, prefer_name: bool):
        if self.name and prefer_name:
            return self.name
        else:
            return self.aid

    @staticmethod
    def export(as_json: bool, lchan):
        """
        Export application specific parameters that are not part of the UICC filesystem.
        """
        if not isinstance(lchan.selected_file, CardADF):
            raise TypeError('currently selected file is not of type CardADF')
        return lchan.selected_file.application.export(as_json, lchan)


class CardEF(CardFile):
    """EF (Entry File) in the smart card filesystem"""

    def __init__(self, *, fid, **kwargs):
        kwargs['fid'] = fid
        super().__init__(**kwargs)

    def __str__(self):
        return "EF(%s)" % (super().__str__())

    def get_selectables(self, flags=[]) -> dict:
        """Return a dict of {'identifier': File} that is selectable from the current DF.

        Args:
            flags : Specify which selectables to return 'FIDS' and/or 'NAMES';
                    If not specified, all selectables will be returned.
        Returns:
            dict containing all selectable items. Key is identifier (string), value
            a reference to a CardFile (or derived class) instance.
        """
        # global selectable names + those of the parent DF
        sels = super().get_selectables(flags)
        if flags == [] or 'FIDS' in flags:
            sels.update({x.fid: x for x in self.parent.children.values() if x.fid and x != self})
        if flags == [] or 'FNAMES' in flags:
            sels.update({x.name: x for x in self.parent.children.values() if x.name and x != self})
        return sels


class TransparentEF(CardEF):
    """Transparent EF (Entry File) in the smart card filesystem.

    A Transparent EF is a binary file with no formal structure.  This is contrary to
    Record based EFs which have [fixed size] records that can be individually read/updated."""

    @with_default_category('Transparent EF Commands')
    class ShellCommands(CommandSet):
        """Shell commands specific for transparent EFs."""

        dec_hex_parser = argparse.ArgumentParser()
        dec_hex_parser.add_argument('--oneline', action='store_true',
                                    help='No JSON pretty-printing, dump as a single line')
        dec_hex_parser.add_argument('HEXSTR', type=is_hexstr, help='Hex-string of encoded data to decode')

        @cmd2.with_argparser(dec_hex_parser)
        def do_decode_hex(self, opts):
            """Decode command-line provided hex-string as if it was read from the file."""
            data = self._cmd.lchan.selected_file.decode_hex(opts.HEXSTR)
            self._cmd.poutput_json(data, opts.oneline)

        read_bin_parser = argparse.ArgumentParser()
        read_bin_parser.add_argument(
            '--offset', type=auto_uint16, default=0, help='Byte offset for start of read')
        read_bin_parser.add_argument(
            '--length', type=auto_uint16, help='Number of bytes to read')

        @cmd2.with_argparser(read_bin_parser)
        def do_read_binary(self, opts):
            """Read binary data from a transparent EF"""
            (data, _sw) = self._cmd.lchan.read_binary(opts.length, opts.offset)
            self._cmd.poutput(data)

        read_bin_dec_parser = argparse.ArgumentParser()
        read_bin_dec_parser.add_argument('--oneline', action='store_true',
                                         help='No JSON pretty-printing, dump as a single line')

        @cmd2.with_argparser(read_bin_dec_parser)
        def do_read_binary_decoded(self, opts):
            """Read + decode data from a transparent EF"""
            (data, _sw) = self._cmd.lchan.read_binary_dec()
            self._cmd.poutput_json(data, opts.oneline)

        upd_bin_parser = argparse.ArgumentParser()
        upd_bin_parser.add_argument(
            '--offset', type=auto_uint16, default=0, help='Byte offset for start of read')
        upd_bin_parser.add_argument('DATA', type=is_hexstr, help='Data bytes (hex format) to write')

        @cmd2.with_argparser(upd_bin_parser)
        def do_update_binary(self, opts):
            """Update (Write) data of a transparent EF"""
            (data, _sw) = self._cmd.lchan.update_binary(opts.DATA, opts.offset)
            if data:
                self._cmd.poutput(data)

        upd_bin_dec_parser = argparse.ArgumentParser()
        upd_bin_dec_parser.add_argument('--json-path', type=str,
                                        help='JSON path to modify specific element of file only')
        upd_bin_dec_parser.add_argument('DATA', help='Abstract data (JSON format) to write')

        @cmd2.with_argparser(upd_bin_dec_parser)
        def do_update_binary_decoded(self, opts):
            """Encode + Update (Write) data of a transparent EF"""
            if opts.json_path:
                (data_json, _sw) = self._cmd.lchan.read_binary_dec()
                js_path_modify(data_json, opts.json_path,
                               json.loads(opts.DATA))
            else:
                data_json = json.loads(opts.DATA)
            (data, _sw) = self._cmd.lchan.update_binary_dec(data_json)
            if data:
                self._cmd.poutput_json(data)

        def do_edit_binary_decoded(self, _opts):
            """Edit the JSON representation of the EF contents in an editor."""
            (orig_json, _sw) = self._cmd.lchan.read_binary_dec()
            with tempfile.TemporaryDirectory(prefix='pysim_') as dirname:
                filename = '%s/file' % dirname
                # write existing data as JSON to file
                with open(filename, 'w') as text_file:
                    json.dump(orig_json, text_file, indent=4)
                # run a text editor
                self._cmd.run_editor(filename)
                with open(filename, 'r') as text_file:
                    edited_json = json.load(text_file)
                if edited_json == orig_json:
                    self._cmd.poutput("Data not modified, skipping write")
                else:
                    (data, _sw) = self._cmd.lchan.update_binary_dec(edited_json)
                    if data:
                        self._cmd.poutput_json(data)

    def __init__(self, fid: str, sfid: str = None, name: str = None, desc: str = None, parent: CardDF = None,
                 size: Size = (1, None), **kwargs):
        """
        Args:
            fid : File Identifier (4 hex digits)
            sfid : Short File Identifier (2 hex digits, optional)
            name : Brief name of the file, lik EF_ICCID
            desc : Description of the file
            parent : Parent CardFile object within filesystem hierarchy
            size : tuple of (minimum_size, recommended_size)
        """
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent, **kwargs)
        self._construct = None
        self._tlv = None
        self.size = size
        self.shell_commands = [self.ShellCommands()]

    def decode_bin(self, raw_bin_data: bytearray) -> dict:
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
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_tlv(raw_bin_data)
            return t.to_dict()
        return {'raw': raw_bin_data.hex()}

    def decode_hex(self, raw_hex_data: str) -> dict:
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
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_tlv(raw_bin_data)
            return t.to_dict()
        return {'raw': raw_bin_data.hex()}

    def __get_size(self, total_len: Optional[int] = None) -> Optional[int]:
        """Get the size (total length) of the file"""

        # Caller has provided the actual total length of the file, this should be the default case
        if total_len is not None:
            return total_len

        if self.size is None:
            return None

        # Alternatively use the recommended size from the specification
        if self.size[1] is not None:
            return self.size[1]
        # In case no recommended size is specified, use the minimum size
        if self.size[0] is not None:
            return self.size[0]

        return None

    def encode_bin(self, abstract_data: dict, total_len: Optional[int] = None) -> bytearray:
        """Encode abstract representation into raw (binary) data.

        A derived class would typically provide an _encode_bin() or _encode_hex() method
        for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
            total_len : expected total length of the encoded data (file size)
        Returns:
            binary encoded data
        """
        method = getattr(self, '_encode_bin', None)
        if callable(method):
            return method(abstract_data, total_len = self.__get_size(total_len))
        method = getattr(self, '_encode_hex', None)
        if callable(method):
            return h2b(method(abstract_data, total_len = self.__get_size(total_len)))
        if self._construct:
            return build_construct(self._construct, abstract_data, {'total_len' : self.__get_size(total_len)})
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_dict(abstract_data)
            return t.to_tlv()
        raise NotImplementedError(
            "%s encoder not yet implemented. Patches welcome." % self)

    def encode_hex(self, abstract_data: dict, total_len: Optional[int] = None) -> str:
        """Encode abstract representation into raw (hex string) data.

        A derived class would typically provide an _encode_bin() or _encode_hex() method
        for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
            total_len : expected total length of the encoded data (file size)
        Returns:
            hex string encoded data
        """
        method = getattr(self, '_encode_hex', None)
        if callable(method):
            return method(abstract_data, total_len = self.__get_size(total_len))
        method = getattr(self, '_encode_bin', None)
        if callable(method):
            raw_bin_data = method(abstract_data, total_len = self.__get_size(total_len))
            return b2h(raw_bin_data)
        if self._construct:
            return b2h(build_construct(self._construct, abstract_data, {'total_len':self.__get_size(total_len)}))
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_dict(abstract_data)
            return b2h(t.to_tlv())
        raise NotImplementedError(
            "%s encoder not yet implemented. Patches welcome." % self)

    @staticmethod
    def export(as_json: bool, lchan):
        """
        Export the file contents of a TransparentEF. This method returns a shell command string (See also ShellCommand
        definition in this class) that can be used to write the file contents back.
        """

        if lchan.selected_file_structure() != 'transparent':
            raise ValueError("selected file has structure type '%s', expecting a file with structure 'transparent'" %
                             lchan.selected_file_structure())
        export_str = ""
        if as_json:
            result = lchan.read_binary_dec()
            export_str += ("update_binary_decoded '%s'\n" % json.dumps(result[0], cls=JsonEncoder))
        else:
            result = lchan.read_binary()
            export_str += ("update_binary %s\n" % str(result[0]))
        return export_str.strip()


class LinFixedEF(CardEF):
    """Linear Fixed EF (Entry File) in the smart card filesystem.

    Linear Fixed EFs are record oriented files.  They consist of a number of fixed-size
    records.  The records can be individually read/updated."""

    @with_default_category('Linear Fixed EF Commands')
    class ShellCommands(CommandSet):
        """Shell commands specific for Linear Fixed EFs."""
        dec_hex_parser = argparse.ArgumentParser()
        dec_hex_parser.add_argument('--oneline', action='store_true',
                                    help='No JSON pretty-printing, dump as a single line')
        dec_hex_parser.add_argument('HEXSTR', type=is_hexstr, help='Hex-string of encoded data to decode')

        @cmd2.with_argparser(dec_hex_parser)
        def do_decode_hex(self, opts):
            """Decode command-line provided hex-string as if it was read from the file."""
            data = self._cmd.lchan.selected_file.decode_record_hex(opts.HEXSTR)
            self._cmd.poutput_json(data, opts.oneline)

        read_rec_parser = argparse.ArgumentParser()
        read_rec_parser.add_argument(
            '--count', type=auto_uint8, default=1, help='Number of records to be read, beginning at record_nr')
        read_rec_parser.add_argument(
            'RECORD_NR', type=auto_uint8, help='Number of record to be read')

        @cmd2.with_argparser(read_rec_parser)
        def do_read_record(self, opts):
            """Read one or multiple records from a record-oriented EF"""
            for r in range(opts.count):
                recnr = opts.RECORD_NR + r
                (data, _sw) = self._cmd.lchan.read_record(recnr)
                if len(data) > 0:
                    recstr = str(data)
                else:
                    recstr = "(empty)"
                self._cmd.poutput("%03d %s" % (recnr, recstr))

        read_rec_dec_parser = argparse.ArgumentParser()
        read_rec_dec_parser.add_argument('--oneline', action='store_true',
                                         help='No JSON pretty-printing, dump as a single line')
        read_rec_dec_parser.add_argument(
            'RECORD_NR', type=auto_uint8, help='Number of record to be read')

        @cmd2.with_argparser(read_rec_dec_parser)
        def do_read_record_decoded(self, opts):
            """Read + decode a record from a record-oriented EF"""
            (data, _sw) = self._cmd.lchan.read_record_dec(opts.RECORD_NR)
            self._cmd.poutput_json(data, opts.oneline)

        read_recs_parser = argparse.ArgumentParser()

        @cmd2.with_argparser(read_recs_parser)
        def do_read_records(self, _opts):
            """Read all records from a record-oriented EF"""
            num_of_rec = self._cmd.lchan.selected_file_num_of_rec()
            for recnr in range(1, 1 + num_of_rec):
                (data, _sw) = self._cmd.lchan.read_record(recnr)
                if len(data) > 0:
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
            num_of_rec = self._cmd.lchan.selected_file_num_of_rec()
            # collect all results in list so they are rendered as JSON list when printing
            data_list = []
            for recnr in range(1, 1 + num_of_rec):
                (data, _sw) = self._cmd.lchan.read_record_dec(recnr)
                data_list.append(data)
            self._cmd.poutput_json(data_list, opts.oneline)

        upd_rec_parser = argparse.ArgumentParser()
        upd_rec_parser.add_argument(
            'RECORD_NR', type=auto_uint8, help='Number of record to be read')
        upd_rec_parser.add_argument('DATA', type=is_hexstr, help='Data bytes (hex format) to write')

        @cmd2.with_argparser(upd_rec_parser)
        def do_update_record(self, opts):
            """Update (write) data to a record-oriented EF"""
            (data, _sw) = self._cmd.lchan.update_record(opts.RECORD_NR, opts.DATA)
            if data:
                self._cmd.poutput(data)

        upd_rec_dec_parser = argparse.ArgumentParser()
        upd_rec_dec_parser.add_argument('--json-path', type=str,
                                        help='JSON path to modify specific element of record only')
        upd_rec_dec_parser.add_argument(
            'RECORD_NR', type=auto_uint8, help='Number of record to be read')
        upd_rec_dec_parser.add_argument('data', help='Abstract data (JSON format) to write')

        @cmd2.with_argparser(upd_rec_dec_parser)
        def do_update_record_decoded(self, opts):
            """Encode + Update (write) data to a record-oriented EF"""
            if opts.json_path:
                (data_json, _sw) = self._cmd.lchan.read_record_dec(opts.RECORD_NR)
                js_path_modify(data_json, opts.json_path,
                               json.loads(opts.data))
            else:
                data_json = json.loads(opts.data)
            (data, _sw) = self._cmd.lchan.update_record_dec(
                opts.RECORD_NR, data_json)
            if data:
                self._cmd.poutput(data)

        edit_rec_dec_parser = argparse.ArgumentParser()
        edit_rec_dec_parser.add_argument(
            'RECORD_NR', type=auto_uint8, help='Number of record to be edited')

        @cmd2.with_argparser(edit_rec_dec_parser)
        def do_edit_record_decoded(self, opts):
            """Edit the JSON representation of one record in an editor."""
            (orig_json, _sw) = self._cmd.lchan.read_record_dec(opts.RECORD_NR)
            with tempfile.TemporaryDirectory(prefix='pysim_') as dirname:
                filename = '%s/file' % dirname
                # write existing data as JSON to file
                with open(filename, 'w') as text_file:
                    json.dump(orig_json, text_file, indent=4)
                # run a text editor
                self._cmd.run_editor(filename)
                with open(filename, 'r') as text_file:
                    edited_json = json.load(text_file)
                if edited_json == orig_json:
                    self._cmd.poutput("Data not modified, skipping write")
                else:
                    (data, _sw) = self._cmd.lchan.update_record_dec(
                        opts.RECORD_NR, edited_json)
                    if data:
                        self._cmd.poutput_json(data)

    def __init__(self, fid: str, sfid: str = None, name: str = None, desc: str = None,
                 parent: Optional[CardDF] = None, rec_len: Size = (1, None), leftpad: bool = False, **kwargs):
        """
        Args:
            fid : File Identifier (4 hex digits)
            sfid : Short File Identifier (2 hex digits, optional)
            name : Brief name of the file, lik EF_ICCID
            desc : Description of the file
            parent : Parent CardFile object within filesystem hierarchy
            rec_len : Tuple of (minimum_length, recommended_length)
            leftpad: On write, data must be padded from the left to fit pysical record length
        """
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent, **kwargs)
        self.rec_len = rec_len
        self.leftpad = leftpad
        self.shell_commands = [self.ShellCommands()]
        self._construct = None
        self._tlv = None

    def decode_record_hex(self, raw_hex_data: str, record_nr: int = 1) -> dict:
        """Decode raw (hex string) data into abstract representation.

        A derived class would typically provide a _decode_record_bin() or _decode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            raw_hex_data : hex-encoded data
            record_nr : record number (1 for first record, ...)
        Returns:
            abstract_data; dict representing the decoded data
        """
        method = getattr(self, '_decode_record_hex', None)
        if callable(method):
            return method(raw_hex_data, record_nr=record_nr)
        raw_bin_data = h2b(raw_hex_data)
        method = getattr(self, '_decode_record_bin', None)
        if callable(method):
            return method(raw_bin_data, record_nr=record_nr)
        if self._construct:
            return parse_construct(self._construct, raw_bin_data)
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_tlv(raw_bin_data)
            return t.to_dict()
        return {'raw': raw_bin_data.hex()}

    def decode_record_bin(self, raw_bin_data: bytearray, record_nr: int) -> dict:
        """Decode raw (binary) data into abstract representation.

        A derived class would typically provide a _decode_record_bin() or _decode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            raw_bin_data : binary encoded data
            record_nr : record number (1 for first record, ...)
        Returns:
            abstract_data; dict representing the decoded data
        """
        method = getattr(self, '_decode_record_bin', None)
        if callable(method):
            return method(raw_bin_data, record_nr=record_nr)
        raw_hex_data = b2h(raw_bin_data)
        method = getattr(self, '_decode_record_hex', None)
        if callable(method):
            return method(raw_hex_data, record_nr=record_nr)
        if self._construct:
            return parse_construct(self._construct, raw_bin_data)
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_tlv(raw_bin_data)
            return t.to_dict()
        return {'raw': raw_hex_data}

    def __get_rec_len(self, total_len: Optional[int] = None) -> Optional[int]:
        """Get the length (total length) of the file record"""

        # Caller has provided the actual total length of the record, this should be the default case
        if total_len is not None:
            return total_len

        if self.rec_len is None:
            return None

        # Alternatively use the recommended length from the specification
        if self.rec_len[1] is not None:
            return self.rec_len[1]
        # In case no recommended length is specified, use the minimum length
        if self.rec_len[0] is not None:
            return self.rec_len[0]

        return None

    def encode_record_hex(self, abstract_data: dict, record_nr: int, total_len: Optional[int] = None) -> str:
        """Encode abstract representation into raw (hex string) data.

        A derived class would typically provide an _encode_record_bin() or _encode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
            record_nr : record number (1 for first record, ...)
            total_len : expected total length of the encoded data (record length)
        Returns:
            hex string encoded data
        """
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return method(abstract_data, record_nr=record_nr, total_len = self.__get_rec_len(total_len))
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            raw_bin_data = method(abstract_data, record_nr=record_nr, total_len = self.__get_rec_len(total_len))
            return b2h(raw_bin_data)
        if self._construct:
            return b2h(build_construct(self._construct, abstract_data, {'total_len':self.__get_rec_len(total_len)}))
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_dict(abstract_data)
            return b2h(t.to_tlv())
        raise NotImplementedError(
            "%s encoder not yet implemented. Patches welcome." % self)

    def encode_record_bin(self, abstract_data: dict, record_nr : int, total_len: Optional[int] = None) -> bytearray:
        """Encode abstract representation into raw (binary) data.

        A derived class would typically provide an _encode_record_bin() or _encode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
            record_nr : record number (1 for first record, ...)
            total_len : expected total length of the encoded data (record length)
        Returns:
            binary encoded data
        """
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            return method(abstract_data, record_nr=record_nr, total_len = self.__get_rec_len(total_len))
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return h2b(method(abstract_data, record_nr=record_nr, total_len = self.__get_rec_len(total_len)))
        if self._construct:
            return build_construct(self._construct, abstract_data, {'total_len':self.__get_rec_len(total_len)})
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_dict(abstract_data)
            return t.to_tlv()
        raise NotImplementedError(
            "%s encoder not yet implemented. Patches welcome." % self)

    @staticmethod
    def export(as_json: bool, lchan):
        """
        Export the file contents of a LinFixedEF (or a CyclicEF). This method returns a shell command string (See also
        ShellCommand definition in this class) that can be used to write the file contents back.
        """

        # A CyclicEF is a subclass of LinFixedEF.
        if lchan.selected_file_structure() != 'linear_fixed' and lchan.selected_file_structure() != 'cyclic':
            raise ValueError("selected file has structure type '%s', expecting a file with structure 'linear_fixed' or 'cyclic'" %
                             lchan.selected_file_structure())

        export_str = ""

        # Use number of records specified in select response
        num_of_rec = lchan.selected_file_num_of_rec()
        if num_of_rec:
            for r in range(1, num_of_rec + 1):
                if as_json:
                    result = lchan.read_record_dec(r)
                    export_str += ("update_record_decoded %d '%s'\n" % (r, json.dumps(result[0], cls=JsonEncoder)))
                else:
                    result = lchan.read_record(r)
                    export_str += ("update_record %d %s\n" % (r, str(result[0])))

        # In case the select response does not return the number of records, read until we hit the first record that
        # cannot be read.
        else:
            r = 1
            while True:
                try:
                    if as_json:
                        result = lchan.read_record_dec(r)
                        export_str += ("update_record_decoded %d '%s'\n" % (r, json.dumps(result[0], cls=JsonEncoder)))
                    else:
                        result = lchan.read_record(r)
                        export_str += ("update_record %d %s\n" % (r, str(result[0])))
                except SwMatchError as e:
                    # We are past the last valid record - stop
                    if e.sw_actual == "9402":
                        break
                # Some other problem occurred
                else:
                    raise e
                r = r + 1

        return export_str.strip()


class CyclicEF(LinFixedEF):
    """Cyclic EF (Entry File) in the smart card filesystem"""
    # we don't really have any special support for those; just recycling LinFixedEF here

    def __init__(self, fid: str, sfid: str = None, name: str = None, desc: str = None, parent: CardDF = None,
                 rec_len: Size = (1, None), **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent, rec_len=rec_len, **kwargs)


class TransRecEF(TransparentEF):
    """Transparent EF (Entry File) containing fixed-size records.

    These are the real odd-balls and mostly look like mistakes in the specification:
    Specified as 'transparent' EF, but actually containing several fixed-length records
    inside.
    We add a special class for those, so the user only has to provide encoder/decoder functions
    for a record, while this class takes care of split / merge of records.
    """

    def __init__(self, fid: str, rec_len: int, sfid: str = None, name: str = None, desc: str = None,
                 parent: Optional[CardDF] = None, size: Size = (1, None), **kwargs):
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
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent, size=size, **kwargs)
        self.rec_len = rec_len

    def decode_record_hex(self, raw_hex_data: str) -> dict:
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
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_tlv(raw_bin_data)
            return t.to_dict()
        return {'raw': raw_hex_data}

    def decode_record_bin(self, raw_bin_data: bytearray) -> dict:
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
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_tlv(raw_bin_data)
            return t.to_dict()
        return {'raw': raw_hex_data}

    def __get_rec_len(self, total_len: Optional[int] = None) -> Optional[int]:
        """Get the length (total length) of the file record"""

        # Caller has provided the actual total length of the record, this should be the default case
        if total_len is not None:
            return total_len

        # Alternatively use the record length from the specification
        if self.rec_len:
            return self.rec_len

        return None

    def encode_record_hex(self, abstract_data: dict, total_len: Optional[int] = None) -> str:
        """Encode abstract representation into raw (hex string) data.

        A derived class would typically provide an _encode_record_bin() or _encode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
            total_len : expected total length of the encoded data (record length)
        Returns:
            hex string encoded data
        """
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return method(abstract_data, total_len = self.__get_rec_len(total_len))
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            return b2h(method(abstract_data, total_len = self.__get_rec_len(total_len)))
        if self._construct:
            return b2h(filter_dict(build_construct(self._construct, abstract_data,
                                                   {'total_len':self.__get_rec_len(total_len)})))
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_dict(abstract_data)
            return b2h(t.to_tlv())
        raise NotImplementedError(
            "%s encoder not yet implemented. Patches welcome." % self)

    def encode_record_bin(self, abstract_data: dict, total_len: Optional[int] = None) -> bytearray:
        """Encode abstract representation into raw (binary) data.

        A derived class would typically provide an _encode_record_bin() or _encode_record_hex()
        method for implementing this specifically for the given file. This function checks which
        of the method exists, add calls them (with conversion, as needed).

        Args:
            abstract_data : dict representing the decoded data
            total_len : expected total length of the encoded data (record length)
        Returns:
            binary encoded data
        """
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            return method(abstract_data, total_len = self.__get_rec_len(total_len))
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return h2b(method(abstract_data, total_len = self.__get_rec_len(total_len)))
        if self._construct:
            return filter_dict(build_construct(self._construct, abstract_data,
                                               {'total_len':self.__get_rec_len(total_len)}))
        if self._tlv:
            t = self._tlv() if inspect.isclass(self._tlv) else self._tlv
            t.from_dict(abstract_data)
            return t.to_tlv()
        raise NotImplementedError(
            "%s encoder not yet implemented. Patches welcome." % self)

    def _decode_bin(self, raw_bin_data: bytearray):
        chunks = [raw_bin_data[i:i+self.rec_len]
                  for i in range(0, len(raw_bin_data), self.rec_len)]
        return [self.decode_record_bin(x) for x in chunks]

    def _encode_bin(self, abstract_data, **kwargs) -> bytes:
        chunks = [self.encode_record_bin(x, total_len = kwargs.get('total_len', None)) for x in abstract_data]
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

        retrieve_data_parser = argparse.ArgumentParser()
        retrieve_data_parser.add_argument(
            'TAG', type=auto_int, help='BER-TLV Tag of value to retrieve')

        @cmd2.with_argparser(retrieve_data_parser)
        def do_retrieve_data(self, opts):
            """Retrieve (Read) data from a BER-TLV EF"""
            (data, _sw) = self._cmd.lchan.retrieve_data(opts.TAG)
            self._cmd.poutput(data)

        def do_retrieve_tags(self, _opts):
            """List tags available in a given BER-TLV EF"""
            tags = self._cmd.lchan.retrieve_tags()
            self._cmd.poutput(tags)

        set_data_parser = argparse.ArgumentParser()
        set_data_parser.add_argument(
            'TAG', type=auto_int, help='BER-TLV Tag of value to set')
        set_data_parser.add_argument('data', type=is_hexstr, help='Data bytes (hex format) to write')

        @cmd2.with_argparser(set_data_parser)
        def do_set_data(self, opts):
            """Set (Write) data for a given tag in a BER-TLV EF"""
            (data, _sw) = self._cmd.lchan.set_data(opts.TAG, opts.data)
            if data:
                self._cmd.poutput(data)

        del_data_parser = argparse.ArgumentParser()
        del_data_parser.add_argument(
            'TAG', type=auto_int, help='BER-TLV Tag of value to set')

        @cmd2.with_argparser(del_data_parser)
        def do_delete_data(self, opts):
            """Delete data for a given tag in a BER-TLV EF"""
            (data, _sw) = self._cmd.lchan.set_data(opts.TAG, None)
            if data:
                self._cmd.poutput(data)

        def do_delete_all(self, opts):
            """Delete all data from a BER-TLV EF"""
            tags = self._cmd.lchan.retrieve_tags()
            for tag in tags:
                self._cmd.lchan.set_data(tag, None)

    def __init__(self, fid: str, sfid: str = None, name: str = None, desc: str = None, parent: CardDF = None,
                 size: Size = (1, None), **kwargs):
        """
        Args:
            fid : File Identifier (4 hex digits)
            sfid : Short File Identifier (2 hex digits, optional)
            name : Brief name of the file, lik EF_ICCID
            desc : Description of the file
            parent : Parent CardFile object within filesystem hierarchy
            size : tuple of (minimum_size, recommended_size)
        """
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent, **kwargs)
        self._construct = None
        self.size = size
        self.shell_commands = [self.ShellCommands()]

    @staticmethod
    def export(as_json: bool, lchan):
        """
        Export the file contents of a BerTlvEF. This method returns a shell command string (See also ShellCommand
        definition in this class) that can be used to write the file contents back.
        """

        if lchan.selected_file_structure() != 'ber_tlv':
            raise ValueError("selected file has structure type '%s', expecting a file with structure 'ber_tlv'" %
                             lchan.selected_file_structure())

        # TODO: Add JSON output as soon as we have a set_data_decoded command and a retrieve_data_dec method.
        if as_json:
            raise NotImplementedError("BerTlvEF encoder not yet implemented. Patches welcome.")

        export_str = ""
        tags = lchan.retrieve_tags()
        if tags == []:
            export_str += "# empty file, no tags"
        else:
            export_str += "delete_all\n"
            for t in tags:
                result = lchan.retrieve_data(t)
                (tag, l, val, remainer) = bertlv_parse_one(h2b(result[0]))
                export_str += ("set_data 0x%02x %s\n" % (t, b2h(val)))
        return export_str.strip()


def interpret_sw(sw_data: dict, sw: str):
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


class CardApplication:
    """A card application is represented by an ADF (with contained hierarchy) and optionally
       some SW definitions."""

    def __init__(self, name, adf: Optional[CardADF] = None, aid: str = None, sw: dict = None):
        """
        Args:
            adf : ADF name
            sw : Dict of status word conversions
        """
        if aid:
            aid = aid.lower()
        self.name = name
        self.adf = adf
        self.sw = sw or {}
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

    @staticmethod
    def export(as_json: bool, lchan):
        """
        Export application specific parameters, in the form of commandline script. (see also comment in the export
        method of class "CardFile")
        """
        return "# %s has no exportable features" % str(lchan.selected_file)



class CardModel(abc.ABC):
    """A specific card model, typically having some additional vendor-specific files. All
    you need to do is to define a sub-class with a list of ATRs or an overridden match
    method."""
    _atrs = []

    @classmethod
    @abc.abstractmethod
    def add_files(cls, rs: 'RuntimeState'):
        """Add model specific files to given RuntimeState."""

    @classmethod
    def match(cls, scc: SimCardCommands) -> bool:
        """Test if given card matches this model."""
        card_atr = scc.get_atr()
        for atr in cls._atrs:
            atr_bin = toBytes(atr)
            if atr_bin == card_atr:
                print("Detected CardModel:", cls.__name__)
                return True
        return False

    @staticmethod
    def apply_matching_models(scc: SimCardCommands, rs: 'RuntimeState'):
        """Check if any of the CardModel sub-classes 'match' the currently inserted card
        (by ATR or overriding the 'match' method). If so, call their 'add_files'
        method."""
        for m in CardModel.__subclasses__():
            if m.match(scc):
                m.add_files(rs)


class Path:
    """Representation of a file-system path."""
    def __init__(self, p: Union[str, List[str], List[int]]):
        # split if given as single string with slahes
        if isinstance(p, str):
            p = p.split('/')
        elif len(p) and isinstance(p[0], int):
            p = ['%04x' % x for x in p]
        # make sure internal representation alwas is uppercase only
        self.list = [x.upper() for x in p]

    def __str__(self) -> str:
        return '/'.join(self.list)

    def __repr__(self) -> str:
        return 'Path(%s)' % (str(self))

    def __eq__(self, other: 'Path') -> bool:
        return self.list == other.list

    def __getitem__(self, i):
        return self.list[i]

    def __len__(self):
        return len(self.list)

    def __add__(self, a):
        if isinstance(a, list):
            l = self.list + a
        elif isinstance(a, Path):
            l = self.list + a.list
        else:
            l = self.list + [a]
        return Path(l)

    def relative_to_mf(self) -> 'Path':
        """Return a path relative to MF, i.e. without initial explicit MF."""
        if len(self.list) and self.list[0] in ['MF', '3F00']:
            return Path(self.list[1:])
        return self

    def is_parent(self, other: 'Path') -> bool:
        """Is this instance a parent of the given other instance?"""
        if len(self.list) >= len(other.list):
            return False
        if other.list[:len(self.list)] == self.list:
            return True
        return False
