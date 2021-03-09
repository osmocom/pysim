# coding=utf-8
"""Representation of the ISO7816-4 filesystem model.

The File (and its derived classes) represent the structure / hierarchy
of the ISO7816-4 smart card file system with the MF, DF, EF and ADF
entries, further sub-divided into the EF sub-types Transparent, Linear Fixed, etc.

The classes are intended to represent the *specification* of the filesystem,
not the actual contents / runtime state of interacting with a given smart card.

(C) 2021 by Harald Welte <laforge@osmocom.org>

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

import code
import json

import cmd2
from cmd2 import CommandSet, with_default_category, with_argparser
import argparse

from pySim.utils import sw_match, h2b, b2h, is_hex
from pySim.exceptions import *

class CardFile(object):
    """Base class for all objects in the smart card filesystem.
    Serve as a common ancestor to all other file types; rarely used directly.
    """
    RESERVED_NAMES = ['..', '.', '/', 'MF']
    RESERVED_FIDS = ['3f00']

    def __init__(self, fid=None, sfid=None, name=None, desc=None, parent=None):
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
        self.shell_commands = []

	# Note: the basic properties (fid, name, ect.) are verified when
	# the file is attached to a parent file. See method add_file() in
	# class Card DF

    def __str__(self):
        if self.name:
            return self.name
        else:
            return self.fid

    def _path_element(self, prefer_name):
        if prefer_name and self.name:
            return self.name
        else:
            return self.fid

    def fully_qualified_path(self, prefer_name=True):
        """Return fully qualified path to file as list of FID or name strings."""
        if self.parent != self:
            ret = self.parent.fully_qualified_path(prefer_name)
        else:
            ret = []
        ret.append(self._path_element(prefer_name))
        return ret

    def get_mf(self):
        """Return the MF (root) of the file system."""
        if self.parent == None:
            return None
        # iterate towards the top. MF has parent == self
        node = self
        while node.parent != node:
            node = node.parent
        return node

    def _get_self_selectables(self, alias=None, flags = []):
        """Return a dict of {'identifier': self} tuples"""
        sels = {}
        if alias:
            sels.update({alias: self})
        if self.fid and (flags == [] or 'FIDS' in flags):
            sels.update({self.fid: self})
        if self.name and (flags == [] or 'FNAMES' in flags):
            sels.update({self.name: self})
        return sels

    def get_selectables(self, flags = []):
        """Return a dict of {'identifier': File} that is selectable from the current file."""
        sels = {}
        # we can always select ourself
        if flags == [] or 'SELF' in flags:
            sels = self._get_self_selectables('.', flags)
        # we can always select our parent
        if flags == [] or 'PARENT' in flags:
            sels = self.parent._get_self_selectables('..', flags)
        # if we have a MF, we can always select its applications
        if flags == [] or 'MF' in flags:
            mf = self.get_mf()
            if mf:
                sels.update(mf._get_self_selectables(flags = flags))
                sels.update(mf.get_app_selectables(flags = flags))
        return sels

    def get_selectable_names(self, flags = []):
        """Return a list of strings for all identifiers that are selectable from the current file."""
        sels = self.get_selectables(flags)
        return sels.keys()

    def decode_select_response(self, data_hex):
        """Decode the response to a SELECT command."""
        return self.parent.decode_select_response(data_hex)


class CardDF(CardFile):
    """DF (Dedicated File) in the smart card filesystem.  Those are basically sub-directories."""
    def __init__(self, **kwargs):
        if not isinstance(self, CardADF):
            if not 'fid' in kwargs:
                raise TypeError('fid is mandatory for all DF')
        super().__init__(**kwargs)
        self.children = dict()

    def __str__(self):
        return "DF(%s)" % (super().__str__())

    def add_file(self, child, ignore_existing=False):
        """Add a child (DF/EF) to this DF"""
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
            raise ValueError("File with given fid %s already exists" % (child.fid))
        if self.lookup_file_by_sfid(child.sfid):
            raise ValueError("File with given sfid %s already exists" % (child.sfid))
        if self.lookup_file_by_name(child.name):
            if ignore_existing:
                return
            raise ValueError("File with given name %s already exists" % (child.name))
        self.children[child.fid] = child
        child.parent = self

    def add_files(self, children, ignore_existing=False):
        """Add a list of child (DF/EF) to this DF"""
        for child in children:
            self.add_file(child, ignore_existing)

    def get_selectables(self, flags = []):
        """Get selectable (DF/EF names) from current DF"""
        # global selectables + our children
        sels = super().get_selectables(flags)
        if flags == [] or 'FIDS' in flags:
                sels.update({x.fid: x for x in self.children.values() if x.fid})
        if flags == [] or 'FNAMES' in flags:
                sels.update({x.name: x for x in self.children.values() if x.name})
        return sels

    def lookup_file_by_name(self, name):
        if name == None:
            return None
        for i in self.children.values():
            if i.name and i.name == name:
                return i
        return None

    def lookup_file_by_sfid(self, sfid):
        if sfid == None:
            return None
        for i in self.children.values():
            if i.sfid == int(sfid):
                return i
        return None

    def lookup_file_by_fid(self, fid):
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

    def add_application(self, app):
        """Add an ADF (Application Dedicated File) to the MF"""
        if not isinstance(app, CardADF):
            raise TypeError("Expected an ADF instance")
        if app.aid in self.applications:
            raise ValueError("AID %s already exists" % (app.aid))
        self.applications[app.aid] = app
        app.parent=self

    def get_app_names(self):
        """Get list of completions (AID names)"""
        return [x.name for x in self.applications]

    def get_selectables(self, flags = []):
        """Get list of completions (DF/EF/ADF names) from current DF"""
        sels = super().get_selectables(flags)
        sels.update(self.get_app_selectables(flags))
        return sels

    def get_app_selectables(self, flags = []):
        """Get applications by AID + name"""
        sels = {}
        if flags == [] or 'AIDS' in flags:
                sels.update({x.aid: x for x in self.applications.values()})
        if flags == [] or 'ANAMES' in flags:
                sels.update({x.name: x for x in self.applications.values() if x.name})
        return sels

    def decode_select_response(self, data_hex):
        """Decode the response to a SELECT command."""
        return data_hex



class CardADF(CardDF):
    """ADF (Application Dedicated File) in the smart card filesystem"""
    def __init__(self, aid, **kwargs):
        super().__init__(**kwargs)
        self.aid = aid           # Application Identifier
        if self.parent:
            self.parent.add_application(self)

    def __str__(self):
        return "ADF(%s)" % (self.aid)

    def _path_element(self, prefer_name):
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

    def get_selectables(self, flags = []):
        """Get list of completions (EF names) from current DF"""
        #global selectable names + those of the parent DF
        sels = super().get_selectables(flags)
        sels.update({x.name:x for x in self.parent.children.values() if x != self})
        return sels


class TransparentEF(CardEF):
    """Transparent EF (Entry File) in the smart card filesystem"""

    @with_default_category('Transparent EF Commands')
    class ShellCommands(CommandSet):
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

        def do_read_binary_decoded(self, opts):
            """Read + decode data from a transparent EF"""
            (data, sw) = self._cmd.rs.read_binary_dec()
            self._cmd.poutput(json.dumps(data, indent=4))

        upd_bin_parser = argparse.ArgumentParser()
        upd_bin_parser.add_argument('--offset', type=int, default=0, help='Byte offset for start of read')
        upd_bin_parser.add_argument('data', help='Data bytes (hex format) to write')
        @cmd2.with_argparser(upd_bin_parser)
        def do_update_binary(self, opts):
            """Update (Write) data of a transparent EF"""
            (data, sw) = self._cmd.rs.update_binary(opts.data, opts.offset)
            self._cmd.poutput(data)

        upd_bin_dec_parser = argparse.ArgumentParser()
        upd_bin_dec_parser.add_argument('data', help='Abstract data (JSON format) to write')
        @cmd2.with_argparser(upd_bin_dec_parser)
        def do_update_binary_decoded(self, opts):
            """Encode + Update (Write) data of a transparent EF"""
            data_json = json.loads(opts.data)
            (data, sw) = self._cmd.rs.update_binary_dec(data_json)
            self._cmd.poutput(json.dumps(data, indent=4))

    def __init__(self, fid, sfid=None, name=None, desc=None, parent=None, size={1,None}):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent)
        self.size = size
        self.shell_commands = [self.ShellCommands()]

    def decode_bin(self, raw_bin_data):
        """Decode raw (binary) data into abstract representation. Overloaded by specific classes."""
        method = getattr(self, '_decode_bin', None)
        if callable(method):
            return method(raw_bin_data)
        method = getattr(self, '_decode_hex', None)
        if callable(method):
            return method(b2h(raw_bin_data))
        return {'raw': raw_bin_data.hex()}

    def decode_hex(self, raw_hex_data):
        """Decode raw (hex string) data into abstract representation. Overloaded by specific classes."""
        method = getattr(self, '_decode_hex', None)
        if callable(method):
            return method(raw_hex_data)
        raw_bin_data = h2b(raw_hex_data)
        method = getattr(self, '_decode_bin', None)
        if callable(method):
            return method(raw_bin_data)
        return {'raw': raw_bin_data.hex()}

    def encode_bin(self, abstract_data):
        """Encode abstract representation into raw (binary) data. Overloaded by specific classes."""
        method = getattr(self, '_encode_bin', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_hex', None)
        if callable(method):
            return h2b(method(abstract_data))
        raise NotImplementedError

    def encode_hex(self, abstract_data):
        """Encode abstract representation into raw (hex string) data. Overloaded by specific classes."""
        method = getattr(self, '_encode_hex', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_bin', None)
        if callable(method):
            raw_bin_data = method(abstract_data)
            return b2h(raw_bin_data)
        raise NotImplementedError


class LinFixedEF(CardEF):
    """Linear Fixed EF (Entry File) in the smart card filesystem"""

    @with_default_category('Linear Fixed EF Commands')
    class ShellCommands(CommandSet):
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
        @cmd2.with_argparser(read_rec_dec_parser)
        def do_read_record_decoded(self, opts):
            """Read + decode a record from a record-oriented EF"""
            (data, sw) = self._cmd.rs.read_record_dec(opts.record_nr)
            self._cmd.poutput(json.dumps(data, indent=4))

        upd_rec_parser = argparse.ArgumentParser()
        upd_rec_parser.add_argument('record_nr', type=int, help='Number of record to be read')
        upd_rec_parser.add_argument('data', help='Data bytes (hex format) to write')
        @cmd2.with_argparser(upd_rec_parser)
        def do_update_record(self, opts):
            """Update (write) data to a record-oriented EF"""
            (data, sw) = self._cmd.rs.update_record(opts.record_nr, opts.data)
            self._cmd.poutput(data)

        upd_rec_dec_parser = argparse.ArgumentParser()
        upd_rec_dec_parser.add_argument('record_nr', type=int, help='Number of record to be read')
        upd_rec_dec_parser.add_argument('data', help='Data bytes (hex format) to write')
        @cmd2.with_argparser(upd_rec_dec_parser)
        def do_update_record_decoded(self, opts):
            """Encode + Update (write) data to a record-oriented EF"""
            (data, sw) = self._cmd.rs.update_record_dec(opts.record_nr, opts.data)
            self._cmd.poutput(data)

    def __init__(self, fid, sfid=None, name=None, desc=None, parent=None, rec_len={1,None}):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent)
        self.rec_len = rec_len
        self.shell_commands = [self.ShellCommands()]

    def decode_record_hex(self, raw_hex_data):
        """Decode raw (hex string) data into abstract representation. Overloaded by specific classes."""
        method = getattr(self, '_decode_record_hex', None)
        if callable(method):
            return method(raw_hex_data)
        raw_bin_data = h2b(raw_hex_data)
        method = getattr(self, '_decode_record_bin', None)
        if callable(method):
            return method(raw_bin_data)
        return {'raw': raw_bin_data.hex()}

    def decode_record_bin(self, raw_bin_data):
        """Decode raw (binary) data into abstract representation. Overloaded by specific classes."""
        method = getattr(self, '_decode_record_bin', None)
        if callable(method):
            return method(raw_bin_data)
        raw_hex_data = b2h(raw_bin_data)
        method = getattr(self, '_decode_record_hex', None)
        if callable(method):
            return method(raw_hex_data)
        return {'raw': raw_hex_data}

    def encode_record_hex(self, abstract_data):
        """Encode abstract representation into raw (hex string) data. Overloaded by specific classes."""
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            raw_bin_data = method(abstract_data)
            return b2h(raww_bin_data)
        raise NotImplementedError

    def encode_record_bin(self, abstract_data):
        """Encode abstract representation into raw (binary) data. Overloaded by specific classes."""
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return b2h(method(abstract_data))
        raise NotImplementedError

class CyclicEF(LinFixedEF):
    """Cyclic EF (Entry File) in the smart card filesystem"""
    # we don't really have any special support for those; just recycling LinFixedEF here
    def __init__(self, fid, sfid=None, name=None, desc=None, parent=None, rec_len={1,None}):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent, rec_len=rec_len)

class TransRecEF(TransparentEF):
    """Transparent EF (Entry File) containing fixed-size records.
    These are the real odd-balls and mostly look like mistakes in the specification:
    Specified as 'transparent' EF, but actually containing several fixed-length records
    inside.
    We add a special class for those, so the user only has to provide encoder/decoder functions
    for a record, while this class takes care of split / merge of records.
    """
    def __init__(self, fid, sfid=None, name=None, desc=None, parent=None, rec_len=None, size={1,None}):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, parent=parent, size=size)
        self.rec_len = rec_len

    def decode_record_hex(self, raw_hex_data):
        """Decode raw (hex string) data into abstract representation. Overloaded by specific classes."""
        method = getattr(self, '_decode_record_hex', None)
        if callable(method):
            return method(raw_hex_data)
        method = getattr(self, '_decode_record_bin', None)
        if callable(method):
            raw_bin_data = h2b(raw_hex_data)
            return method(raw_bin_data)
        return {'raw': raw_hex_data}

    def decode_record_bin(self, raw_bin_data):
        """Decode raw (hex string) data into abstract representation. Overloaded by specific classes."""
        method = getattr(self, '_decode_record_bin', None)
        if callable(method):
            return method(raw_bin_data)
        raw_hex_data = b2h(raw_bin_data)
        method = getattr(self, '_decode_record_hex', None)
        if callable(method):
            return method(raw_hex_data)
        return {'raw': raw_hex_data}

    def encode_record_hex(self, abstract_data):
        """Encode abstract representation into raw (hex string) data. Overloaded by specific classes."""
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            return h2b(method(abstract_data))
        raise NotImplementedError

    def encode_record_bin(self, abstract_data):
        """Encode abstract representation into raw (binary) data. Overloaded by specific classes."""
        method = getattr(self, '_encode_record_bin', None)
        if callable(method):
            return method(abstract_data)
        method = getattr(self, '_encode_record_hex', None)
        if callable(method):
            return h2b(method(abstract_data))
        raise NotImplementedError

    def _decode_bin(self, raw_bin_data):
        chunks = [raw_bin_data[i:i+self.rec_len] for i in range(0, len(raw_bin_data), self.rec_len)]
        return [self.decode_record_bin(x) for x in chunks]

    def _encode_bin(self, abstract_data):
        chunks = [self.encode_record_bin(x) for x in abstract_data]
        # FIXME: pad to file size
        return b''.join(chunks)





class RuntimeState(object):
    """Represent the runtime state of a session with a card."""
    def __init__(self, card, profile):
        self.mf = CardMF()
        self.card = card
        self.selected_file = self.mf
        self.profile = profile
        # add applications + MF-files from profile
        for a in self.profile.applications:
            self.mf.add_application(a)
        for f in self.profile.files_in_mf:
            self.mf.add_file(f)

    def get_cwd(self):
        """Obtain the current working directory."""
        if isinstance(self.selected_file, CardDF):
            return self.selected_file
        else:
            return self.selected_file.parent

    def get_application(self):
        """Obtain the currently selected application (if any)."""
        # iterate upwards from selected file; check if any is an ADF
        node = self.selected_file
        while node.parent != node:
            if isinstance(node, CardADF):
                return node
            node = node.parent
        return None

    def interpret_sw(self, sw):
        """Interpret the given SW relative to the currently selected Application
           or the underlying profile."""
        app = self.get_application()
        if app:
            # The application either comes with its own interpret_sw
            # method or we will use the interpret_sw method from the
            # card profile.
            if hasattr(app, "interpret_sw"):
                return app.interpret_sw(sw)
            else:
                return self.profile.interpret_sw(sw)
            return app.interpret_sw(sw)
        else:
            return self.profile.interpret_sw(sw)

    def select(self, name, cmd_app=None):
        """Change current directory"""
        sels = self.selected_file.get_selectables()
        if is_hex(name):
            name = name.lower()
        if name in sels:
            f = sels[name]
            # unregister commands of old file
            if cmd_app and self.selected_file.shell_commands:
                for c in self.selected_file.shell_commands:
                    cmd_app.unregister_command_set(c)
            try:
                if isinstance(f, CardADF):
                    (data, sw) = self.card._scc.select_adf(f.aid)
                else:
                    (data, sw) = self.card._scc.select_file(f.fid)
                self.selected_file = f
            except SwMatchError as swm:
                k = self.interpret_sw(swm.sw_actual)
                if not k:
                    raise(swm)
                raise RuntimeError("%s: %s - %s" % (swm.sw_actual, k[0], k[1]))
            # register commands of new file
            if cmd_app and self.selected_file.shell_commands:
                for c in self.selected_file.shell_commands:
                    cmd_app.register_command_set(c)
            return f.decode_select_response(data)
        #elif looks_like_fid(name):
        else:
            raise ValueError("Cannot select unknown %s" % (name))

    def read_binary(self, length=None, offset=0):
        if not isinstance(self.selected_file, TransparentEF):
            raise TypeError("Only works with TransparentEF")
        return self.card._scc.read_binary(self.selected_file.fid, length, offset)

    def read_binary_dec(self):
        (data, sw) = self.read_binary()
        dec_data = self.selected_file.decode_hex(data)
        print("%s: %s -> %s" % (sw, data, dec_data))
        return (dec_data, sw)

    def update_binary(self, data_hex, offset=0):
        if not isinstance(self.selected_file, TransparentEF):
            raise TypeError("Only works with TransparentEF")
        return self.card._scc.update_binary(self.selected_file.fid, data_hex, offset)

    def update_binary_dec(self, data):
        data_hex = self.selected_file.encode_hex(data)
        print("%s -> %s" % (data, data_hex))
        return self.update_binary(data_hex)

    def read_record(self, rec_nr=0):
        if not isinstance(self.selected_file, LinFixedEF):
            raise TypeError("Only works with Linear Fixed EF")
        # returns a string of hex nibbles
        return self.card._scc.read_record(self.selected_file.fid, rec_nr)

    def read_record_dec(self, rec_nr=0):
        (data, sw) = self.read_record(rec_nr)
        return (self.selected_file.decode_record_hex(data), sw)

    def update_record(self, rec_nr, data_hex):
        if not isinstance(self.selected_file, LinFixedEF):
            raise TypeError("Only works with Linear Fixed EF")
        return self.card._scc.update_record(self.selected_file.fid, rec_nr, data_hex)

    def update_record_dec(self, rec_nr, data):
        hex_data = self.selected_file.encode_record_hex(data)
        return self.update_record(self, rec_nr, data_hex)



class FileData(object):
    """Represent the runtime, on-card data."""
    def __init__(self, fdesc):
        self.desc = fdesc
        self.fcp = None


def interpret_sw(sw_data, sw):
    """Interpret a given status word within the profile.  Returns tuple of
       two strings"""
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
    def __init__(self, name, adf=None, sw={}):
        self.name = name
        self.adf = adf
        self.sw = sw

    def __str__(self):
        return "APP(%s)" % (self.name)

    def interpret_sw(self, sw):
        """Interpret a given status word within the application.  Returns tuple of
           two strings"""
        return interpret_sw(self.sw, sw)

class CardProfile(object):
    """A Card Profile describes a card, it's filessystem hierarchy, an [initial] list of
       applications as well as profile-specific SW and shell commands.  Every card has
       one card profile, but there may be multiple applications within that profile."""
    def __init__(self, name, desc=None, files_in_mf=[], sw=[], applications=[], shell_cmdsets=[]):
        self.name = name
        self.desc = desc
        self.files_in_mf = files_in_mf
        self.sw = sw
        self.applications = applications
        self.shell_cmdsets = shell_cmdsets

    def __str__(self):
        return self.name

    def add_application(self, app):
        self.applications.add(app)

    def interpret_sw(self, sw):
        """Interpret a given status word within the profile.  Returns tuple of
           two strings"""
        return interpret_sw(self.sw, sw)
