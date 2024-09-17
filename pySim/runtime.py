# coding=utf-8
"""Representation of the runtime state of an application like pySim-shell.
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

from typing import Optional, Tuple
from osmocom.utils import h2b, i2h, is_hex, Hexstr
from osmocom.tlv import bertlv_parse_one

from pySim.exceptions import *
from pySim.filesystem import *

def lchan_nr_from_cla(cla: int) -> int:
    """Resolve the logical channel number from the CLA byte."""
    # TS 102 221 10.1.1 Coding of Class Byte
    if cla >> 4 in [0x0, 0xA, 0x8]:
        # Table 10.3
        return cla & 0x03
    if cla & 0xD0 in [0x40, 0xC0]:
        # Table 10.4a
        return 4 + (cla & 0x0F)
    raise ValueError('Could not determine logical channel for CLA=%2X' % cla)

class RuntimeState:
    """Represent the runtime state of a session with a card."""

    def __init__(self, card: 'CardBase', profile: 'CardProfile'):
        """
        Args:
            card : pysim.cards.Card instance
            profile : CardProfile instance
        """
        self.mf = CardMF(profile=profile)
        self.card = card
        self.profile = profile
        self.lchan = {}
        # the basic logical channel always exists
        self.lchan[0] = RuntimeLchan(0, self)
        # this is a dict of card identities which different parts of the code might populate,
        # typically with something like ICCID, EID, ATR, ...
        self.identity = {}

        # make sure the class and selection control bytes, which are specified
        # by the card profile are used
        self.card.set_apdu_parameter(
            cla=self.profile.cla, sel_ctrl=self.profile.sel_ctrl)

        for addon_cls in self.profile.addons:
            addon = addon_cls()
            if addon.probe(self.card):
                print("Detected %s Add-on \"%s\"" % (self.profile, addon))
                for f in addon.files_in_mf:
                    self.mf.add_file(f)

        # go back to MF before the next steps (addon probing might have changed DF)
        self.lchan[0].select('MF')

        # add application ADFs + MF-files from profile
        apps = self._match_applications()
        for a in apps:
            if a.adf:
                self.mf.add_application_df(a.adf)
        for f in self.profile.files_in_mf:
            self.mf.add_file(f)
        self.conserve_write = True

        # make sure that when the runtime state is created, the card is also
        # in a defined state.
        self.reset()

    def _match_applications(self):
        """match the applications from the profile with applications on the card"""
        apps_profile = self.profile.applications

        # When the profile does not feature any applications, then we are done already
        if not apps_profile:
            return []

        # Read AIDs from card and match them against the applications defined by the
        # card profile
        aids_card = self.card.read_aids()
        apps_taken = []
        if aids_card:
            aids_taken = []
            print("AIDs on card:")
            for a in aids_card:
                for f in apps_profile:
                    if f.aid in a:
                        print(" %s: %s (EF.DIR)" % (f.name, a))
                        aids_taken.append(a)
                        apps_taken.append(f)
            aids_unknown = set(aids_card) - set(aids_taken)
            for a in aids_unknown:
                print(" unknown: %s (EF.DIR)" % a)
        else:
            print("warning: EF.DIR seems to be empty!")

        # Some card applications may not be registered in EF.DIR, we will actively
        # probe for those applications
        for f in sorted(set(apps_profile) - set(apps_taken), key=str):
            try:
                # we can not use the lchan provided methods select, or select_file
                # since those method work on an already finished file model. At
                # this point we are still in the initialization process, so it is
                # no problem when we access the card object directly without caring
                # about updating other states. For normal selects at runtime, the
                # caller must use the lchan provided methods select or select_file!
                _data, sw = self.card.select_adf_by_aid(f.aid)
                self.selected_adf = f
                if sw == "9000":
                    print(" %s: %s" % (f.name, f.aid))
                    apps_taken.append(f)
            except (SwMatchError, ProtocolError):
                pass
        return apps_taken

    def reset(self, cmd_app=None) -> Hexstr:
        """Perform physical card reset and obtain ATR.
        Args:
            cmd_app : Command Application State (for unregistering old file commands)
        """
        # delete all lchan != 0 (basic lchan)
        for lchan_nr in list(self.lchan.keys()):
            self.lchan[lchan_nr].scc.scp = None
            if lchan_nr == 0:
                continue
            del self.lchan[lchan_nr]
        atr = i2h(self.card.reset())
        if cmd_app:
            cmd_app.lchan = self.lchan[0]
        # select MF to reset internal state and to verify card really works
        self.lchan[0].select('MF', cmd_app)
        self.lchan[0].selected_adf = None
        # store ATR as part of our card identies dict
        self.identity['ATR'] = atr
        return atr

    def add_lchan(self, lchan_nr: int) -> 'RuntimeLchan':
        """Add a logical channel to the runtime state.  You shouldn't call this
        directly but always go through RuntimeLchan.add_lchan()."""
        if lchan_nr in self.lchan.keys():
            raise ValueError('Cannot create already-existing lchan %d' % lchan_nr)
        self.lchan[lchan_nr] = RuntimeLchan(lchan_nr, self)
        return self.lchan[lchan_nr]

    def del_lchan(self, lchan_nr: int):
        if lchan_nr in self.lchan.keys():
            del self.lchan[lchan_nr]
            return True
        else:
            return False

    def get_lchan_by_cla(self, cla) -> Optional['RuntimeLchan']:
        lchan_nr = lchan_nr_from_cla(cla)
        if lchan_nr in self.lchan.keys():
            return self.lchan[lchan_nr]
        else:
            return None


class RuntimeLchan:
    """Represent the runtime state of a logical channel with a card."""

    def __init__(self, lchan_nr: int, rs: RuntimeState):
        self.lchan_nr = lchan_nr
        self.rs = rs
        self.scc = self.rs.card._scc.fork_lchan(lchan_nr)

        # File reference data
        self.selected_file = self.rs.mf
        self.selected_adf = None
        self.selected_file_fcp = None
        self.selected_file_fcp_hex = None

    def add_lchan(self, lchan_nr: int) -> 'RuntimeLchan':
        """Add a new logical channel from the current logical channel. Just affects
        internal state, doesn't actually open a channel with the UICC."""
        new_lchan = self.rs.add_lchan(lchan_nr)
        # See TS 102 221 Table 8.3
        if self.lchan_nr != 0:
            new_lchan.selected_file = self.get_cwd()
            new_lchan.selected_adf = self.selected_adf
        return new_lchan

    def selected_file_descriptor_byte(self) -> dict:
        return self.selected_file_fcp['file_descriptor']['file_descriptor_byte']

    def selected_file_shareable(self) -> bool:
        return self.selected_file_descriptor_byte()['shareable']

    def selected_file_structure(self) -> str:
        return self.selected_file_descriptor_byte()['structure']

    def selected_file_type(self) -> str:
        return self.selected_file_descriptor_byte()['file_type']

    def selected_file_num_of_rec(self) -> Optional[int]:
        return self.selected_file_fcp['file_descriptor'].get('num_of_rec')

    def selected_file_record_len(self) -> Optional[int]:
        return self.selected_file_fcp['file_descriptor'].get('record_len')

    def selected_file_size(self) -> Optional[int]:
        return self.selected_file_fcp.get('file_size')

    def selected_file_reserved_file_size(self) -> Optional[int]:
        return self.selected_file_fcp['proprietary_information'].get('reserved_file_size')

    def selected_file_maximum_file_size(self) -> Optional[int]:
        return self.selected_file_fcp['proprietary_information'].get('maximum_file_size')

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

    def get_file_by_name(self, name: str) -> CardFile:
        """Obtain the file object from the file system tree by its name without actually selecting the file.

        Returns:
            CardFile() instance or None"""

        # handling of entire paths with multiple directories/elements
        if '/' in name:
            pathlist = name.split('/')
            # treat /DF.GSM/foo like MF/DF.GSM/foo
            if pathlist[0] == '':
                pathlist[0] = 'MF'
        else:
            pathlist = [name]

        # start in the current working directory (we can still
        # select any ADF and the MF from here, so those will be
        # among the selectables).
        file = self.get_cwd()

        for p in pathlist:
            # Look for the next file in the path list
            selectables = file.get_selectables()
            file = None
            for selectable in selectables:
                if selectable == p:
                    file = selectables[selectable]
                    break

            # When we hit none, then the given path must be invalid
            if file is None:
                return None

        # Return the file object found at the tip of the path
        return file

    def interpret_sw(self, sw: str):
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
        return res or self.rs.profile.interpret_sw(sw)

    def probe_file(self, fid: str, cmd_app=None):
        """Blindly try to select a file and automatically add a matching file
           object if the file actually exists."""
        if not is_hex(fid, 4, 4):
            raise ValueError(
                "Cannot select unknown file by name %s, only hexadecimal 4 digit FID is allowed" % fid)

        # unregister commands of old file
        self.unregister_cmds(cmd_app)

        try:
            # We access the card through the select_file method of the scc object.
            # If we succeed, we know that the file exists on the card and we may
            # proceed with creating a new CardEF object in the local file model at
            # run time. In case the file does not exist on the card, we just abort.
            # The state on the card (selected file/application) wont't be changed,
            # so we do not have to update any state in that case.
            (data, _sw) = self.scc.select_file(fid)
        except SwMatchError as swm:
            self._select_post(cmd_app)
            k = self.interpret_sw(swm.sw_actual)
            if not k:
                raise swm
            raise RuntimeError("%s: %s - %s" % (swm.sw_actual, k[0], k[1])) from swm

        select_resp = self.selected_file.decode_select_response(data)
        if select_resp['file_descriptor']['file_descriptor_byte']['file_type'] == 'df':
            f = CardDF(fid=fid, sfid=None, name="DF." + str(fid).upper(),
                       desc="dedicated file, manually added at runtime")
        else:
            if select_resp['file_descriptor']['file_descriptor_byte']['structure'] == 'transparent':
                f = TransparentEF(fid=fid, sfid=None, name="EF." + str(fid).upper(),
                                  desc="elementary file, manually added at runtime")
            else:
                f = LinFixedEF(fid=fid, sfid=None, name="EF." + str(fid).upper(),
                               desc="elementary file, manually added at runtime")

        self.selected_file.add_files([f])

        self._select_post(cmd_app, f, data)

    def _select_post(self, cmd_app, file:Optional[CardFile] = None, select_resp_data = None):
        # we store some reference data (see above) about the currently selected file.
        # This data must be updated after every select.
        if file:
            self.selected_file = file
            if isinstance(file, CardADF):
                self.selected_adf = file
            if select_resp_data:
                self.selected_file_fcp_hex = select_resp_data
                self.selected_file_fcp = self.selected_file.decode_select_response(select_resp_data)
            else:
                self.selected_file_fcp_hex = None
                self.selected_file_fcp = None

        # register commands of new file
        self.register_cmds(cmd_app)

    def select_file(self, file: CardFile, cmd_app=None):
        """Select a file (EF, DF, ADF, MF, ...).

        Args:
            file : CardFile [or derived class] instance
            cmd_app : Command Application State (for unregistering old file commands)
        """

        if not isinstance(file, CardADF) and self.selected_adf and self.selected_adf.has_fs == False:
            # Not every application that may be present on a GlobalPlatform card will support the SELECT
            # command as we know it from ETSI TS 102 221, section 11.1.1. In fact the only subset of
            # SELECT we may rely on is the OPEN SELECT command as specified in GlobalPlatform Card
            # Specification, section 11.9. Unfortunately the OPEN SELECT command only supports the
            # "select by name" method, which means we can only select an application and not a file.
            # The consequence of this is that we may get trapped in an application that does not have
            # ISIM/USIM like file system support and the only way to leave that application is to select
            # an ISIM/USIM application in order to get the file system access back.
            #
            # To automate this escape-route we will first select an arbitrary ADF that has file system support first
            # and then continue normally.
            for selectable in self.rs.mf.get_selectables().items():
                if isinstance(selectable[1], CardADF) and selectable[1].has_fs == True:
                    self.select(selectable[1].name, cmd_app)
                    break

        # we need to find a path from our self.selected_file to the destination
        inter_path = self.selected_file.build_select_path_to(file)
        if not inter_path:
            raise RuntimeError('Cannot determine path from %s to %s' % (self.selected_file, file))

        # unregister commands of old file
        self.unregister_cmds(cmd_app)

        # be sure the variables that we pass to _select_post contain valid values.
        selected_file = self.selected_file
        data = self.selected_file_fcp_hex

        for f in inter_path:
            try:
                # We now directly accessing the card to perform the selection. This
                # will change the state of the card, so we must take care to update
                # the local state (lchan) as well. This is done in the method
                # _select_post. It should be noted that the caller must always use
                # the methods select_file or select. The caller must not access the
                # card directly since this would lead into an incoherence of the
                # card state and the state of the lchan.
                if isinstance(f, CardADF):
                    (data, _sw) = self.rs.card.select_adf_by_aid(f.aid, scc=self.scc)
                else:
                    (data, _sw) = self.scc.select_file(f.fid)
                selected_file = f
            except SwMatchError as swm:
                self._select_post(cmd_app, selected_file, data)
                raise swm

        self._select_post(cmd_app, f, data)

    def select(self, name: str, cmd_app=None):
        """Select a file (EF, DF, ADF, MF, ...).

        Args:
            name : Name of file to select
            cmd_app : Command Application State (for unregistering old file commands)
        """
        # if any intermediate step fails, we must be able to go back where we were
        prev_sel_file = self.selected_file

        # handling of entire paths with multiple directories/elements
        if '/' in name:
            pathlist = name.split('/')
            # treat /DF.GSM/foo like MF/DF.GSM/foo
            if pathlist[0] == '':
                pathlist[0] = 'MF'
            try:
                for p in pathlist:
                    self.select(p, cmd_app)
                return self.selected_file_fcp
            except Exception as e:
                self.select_file(prev_sel_file, cmd_app)
                raise e

        # we are now in the directory where the target file is located
        # so we can now refer to the get_selectables() method to get the
        # file object and select it using select_file()
        sels = self.selected_file.get_selectables()
        if is_hex(name):
            name = name.lower()

        try:
            if name in sels:
                self.select_file(sels[name], cmd_app)
            else:
                self.probe_file(name, cmd_app)
        except Exception as e:
            self.select_file(prev_sel_file, cmd_app)
            raise e

        return self.selected_file_fcp

    def status(self):
        """Request STATUS (current selected file FCP) from card."""
        (data, _sw) = self.scc.status()
        return self.selected_file.decode_select_response(data)

    def get_file_for_filename(self, name: str):
        """Get the related CardFile object for a specified filename."""
        sels = self.selected_file.get_selectables()
        return sels[name]

    def activate_file(self, name: str):
        """Request ACTIVATE FILE of specified file."""
        sels = self.selected_file.get_selectables()
        f = sels[name]
        data, sw = self.scc.activate_file(f.fid)
        return data, sw

    def read_binary(self, length: int = None, offset: int = 0):
        """Read [part of] a transparent EF binary data.

        Args:
            length : Amount of data to read (None: as much as possible)
            offset : Offset into the file from which to read 'length' bytes
        Returns:
            binary data read from the file
        """
        if not isinstance(self.selected_file, TransparentEF):
            raise TypeError("Only works with TransparentEF, but %s is %s" % (self.selected_file,
                                                                             self.selected_file.__class__.__mro__))
        return self.scc.read_binary(self.selected_file.fid, length, offset)

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

    def update_binary(self, data_hex: str, offset: int = 0):
        """Update transparent EF binary data.

        Args:
            data_hex : hex string of data to be written
            offset : Offset into the file from which to write 'data_hex'
        """
        if not isinstance(self.selected_file, TransparentEF):
            raise TypeError("Only works with TransparentEF, but %s is %s" % (self.selected_file,
                                                                             self.selected_file.__class__.__mro__))
        return self.scc.update_binary(self.selected_file.fid, data_hex, offset, conserve=self.rs.conserve_write)

    def update_binary_dec(self, data: dict):
        """Update transparent EF from abstract data. Encodes the data to binary and
        then updates the EF with it.

        Args:
            data : abstract data which is to be encoded and written
        """
        data_hex = self.selected_file.encode_hex(data, self.selected_file_size())
        return self.update_binary(data_hex)

    def read_record(self, rec_nr: int = 0):
        """Read a record as binary data.

        Args:
            rec_nr : Record number to read
        Returns:
            hex string of binary data contained in record
        """
        if not isinstance(self.selected_file, LinFixedEF):
            raise TypeError("Only works with Linear Fixed EF, but %s is %s" % (self.selected_file,
                                                                               self.selected_file.__class__.__mro__))
        # returns a string of hex nibbles
        return self.scc.read_record(self.selected_file.fid, rec_nr)

    def read_record_dec(self, rec_nr: int = 0) -> Tuple[dict, str]:
        """Read a record and decode it to abstract data.

        Args:
            rec_nr : Record number to read
        Returns:
            abstract data contained in record
        """
        (data, sw) = self.read_record(rec_nr)
        return (self.selected_file.decode_record_hex(data, rec_nr), sw)

    def update_record(self, rec_nr: int, data_hex: str):
        """Update a record with given binary data

        Args:
            rec_nr : Record number to read
            data_hex : Hex string binary data to be written
        """
        if not isinstance(self.selected_file, LinFixedEF):
            raise TypeError("Only works with Linear Fixed EF, but %s is %s" % (self.selected_file,
                                                                               self.selected_file.__class__.__mro__))
        return self.scc.update_record(self.selected_file.fid, rec_nr, data_hex,
					       conserve=self.rs.conserve_write,
					       leftpad=self.selected_file.leftpad)

    def update_record_dec(self, rec_nr: int, data: dict):
        """Update a record with given abstract data.  Will encode abstract to binary data
        and then write it to the given record on the card.

        Args:
            rec_nr : Record number to read
            data_hex : Abstract data to be written
        """
        data_hex = self.selected_file.encode_record_hex(data, rec_nr, self.selected_file_record_len())
        return self.update_record(rec_nr, data_hex)

    def retrieve_data(self, tag: int = 0):
        """Read a DO/TLV as binary data.

        Args:
            tag : Tag of TLV/DO to read
        Returns:
            hex string of full BER-TLV DO including Tag and Length
        """
        if not isinstance(self.selected_file, BerTlvEF):
            raise TypeError("Only works with BER-TLV EF")
        # returns a string of hex nibbles
        return self.scc.retrieve_data(self.selected_file.fid, tag)

    def retrieve_tags(self):
        """Retrieve tags available on BER-TLV EF.

        Returns:
            list of integer tags contained in EF
        """
        if not isinstance(self.selected_file, BerTlvEF):
            raise TypeError("Only works with BER-TLV EF, but %s is %s" % (self.selected_file,
                                                                          self.selected_file.__class__.__mro__))
        data, _sw = self.scc.retrieve_data(self.selected_file.fid, 0x5c)
        _tag, _length, value, _remainder = bertlv_parse_one(h2b(data))
        return list(value)

    def set_data(self, tag: int, data_hex: str):
        """Update a TLV/DO with given binary data

        Args:
            tag : Tag of TLV/DO to be written
            data_hex : Hex string binary data to be written (value portion)
        """
        if not isinstance(self.selected_file, BerTlvEF):
            raise TypeError("Only works with BER-TLV EF, but %s is %s" % (self.selected_file,
                                                                          self.selected_file.__class__.__mro__))
        return self.scc.set_data(self.selected_file.fid, tag, data_hex, conserve=self.rs.conserve_write)

    def register_cmds(self, cmd_app=None):
        """Register command set that is associated with the currently selected file"""
        if cmd_app and self.selected_file.shell_commands:
            for c in self.selected_file.shell_commands:
                cmd_app.register_command_set(c)

    def unregister_cmds(self, cmd_app=None):
        """Unregister command set that is associated with the currently selected file"""
        if cmd_app and self.selected_file.shell_commands:
            for c in self.selected_file.shell_commands:
                cmd_app.unregister_command_set(c)
