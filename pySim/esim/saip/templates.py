"""Implementation of SimAlliance/TCA Interoperable Profile Templates."""

# (C) 2024 by Harald Welte <laforge@osmocom.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from typing import *
from copy import deepcopy
from pySim.utils import all_subclasses, h2b
from pySim.filesystem import Path
import pySim.esim.saip.oid as OID

class FileTemplate:
    """Representation of a single file in a SimAlliance/TCA Profile Template. The argument order
    is done to match that of the tables in Section 9 of the SAIP specification."""
    def __init__(self, fid:int, name:str, ftype, nb_rec: Optional[int], size:Optional[int], arr:int,
                 sfi:Optional[int] = None, default_val:Optional[str] = None, content_rqd:bool = True,
                 params:Optional[List] = None, ass_serv:Optional[List[int]]=None, high_update:bool = False,
                 pe_name:Optional[str] = None, repeat:bool = False, ppath: List[int] = []):
        """
        Args:
            fid: The 16bit file-identifier of the file
            name: The name of the file in human-readable "EF.FOO", "DF.BAR" notation
            ftype: The type of the file; can be 'MF', 'ADF', 'DF', 'TR', 'LF', 'CY', 'BT'
            nb_rec: Then number of records (only valid for 'LF' and 'CY')
            size: The size of the file ('TR', 'BT'); size of each record ('LF, 'CY')
            arr: The record number of EF.ARR for referenced access rules
            sfi: The short file identifier, if any
            default_val: The default value [pattern] of the file
            content_rqd: Whether an instance of template *must* specify file contents
            params: A list of parameters that an instance of the template *must* specify
            ass_serv: The associated service[s] of the service table
            high_update: Is this file of "high update frequency" type?
            pe_name: The name of this file in the ASN.1 type of the PE. Auto-generated for most.
            repeat: Whether the default_val pattern is a repeating pattern.
            ppath: The intermediate path between the base_df of the ProfileTemplate and this file.  If not
                   specified, the file will be created immediately underneath the base_df.
        """
        # initialize from arguments
        self.fid = fid
        self.name = name
        if pe_name:
            self.pe_name = pe_name
        else:
            self.pe_name = self.name.replace('.','-').replace('_','-').lower()
        self.file_type = ftype
        if ftype in ['LF', 'CY']:
            self.nb_rec = nb_rec
            self.rec_len = size
        elif ftype in ['TR', 'BT']:
            self.file_size = size
        self.arr = arr
        self.sfi = sfi
        self.default_val = default_val
        self.default_val_repeat = repeat
        self.content_rqd = content_rqd
        self.params = params
        self.ass_serv = ass_serv
        self.high_update = high_update
        self.ppath = ppath # parent path, if this FileTemplate is not immediately below the base_df
        # initialize empty
        self.parent = None
        self.children = []
        if self.default_val:
            length = self._default_value_len() or 100
            # run the method once to verify the pattern can be processed
            self.expand_default_value_pattern(length)

    def __str__(self) -> str:
        return "FileTemplate(%s)" % (self.name)

    def __repr__(self) -> str:
        s_fid = "%04x" % self.fid if self.fid is not None else 'None'
        s_arr = self.arr if self.arr is not None else 'None'
        s_sfi = "%02x" % self.sfi if self.sfi is not None else 'None'
        return "FileTemplate(%s/%s, %s, %s, arr=%s, sfi=%s, ppath=%s)" % (self.name, self.pe_name, s_fid, self.file_type, s_arr, s_sfi, self.ppath)

    def print_tree(self, indent:str = ""):
        """recursive printing of FileTemplate tree structure."""
        print("%s%s (%s)" % (indent, repr(self), self.path))
        indent += " "
        for c in self.children:
            c.print_tree(indent)

    @property
    def path(self):
        """Return the path of the given File within the hierarchy."""
        if self.parent:
            return self.parent.path + self.name
        else:
            return Path(self.name)

    def get_file_by_path(self, path: List[str]) -> Optional['FileTemplate']:
        """Return a FileTemplate matching the given path within this ProfileTemplate."""
        if path[0].lower() != self.name.lower():
            return None
        for c in self.children:
            if path[1].lower() == c.name.lower():
                return c.get_file_by_path(path[1:])

    def _default_value_len(self):
        if self.file_type in ['TR']:
            return self.file_size
        elif self.file_type in ['LF', 'CY']:
            return self.rec_len

    def expand_default_value_pattern(self, length: Optional[int] = None) -> Optional[bytes]:
        """Expand the default value pattern to the specified length."""
        if length is None:
            length = self._default_value_len()
        if length is None:
            raise ValueError("%s does not have a default length" % self)
        if not self.default_val:
            return None
        if not '...' in self.default_val:
            return h2b(self.default_val)
        l = self.default_val.split('...')
        if len(l) != 2:
            raise ValueError("Pattern '%s' contains more than one ..." % self.default_val)
        prefix = h2b(l[0])
        suffix = h2b(l[1])
        pad_len = length - len(prefix) - len(suffix)
        if pad_len <= 0:
            ret = prefix + suffix
            return ret[:length]
        return prefix + prefix[-1:] * pad_len + suffix


class ProfileTemplate:
    """Representation of a SimAlliance/TCA Profile Template.  Each Template is identified by its OID and
    consists of a number of file definitions.  We implement each profile template as a class derived from this
    base class.  Each such derived class is a singleton and has no instances."""
    created_by_default: bool = False
    optional: bool = False
    oid: Optional[OID.eOID] = None
    files: List[FileTemplate] = []

    # indicates that a given template does not have its own 'base DF', but that its contents merely
    # extends that of the 'base DF' of another template
    extends: Optional['ProfileTemplate'] = None

    # indicates a parent ProfileTemplate below whose 'base DF' our files should be placed.
    parent: Optional['ProfileTemplate'] = None

    def __init_subclass__(cls, **kwargs):
        """This classmethod is called automatically after executing the subclass body. We use it to
        initialize the cls.files_by_pename from the cls.files"""
        super().__init_subclass__(**kwargs)
        cur_df = None

        cls.files_by_pename: dict[str,FileTemplate] = {}
        cls.tree: List[FileTemplate] = []

        if not cls.optional and not cls.files[0].file_type in ['MF', 'DF', 'ADF']:
            raise ValueError('First file in non-optional template must be MF, DF or ADF (is: %s)' % cls.files[0])
        for f in cls.files:
            if f.file_type in ['MF', 'DF', 'ADF']:
                if cur_df == None:
                    cls.tree.append(f)
                    f.parent = None
                    cur_df = f
                else:
                    # "cd .."
                    if cur_df.parent:
                        cur_df = cur_df.parent
                    f.parent = cur_df
                    cur_df.children.append(f)
                    cur_df = f
            else:
                if cur_df == None:
                    cls.tree.append(f)
                    f.parent = None
                else:
                    cur_df.children.append(f)
                    f.parent = cur_df
            cls.files_by_pename[f.pe_name] = f
        ProfileTemplateRegistry.add(cls)

    @classmethod
    def print_tree(cls):
        for c in cls.tree:
            c.print_tree()

    @classmethod
    def base_df(cls) -> FileTemplate:
        """Return the FileTemplate for the base DF of the given template.  This may be a DF or ADF
        within this template, or refer to another template (e.g. mandatory USIM if we are optional USIM."""
        if cls.extends:
            return cls.extends.base_df
        return cls.files[0]

class ProfileTemplateRegistry:
    """A registry of profile templates.  Exists as a singleton class with no instances and only
    classmethods."""
    by_oid = {}

    @classmethod
    def add(cls, tpl: ProfileTemplate):
        """Add a ProfileTemplate to the registry.  There can only be one Template per OID."""
        oid_str = str(tpl.oid)
        if oid_str in cls.by_oid:
            raise ValueError("We already have a template for OID %s" % oid_str)
        cls.by_oid[oid_str] = tpl

    @classmethod
    def get_by_oid(cls, oid: Union[List[int], str]) -> Optional[ProfileTemplate]:
        """Look-up the ProfileTemplate based on its OID.  The OID can be given either in dotted-string format,
        or as a list of integers."""
        if not isinstance(oid, str):
            oid = OID.OID.str_from_intlist(oid)
        return cls.by_oid.get(oid, None)

# below are transcribed template definitions from "ANNEX A (Normative): File Structure Templates Definition"
# of "Profile interoperability specification V3.3.1 Final" (unless other version explicitly specified).

class FilesAtMF(ProfileTemplate):
    """Files at MF as per Section 9.2"""
    created_by_default = True
    oid = OID.MF
    files = [
        FileTemplate(0x3f00, 'MF',           'MF', None, None,  14, None, None, None, params=['pinStatusTemplateDO']),
        FileTemplate(0x2f05, 'EF.PL',        'TR', None,    2,   1, 0x05, 'FF...FF', None),
        FileTemplate(0x2f02, 'EF.ICCID',     'TR', None,   10,  11, None, None, True),
        FileTemplate(0x2f00, 'EF.DIR',       'LF', None, None,  10, 0x1e, None, True, params=['nb_rec', 'size']),
        FileTemplate(0x2f06, 'EF.ARR',       'LF', None, None,  10, None, None, True, params=['nb_rec', 'size']),
        FileTemplate(0x2f08, 'EF.UMPC',      'TR', None,    5,  10, 0x08, None, False),
    ]


class FilesCD(ProfileTemplate):
    """Files at DF.CD as per Section 9.3"""
    created_by_default = False
    oid = OID.DF_CD
    files = [
        FileTemplate(0x7f11, 'DF.CD',        'DF', None, None,  14, None, None, False, params=['pinStatusTemplateDO']),
        FileTemplate(0x6f01, 'EF.LAUNCHPAD', 'TR', None, None,   2, None, None, True, params=['size']),
    ]
    for i in range(0x40, 0x7f):
        files.append(FileTemplate(0x6f00+i, 'EF.ICON',      'TR', None, None,   2, None, None, True, params=['size']))


# Section 9.4: Do this separately, so we can use them also from 9.5.3
df_pb_files = [
    FileTemplate(0x5f3a, 'DF.PHONEBOOK', 'DF', None, None,  14, None, None, True, ['pinStatusTemplateDO']),
    FileTemplate(0x4f30, 'EF.PBR',       'LF', None, None,   2, None, None, True, ['nb_rec', 'size'], ppath=[0x5f3a]),
]
for i in range(0x38, 0x40):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.EXT1', 'LF', None,   13,  5, None, '00FF...FF', False, ['size','sfi'], ppath=[0x5f3a]))
for i in range(0x40, 0x48):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.AAS', 'LF', None, None,  5, None, 'FF...FF', False, ['nb_rec','size'], ppath=[0x5f3a]))
for i in range(0x48, 0x50):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.GAS', 'LF', None, None,  5, None, 'FF...FF', False, ['nb_rec','size'], ppath=[0x5f3a]))
df_pb_files += [
    FileTemplate(0x4f22, 'EF.PSC',       'TR', None,    4,   5, None, '00000000', False, ['sfi'], ppath=[0x5f3a]),
    FileTemplate(0x4f23, 'EF.CC',        'TR', None,    2,   5, None, '0000', False, ['sfi'], high_update=True, ppath=[0x5f3a]),
    FileTemplate(0x4f24, 'EF.PUID',      'TR', None,    2,   5, None, '0000', False, ['sfi'], high_update=True, ppath=[0x5f3a]),
]
for i in range(0x50, 0x58):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.IAP', 'LF', None, None,  5, None, 'FF...FF', False, ['nb_rec','size','sfi'], ppath=[0x5f3a]))
for i in range(0x58, 0x60):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.ADN', 'LF', None, None,  5, None, 'FF...FF', False, ['nb_rec','size','sfi'], ppath=[0x5f3a]))
for i in range(0x60, 0x68):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.ADN', 'LF', None,    2,  5, None, '00...00', False, ['nb_rec','sfi'], ppath=[0x5f3a]))
for i in range(0x68, 0x70):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.ANR', 'LF', None, None,  5, None, 'FF...FF', False, ['nb_rec','size','sfi'], ppath=[0x5f3a]))
for i in range(0x70, 0x78):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.PURI', 'LF', None, None,  5, None, None, True, ['nb_rec','size','sfi'], ppath=[0x5f3a]))
for i in range(0x78, 0x80):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.EMAIL', 'LF', None, None,  5, None, 'FF...FF', False, ['nb_rec','size','sfi'], ppath=[0x5f3a]))
for i in range(0x80, 0x88):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.SNE', 'LF', None, None,  5, None, 'FF...FF', False, ['nb_rec','size','sfi'], ppath=[0x5f3a]))
for i in range(0x88, 0x90):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.UID', 'LF', None,    2,  5, None, '0000', False, ['nb_rec','sfi'], ppath=[0x5f3a]))
for i in range(0x90, 0x98):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.GRP', 'LF', None, None,  5, None, '00...00', False, ['nb_rec','size','sfi'], ppath=[0x5f3a]))
for i in range(0x98, 0xa0):
    df_pb_files.append(FileTemplate(0x4f00+i, 'EF.CCP1', 'LF', None, None,  5, None, 'FF...FF', False, ['nb_rec','size','sfi'], ppath=[0x5f3a]))

class FilesTelecom(ProfileTemplate):
    """Files at DF.TELECOM as per Section 9.4 v2.3.1"""
    created_by_default = False
    oid = OID.DF_TELECOM
    base_path = Path('MF')
    files = [
        FileTemplate(0x7f10, 'DF.TELECOM',   'DF', None, None,  14, None, None, False, params=['pinStatusTemplateDO']),
        FileTemplate(0x6f06, 'EF.ARR',       'LF', None, None,  10, None, None, True, ['nb_rec', 'size']),
        FileTemplate(0x6f53, 'EF.RMA',       'LF', None, None,   3, None, None, True, ['nb_rec', 'size']),
        FileTemplate(0x6f54, 'EF.SUME',      'TR', None,   22,   3, None, None, True),
        FileTemplate(0x6fe0, 'EF.ICE_DN',    'LF',   50,   24,   9, None, 'FF...FF', False),
        FileTemplate(0x6fe1, 'EF.ICE_FF',    'LF', None, None,   9, None, 'FF...FF', False, ['nb_rec', 'size']),
        FileTemplate(0x6fe5, 'EF.PSISMSC',   'LF', None, None,   5, None, None, True, ['nb_rec', 'size'], ass_serv=[12,91]),
        FileTemplate(0x5f50, 'DF.GRAPHICS',  'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO']),
        FileTemplate(0x4f20, 'EF.IMG',       'LF', None, None,   2, None, '00FF...FF', False, ['nb_rec', 'size'], ppath=[0x5f50]),
        # EF.IIDF below
        FileTemplate(0x4f21, 'EF.ICE_GRAPHICS','BT',None,None,   9, None, None, False, ['size'], ppath=[0x5f50]),
        FileTemplate(0x4f01, 'EF.LAUNCH_SCWS','TR',None, None,  10, None, None, True, ['size'], ppath=[0x5f50]),
        # EF.ICON below
    ]
    for i in range(0x40, 0x80):
        files.append(FileTemplate(0x4f00+i, 'EF.IIDF', 'TR', None, None, 2, None, 'FF...FF', False, ['size'], ppath=[0x5f50]))
    for i in range(0x80, 0xC0):
        files.append(FileTemplate(0x4f00+i, 'EF.ICON', 'TR', None, None, 10, None, None, True, ['size'], ppath=[0x5f50]))

    # we copy the objects (instances) here as we also use them below from FilesUsimDfPhonebook
    df_pb = deepcopy(df_pb_files)
    files += df_pb

    files += [
        FileTemplate(0x5f3b, 'DF.MULTIMEDIA','DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv=[67]),
        FileTemplate(0x4f47, 'EF.MML',       'BT', None, None,   5, None, None, False, ['size'], ass_serv=[67], ppath=[0x5f3b]),
        FileTemplate(0x4f48, 'EF.MMDF',      'BT', None, None,   5, None, None, False, ['size'], ass_serv=[67], ppath=[0x5f3b]),

        FileTemplate(0x5f3c, 'DF.MMSS',      'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO']),
        FileTemplate(0x4f20, 'EF.MLPL',      'TR', None, None,   2, 0x01, None, True, ['size'], ppath=[0x5f3c]),
        FileTemplate(0x4f21, 'EF.MSPL',      'TR', None, None,   2, 0x02, None, True, ['size'], ppath=[0x5f3c]),
        FileTemplate(0x4f21, 'EF.MMSSMODE',  'TR', None,    1,   2, 0x03, None, True, ppath=[0x5f3c]),
    ]


class FilesTelecomV2(ProfileTemplate):
    """Files at DF.TELECOM as per Section 9.4"""
    created_by_default = False
    oid = OID.DF_TELECOM_v2
    base_path = Path('MF')
    files = [
        FileTemplate(0x7f10, 'DF.TELECOM',   'DF', None, None,  14, None, None, False, params=['pinStatusTemplateDO']),
        FileTemplate(0x6f06, 'EF.ARR',       'LF', None, None,  10, None, None, True, ['nb_rec', 'size']),
        FileTemplate(0x6f53, 'EF.RMA',       'LF', None, None,   3, None, None, True, ['nb_rec', 'size']),
        FileTemplate(0x6f54, 'EF.SUME',      'TR', None,   22,   3, None, None, True),
        FileTemplate(0x6fe0, 'EF.ICE_DN',    'LF',   50,   24,   9, None, 'FF...FF', False),
        FileTemplate(0x6fe1, 'EF.ICE_FF',    'LF', None, None,   9, None, 'FF...FF', False, ['nb_rec', 'size']),
        FileTemplate(0x6fe5, 'EF.PSISMSC',   'LF', None, None,   5, None, None, True, ['nb_rec', 'size'], ass_serv=[12,91]),
        FileTemplate(0x5f50, 'DF.GRAPHICS',  'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO']),
        FileTemplate(0x4f20, 'EF.IMG',       'LF', None, None,   2, None, '00FF...FF', False, ['nb_rec', 'size'], ppath=[0x5f50]),
        # EF.IIDF below
        FileTemplate(0x4f21, 'EF.ICE_GRRAPHICS','BT',None,None,   9, None, None, False, ['size'], ppath=[0x5f50]),
        FileTemplate(0x4f01, 'EF.LAUNCH_SCWS','TR',None, None,  10, None, None, True, ['size'], ppath=[0x5f50]),
        # EF.ICON below
    ]
    for i in range(0x40, 0x80):
        files.append(FileTemplate(0x4f00+i, 'EF.IIDF', 'TR', None, None, 2, None, 'FF...FF', False, ['size'], ppath=[0x5f50]))
    for i in range(0x80, 0xC0):
        files.append(FileTemplate(0x4f00+i, 'EF.ICON', 'TR', None, None, 10, None, None, True, ['size'],ppath=[0x5f50]))

    # we copy the objects (instances) here as we also use them below from FilesUsimDfPhonebook
    df_pb = deepcopy(df_pb_files)
    files += df_pb

    files += [
        FileTemplate(0x5f3b, 'DF.MULTIMEDIA','DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv=[67]),
        FileTemplate(0x4f47, 'EF.MML',       'BT', None, None,   5, None, None, False, ['size'], ass_serv=[67], ppath=[0x5f3b]),
        FileTemplate(0x4f48, 'EF.MMDF',      'BT', None, None,   5, None, None, False, ['size'], ass_serv=[67], ppath=[0x5f3b]),

        FileTemplate(0x5f3c, 'DF.MMSS',      'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO']),
        FileTemplate(0x4f20, 'EF.MLPL',      'TR', None, None,   2, 0x01, None, True, ['size'], ppath=[0x5f3c]),
        FileTemplate(0x4f21, 'EF.MSPL',      'TR', None, None,   2, 0x02, None, True, ['size'], ppath=[0x5f3c]),
        FileTemplate(0x4f21, 'EF.MMSSMODE',  'TR', None,    1,   2, 0x03, None, True, ppath=[0x5f3c]),

        FileTemplate(0x5f3d, 'DF.MCS',       'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv={'usim':109, 'isim': 15}),
        FileTemplate(0x4f01, 'EF.MST',       'TR', None, None,   2, 0x01, None, True, ['size'], ass_serv={'usim':109, 'isim': 15}, ppath=[0x5f3d]),
        FileTemplate(0x4f02, 'EF.MCSCONFIG', 'BT', None, None,   2, 0x02, None, True, ['size'], ass_serv={'usim':109, 'isim': 15}, ppath=[0x5f3d]),

        FileTemplate(0x5f3e, 'DF.V2X',       'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv=[119]),
        FileTemplate(0x4f01, 'EF.VST',       'TR', None, None,   2, 0x01, None, True, ['size'], ass_serv=[119], ppath=[0x5f3e]),
        FileTemplate(0x4f02, 'EF.V2X_CONFIG','BT', None, None,   2, 0x02, None, True, ['size'], ass_serv=[119], ppath=[0x5f3e]),
        FileTemplate(0x4f03, 'EF.V2XP_PC5',  'TR', None, None,   2, None, None, True, ['size'], ass_serv=[119], ppath=[0x5f3e]), # VST: 2
        FileTemplate(0x4f04, 'EF.V2XP_Uu',   'TR', None, None,   2, None, None, True, ['size'], ass_serv=[119], ppath=[0x5f3e]), # VST: 3
    ]


class FilesUsimMandatory(ProfileTemplate):
    """Mandatory Files at ADF.USIM as per Section 9.5.1 v2.3.1"""
    created_by_default = True
    oid = OID.ADF_USIM_by_default
    files = [
        FileTemplate(  None, 'ADF.USIM',    'ADF', None, None,  14, None, None, False, ['aid', 'temp_fid', 'pinStatusTemplateDO']),
        FileTemplate(0x6f07, 'EF.IMSI',      'TR', None,    9,   2, 0x07, None, True, ['size']),
        FileTemplate(0x6f06, 'EF.ARR',       'LF', None, None,  10, 0x17, None, True, ['nb_rec','size']),
        FileTemplate(0x6f08, 'EF.Keys',      'TR', None,   33,   5, 0x08, '07FF...FF', False, high_update=True),
        FileTemplate(0x6f09, 'EF.KeysPS',    'TR', None,   33,   5, 0x09, '07FF...FF', False, high_update=True, pe_name = 'ef-keysPS'),
        FileTemplate(0x6f31, 'EF.HPPLMN',    'TR', None,    1,   2, 0x12, '0A', False),
        FileTemplate(0x6f38, 'EF.UST',       'TR', None,   14,   2, 0x04, None, True),
        FileTemplate(0x6f3b, 'EF.FDN',       'LF',   20,   26,   8, None, 'FF...FF', False, ass_serv=[2, 89]),
        FileTemplate(0x6f3c, 'EF.SMS',       'LF',   10,  176,   5, None, '00FF...FF', False, ass_serv=[10]),
        FileTemplate(0x6f42, 'EF.SMSP',      'LF',    1,   38,   5, None, 'FF...FF', False, ass_serv=[12]),
        FileTemplate(0x6f43, 'EF.SMSS',      'TR', None,    2,   5, None, 'FFFF', False, ass_serv=[10]),
        FileTemplate(0x6f46, 'EF.SPN',       'TR', None,   17,  10, None, None, True, ass_serv=[19]),
        FileTemplate(0x6f56, 'EF.EST',       'TR', None,    1,   8, 0x05, None, True, ass_serv=[2,6,34,35]),
        FileTemplate(0x6f5b, 'EF.START-HFN', 'TR', None,    6,   5, 0x0f, 'F00000F00000', False, high_update=True),
        FileTemplate(0x6f5c, 'EF.THRESHOLD', 'TR', None,    3,   2, 0x10, 'FFFFFF', False),
        FileTemplate(0x6f73, 'EF.PSLOCI',    'TR', None,   14,   5, 0x0c, 'FFFFFFFFFFFFFFFFFFFF0000FF01', False, high_update=True),
        FileTemplate(0x6f78, 'EF.ACC',       'TR', None,    2,   2, 0x06, None, True),
        FileTemplate(0x6f7b, 'EF.FPLMN',     'TR', None,   12,   5, 0x0d, 'FF...FF', False),
        FileTemplate(0x6f7e, 'EF.LOCI',      'TR', None,   11,   5, 0x0b, 'FFFFFFFFFFFFFF0000FF01', False, high_update=True),
        FileTemplate(0x6fad, 'EF.AD',        'TR', None,    4,  10, 0x03, '00000002', False),
        FileTemplate(0x6fb7, 'EF.ECC',       'LF',    1,    4,  10, 0x01, None, True),
        FileTemplate(0x6fc4, 'EF.NETPAR',    'TR', None,  128,   5, None, 'FF...FF', False, high_update=True),
        FileTemplate(0x6fe3, 'EF.EPSLOCI',   'TR', None,   18,   5, 0x1e, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000001', False, ass_serv=[85], high_update=True),
        FileTemplate(0x6fe4, 'EF.EPSNSC',    'LF',    1,   80,   5, 0x18, 'FF...FF', False, ass_serv=[85], high_update=True),
    ]

class FilesUsimMandatoryV2(ProfileTemplate):
    """Mandatory Files at ADF.USIM as per Section 9.5.1"""
    created_by_default = True
    oid = OID.ADF_USIM_by_default_v2
    files = [
        FileTemplate(  None, 'ADF.USIM',    'ADF', None, None,  14, None, None, False, ['aid', 'temp_fid', 'pinStatusTemplateDO']),
        FileTemplate(0x6f07, 'EF.IMSI',      'TR', None,    9,   2, 0x07, None, True, ['size']),
        FileTemplate(0x6f06, 'EF.ARR',       'LF', None, None,  10, 0x17, None, True, ['nb_rec','size']),
        FileTemplate(0x6f08, 'EF.Keys',      'TR', None,   33,   5, 0x08, '07FF...FF', False, high_update=True),
        FileTemplate(0x6f09, 'EF.KeysPS',    'TR', None,   33,   5, 0x09, '07FF...FF', False, high_update=True, pe_name='ef-keysPS'),
        FileTemplate(0x6f31, 'EF.HPPLMN',    'TR', None,    1,   2, 0x12, '0A', False),
        FileTemplate(0x6f38, 'EF.UST',       'TR', None,   17,   2, 0x04, None, True),
        FileTemplate(0x6f3b, 'EF.FDN',       'LF',   20,   26,   8, None, 'FF...FF', False, ass_serv=[2, 89]),
        FileTemplate(0x6f3c, 'EF.SMS',       'LF',   10,  176,   5, None, '00FF...FF', False, ass_serv=[10]),
        FileTemplate(0x6f42, 'EF.SMSP',      'LF',    1,   38,   5, None, 'FF...FF', False, ass_serv=[12]),
        FileTemplate(0x6f43, 'EF.SMSS',      'TR', None,    2,   5, None, 'FFFF', False, ass_serv=[10]),
        FileTemplate(0x6f46, 'EF.SPN',       'TR', None,   17,  10, None, None, True, ass_serv=[19]),
        FileTemplate(0x6f56, 'EF.EST',       'TR', None,    1,   8, 0x05, None, True, ass_serv=[2,6,34,35]),
        FileTemplate(0x6f5b, 'EF.START-HFN', 'TR', None,    6,   5, 0x0f, 'F00000F00000', False, high_update=True),
        FileTemplate(0x6f5c, 'EF.THRESHOLD', 'TR', None,    3,   2, 0x10, 'FFFFFF', False),
        FileTemplate(0x6f73, 'EF.PSLOCI',    'TR', None,   14,   5, 0x0c, 'FFFFFFFFFFFFFFFFFFFF0000FF01', False, high_update=True),
        FileTemplate(0x6f78, 'EF.ACC',       'TR', None,    2,   2, 0x06, None, True),
        FileTemplate(0x6f7b, 'EF.FPLMN',     'TR', None,   12,   5, 0x0d, 'FF...FF', False),
        FileTemplate(0x6f7e, 'EF.LOCI',      'TR', None,   11,   5, 0x0b, 'FFFFFFFFFFFFFF0000FF01', False, high_update=True),
        FileTemplate(0x6fad, 'EF.AD',        'TR', None,    4,  10, 0x03, '00000002', False),
        FileTemplate(0x6fb7, 'EF.ECC',       'LF',    1,    4,  10, 0x01, None, True),
        FileTemplate(0x6fc4, 'EF.NETPAR',    'TR', None,  128,   5, None, 'FF...FF', False, high_update=True),
        FileTemplate(0x6fe3, 'EF.EPSLOCI',   'TR', None,   18,   5, 0x1e, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000001', False, ass_serv=[85], high_update=True),
        FileTemplate(0x6fe4, 'EF.EPSNSC',    'LF',    1,   80,   5, 0x18, 'FF...FF', False, ass_serv=[85], high_update=True),
    ]


class FilesUsimOptional(ProfileTemplate):
    """Optional Files at ADF.USIM as per Section 9.5.2 v2.3.1"""
    created_by_default = False
    optional = True
    oid = OID.ADF_USIMopt_not_by_default
    base_path = Path('ADF.USIM')
    extends = FilesUsimMandatory
    files = [
        FileTemplate(0x6f05, 'EF.LI',        'TR', None,    6,   1, 0x02, 'FF...FF', False),
        FileTemplate(0x6f37, 'EF.ACMmax',    'TR', None,    3,   5, None, '000000', False, ass_serv=[13], pe_name='ef-acmax'),
        FileTemplate(0x6f39, 'EF.ACM',       'CY',    1,    3,   7, None, '000000', False, ass_serv=[13], high_update=True),
        FileTemplate(0x6f3e, 'EF.GID1',      'TR', None,    8,   2, None, None, True, ass_serv=[17]),
        FileTemplate(0x6f3f, 'EF.GID2',      'TR', None,    8,   2, None, None, True, ass_serv=[18]),
        FileTemplate(0x6f40, 'EF.MSISDN',    'LF',    1,   24,   2, None, 'FF...FF', False, ass_serv=[21]),
        FileTemplate(0x6f41, 'EF.PUCT',      'TR', None,    5,   5, None, 'FFFFFF0000', False, ass_serv=[13]),
        FileTemplate(0x6f45, 'EF.CBMI',      'TR', None,   10,   5, None, 'FF...FF', False, ass_serv=[15]),
        FileTemplate(0x6f48, 'EF.CBMID',     'TR', None,   10,   2, 0x0e, 'FF...FF', False, ass_serv=[19]),
        FileTemplate(0x6f49, 'EF.SDN',       'LF',   10,   24,   2, None, 'FF...FF', False, ass_serv=[4,89]),
        FileTemplate(0x6f4b, 'EF.EXT2',      'LF',   10,   13,   8, None, '00FF...FF', False, ass_serv=[3]),
        FileTemplate(0x6f4c, 'EF.EXT3',      'LF',   10,   13,   2, None, '00FF...FF', False, ass_serv=[5]),
        FileTemplate(0x6f50, 'EF.CBMIR',     'TR', None,   20,   5, None, 'FF...FF', False, ass_serv=[16]),
        FileTemplate(0x6f60, 'EF.PLMNwAcT',  'TR', None,   40,   5, 0x0a, 'FFFFFF0000', False, ass_serv=[20], repeat=True),
        FileTemplate(0x6f61, 'EF.OPLMNwAcT', 'TR', None,   40,   2, 0x11, 'FFFFFF0000', False, ass_serv=[42], repeat=True),
        FileTemplate(0x6f62, 'EF.HPLMNwAcT', 'TR', None,    5,   2, 0x13, 'FFFFFF0000', False, ass_serv=[43], repeat=True),
        FileTemplate(0x6f2c, 'EF.DCK',       'TR', None,   16,   5, None, 'FF...FF', False, ass_serv=[36]),
        FileTemplate(0x6f32, 'EF.CNL',       'TR', None,   30,   2, None, 'FF...FF', False, ass_serv=[37]),
        FileTemplate(0x6f47, 'EF.SMSR',      'LF',   10,   30,   5, None, '00FF...FF', False, ass_serv=[11]),
        FileTemplate(0x6f4d, 'EF.BDN',       'LF',   10,   25,   8, None, 'FF...FF', False, ass_serv=[6]),
        FileTemplate(0x6f4e, 'EF.EXT5',      'LF',   10,   13,   5, None, '00FF...FF', False, ass_serv=[44]),
        FileTemplate(0x6f4f, 'EF.CCP2',      'LF',    5,   15,   5, 0x16, 'FF...FF', False, ass_serv=[14]),
        FileTemplate(0x6f55, 'EF.EXT4',      'LF',   10,   13,   8, None, '00FF...FF', False, ass_serv=[7]),
        FileTemplate(0x6f57, 'EF.ACL',       'TR', None,  101,   8, None, '00FF...FF', False, ass_serv=[35]),
        FileTemplate(0x6f58, 'EF.CMI',       'LF',   10,   11,   2, None, 'FF...FF', False, ass_serv=[6]),
        FileTemplate(0x6f80, 'EF.ICI',       'CY',   20,   38,   5, 0x14, 'FF...FF0000000001FFFF', False, ass_serv=[9], high_update=True),
        FileTemplate(0x6f81, 'EF.OCI',       'CY',   20,   37,   5, 0x15, 'FF...FF00000001FFFF', False, ass_serv=[8], high_update=True),
        FileTemplate(0x6f82, 'EF.ICT',       'CY',    1,    3,   7, None, '000000', False, ass_serv=[9], high_update=True),
        FileTemplate(0x6f83, 'EF.OCT',       'CY',    1,    3,   7, None, '000000', False, ass_serv=[8], high_update=True),
        FileTemplate(0x6fb1, 'EF.VGCS',      'TR', None,   20,   2, None, None, True, ass_serv=[57]),
        FileTemplate(0x6fb2, 'EF.VGCSS',     'TR', None,    7,   5, None, None, True, ass_serv=[57]),
        FileTemplate(0x6fb3, 'EF.VBS',       'TR', None,   20,   2, None, None, True, ass_serv=[58]),
        FileTemplate(0x6fb4, 'EF.VBSS',      'TR', None,    7,   5, None, None, True, ass_serv=[58]), # ARR 2!??
        FileTemplate(0x6fb5, 'EF.eMLPP',     'TR', None,    2,   2, None, None, True, ass_serv=[24]),
        FileTemplate(0x6fb6, 'EF.AaeM',      'TR', None,    1,   5, None, '00', False, ass_serv=[25]),
        FileTemplate(0x6fc3, 'EF.HiddenKey', 'TR', None,    4,   5, None, 'FF...FF', False),
        FileTemplate(0x6fc5, 'EF.PNN',       'LF',   10,   16,  10, 0x19, None, True, ass_serv=[45]),
        FileTemplate(0x6fc6, 'EF.OPL',       'LF',    5,    8,  10, 0x1a, None, True, ass_serv=[46]),
        FileTemplate(0x6fc7, 'EF.MBDN',      'LF',    3,   24,   5, None, None, True, ass_serv=[47]),
        FileTemplate(0x6fc8, 'EF.EXT6',      'LF',   10,   13,   5, None, '00FF...FF', False, ass_serv=[47]),
        FileTemplate(0x6fc9, 'EF.MBI',       'LF',   10,    5,   5, None, None, True, ass_serv=[47]),
        FileTemplate(0x6fca, 'EF.MWIS',      'LF',   10,    6,   5, None, '00...00', False, ass_serv=[48], high_update=True),
        FileTemplate(0x6fcb, 'EF.CFIS',      'LF',   10,   16,   5, None, '0100FF...FF', False, ass_serv=[49]),
        FileTemplate(0x6fcb, 'EF.EXT7',      'LF',   10,   13,   5, None, '00FF...FF', False, ass_serv=[49]),
        FileTemplate(0x6fcd, 'EF.SPDI',      'TR', None,   17,   2, 0x1b, None, True, ass_serv=[51]),
        FileTemplate(0x6fce, 'EF.MMSN',      'LF',   10,    6,   5, None, '000000FF...FF', False, ass_serv=[52]),
        FileTemplate(0x6fcf, 'EF.EXT8',      'LF',   10,   13,   5, None, '00FF...FF', False, ass_serv=[53]),
        FileTemplate(0x6fd0, 'EF.MMSICP',    'TR', None,  100,   2, None, 'FF...FF', False, ass_serv=[52]),
        FileTemplate(0x6fd1, 'EF.MMSUP',     'LF', None, None,   5, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[52]),
        FileTemplate(0x6fd2, 'EF.MMSUCP',    'TR', None,  100,   5, None, 'FF...FF', False, ass_serv=[52,55]),
        FileTemplate(0x6fd3, 'EF.NIA',       'LF',    5,   11,   2, None, 'FF...FF', False, ass_serv=[56]),
        FileTemplate(0x6fd4, 'EF.VGCSCA',    'TR', None, None,   2, None, '00...00', False, ['size'], ass_serv=[64]),
        FileTemplate(0x6fd5, 'EF.VBSCA',     'TR', None, None,   2, None, '00...00', False, ['size'], ass_serv=[65]),
        FileTemplate(0x6fd6, 'EF.GBABP',     'TR', None, None,   5, None, 'FF...FF', False, ['size'], ass_serv=[68]),
        FileTemplate(0x6fd7, 'EF.MSK',       'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[69], high_update=True),
        FileTemplate(0x6fd8, 'EF.MUK',       'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[69]),
        FileTemplate(0x6fd9, 'EF.EHPLMN',    'TR', None,   15,   2, 0x1d, 'FF...FF', False, ass_serv=[71]),
        FileTemplate(0x6fda, 'EF.GBANL',     'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[68]),
        FileTemplate(0x6fdb, 'EF.EHPLMNPI',  'TR', None,    1,   2, None, '00', False, ass_serv=[71,73]),
        FileTemplate(0x6fdc, 'EF.LRPLMNSI',  'TR', None,    1,   2, None, '00', False, ass_serv=[74]),
        FileTemplate(0x6fdd, 'EF.NAFKCA',    'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[68,76]),
        FileTemplate(0x6fde, 'EF.SPNI',      'TR', None, None,  10, None, '00FF...FF', False, ['size'], ass_serv=[78]),
        FileTemplate(0x6fdf, 'EF.PNNI',      'LF', None, None,  10, None, '00FF...FF', False, ['nb_rec','size'], ass_serv=[79]),
        FileTemplate(0x6fe2, 'EF.NCP-IP',    'LF', None, None,   2, None, None, True, ['nb_rec','size'], ass_serv=[80]),
        FileTemplate(0x6fe6, 'EF.UFC',       'TR', None,   30,  10, None, '801E60C01E900080040000000000000000F0000000004000000000000080', False),
        FileTemplate(0x6fe8, 'EF.NASCONFIG', 'TR', None,   18,   2, None, None, True, ass_serv=[96]),
        FileTemplate(0x6fe7, 'EF.UICCIARI',  'LF', None, None,   2, None, None, True, ['nb_rec','size'], ass_serv=[95]),
        FileTemplate(0x6fec, 'EF.PWS',       'TR', None, None,  10, None, None, True, ['size'], ass_serv=[97]),
        FileTemplate(0x6fed, 'EF.FDNURI',    'LF', None, None,   8, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[2,99]),
        FileTemplate(0x6fee, 'EF.BDNURI',    'LF', None, None,   8, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[6,99]),
        FileTemplate(0x6fef, 'EF.SDNURI',    'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[4,99]),
        FileTemplate(0x6ff0, 'EF.IWL',       'LF', None, None,   3, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[102]),
        FileTemplate(0x6ff1, 'EF.IPS',       'CY', None,    4,  10, None, 'FF...FF', False, ['size'], ass_serv=[102], high_update=True),
        FileTemplate(0x6ff2, 'EF.IPD',       'LF', None, None,   3, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[102], high_update=True),
    ]


# Section 9.5.2
class FilesUsimOptionalV2(ProfileTemplate):
    """Optional Files at ADF.USIM as per Section 9.5.2"""
    created_by_default = False
    optional = True
    oid = OID.ADF_USIMopt_not_by_default_v2
    base_path = Path('ADF.USIM')
    extends = FilesUsimMandatoryV2
    files = [
        FileTemplate(0x6f05, 'EF.LI',        'TR', None,    6,   1, 0x02, 'FF...FF', False),
        FileTemplate(0x6f37, 'EF.ACMmax',    'TR', None,    3,   5, None, '000000', False, ass_serv=[13]),
        FileTemplate(0x6f39, 'EF.ACM',       'CY',    1,    3,   7, None, '000000', False, ass_serv=[13], high_update=True),
        FileTemplate(0x6f3e, 'EF.GID1',      'TR', None,    8,   2, None, None, True, ass_serv=[17]),
        FileTemplate(0x6f3f, 'EF.GID2',      'TR', None,    8,   2, None, None, True, ass_serv=[18]),
        FileTemplate(0x6f40, 'EF.MSISDN',    'LF',    1,   24,   2, None, 'FF...FF', False, ass_serv=[21]),
        FileTemplate(0x6f41, 'EF.PUCT',      'TR', None,    5,   5, None, 'FFFFFF0000', False, ass_serv=[13]),
        FileTemplate(0x6f45, 'EF.CBMI',      'TR', None,   10,   5, None, 'FF...FF', False, ass_serv=[15]),
        FileTemplate(0x6f48, 'EF.CBMID',     'TR', None,   10,   2, 0x0e, 'FF...FF', False, ass_serv=[19]),
        FileTemplate(0x6f49, 'EF.SDN',       'LF',   10,   24,   2, None, 'FF...FF', False, ass_serv=[4,89]),
        FileTemplate(0x6f4b, 'EF.EXT2',      'LF',   10,   13,   8, None, '00FF...FF', False, ass_serv=[3]),
        FileTemplate(0x6f4c, 'EF.EXT3',      'LF',   10,   13,   2, None, '00FF...FF', False, ass_serv=[5]),
        FileTemplate(0x6f50, 'EF.CBMIR',     'TR', None,   20,   5, None, 'FF...FF', False, ass_serv=[16]),
        FileTemplate(0x6f60, 'EF.PLMNwAcT',  'TR', None,   40,   5, 0x0a, 'FFFFFF0000'*8, False, ass_serv=[20]),
        FileTemplate(0x6f61, 'EF.OPLMNwAcT', 'TR', None,   40,   2, 0x11, 'FFFFFF0000'*8, False, ass_serv=[42]),
        FileTemplate(0x6f62, 'EF.HPLMNwAcT', 'TR', None,    5,   2, 0x13, 'FFFFFF0000', False, ass_serv=[43]),
        FileTemplate(0x6f2c, 'EF.DCK',       'TR', None,   16,   5, None, 'FF...FF', False, ass_serv=[36]),
        FileTemplate(0x6f32, 'EF.CNL',       'TR', None,   30,   2, None, 'FF...FF', False, ass_serv=[37]),
        FileTemplate(0x6f47, 'EF.SMSR',      'LF',   10,   30,   5, None, '00FF...FF', False, ass_serv=[11]),
        FileTemplate(0x6f4d, 'EF.BDN',       'LF',   10,   25,   8, None, 'FF...FF', False, ass_serv=[6]),
        FileTemplate(0x6f4e, 'EF.EXT5',      'LF',   10,   13,   5, None, '00FF...FF', False, ass_serv=[44]),
        FileTemplate(0x6f4f, 'EF.CCP2',      'LF',    5,   15,   5, 0x16, 'FF...FF', False, ass_serv=[14]),
        FileTemplate(0x6f55, 'EF.EXT4',      'LF',   10,   13,   8, None, '00FF...FF', False, ass_serv=[7]),
        FileTemplate(0x6f57, 'EF.ACL',       'TR', None,  101,   8, None, '00FF...FF', False, ass_serv=[35]),
        FileTemplate(0x6f58, 'EF.CMI',       'LF',   10,   11,   2, None, 'FF...FF', False, ass_serv=[6]),
        FileTemplate(0x6f80, 'EF.ICI',       'CY',   20,   38,   5, 0x14, 'FF...FF0000000001FFFF', False, ass_serv=[9], high_update=True),
        FileTemplate(0x6f81, 'EF.OCI',       'CY',   20,   37,   5, 0x15, 'FF...FF00000001FFFF', False, ass_serv=[8], high_update=True),
        FileTemplate(0x6f82, 'EF.ICT',       'CY',    1,    3,   7, None, '000000', False, ass_serv=[9], high_update=True),
        FileTemplate(0x6f83, 'EF.OCT',       'CY',    1,    3,   7, None, '000000', False, ass_serv=[8], high_update=True),
        FileTemplate(0x6fb1, 'EF.VGCS',      'TR', None,   20,   2, None, None, True, ass_serv=[57]),
        FileTemplate(0x6fb2, 'EF.VGCSS',     'TR', None,    7,   5, None, None, True, ass_serv=[57]),
        FileTemplate(0x6fb3, 'EF.VBS',       'TR', None,   20,   2, None, None, True, ass_serv=[58]),
        FileTemplate(0x6fb4, 'EF.VBSS',      'TR', None,    7,   5, None, None, True, ass_serv=[58]), # ARR 2!??
        FileTemplate(0x6fb5, 'EF.eMLPP',     'TR', None,    2,   2, None, None, True, ass_serv=[24]),
        FileTemplate(0x6fb6, 'EF.AaeM',      'TR', None,    1,   5, None, '00', False, ass_serv=[25]),
        FileTemplate(0x6fc3, 'EF.HiddenKey', 'TR', None,    4,   5, None, 'FF...FF', False),
        FileTemplate(0x6fc5, 'EF.PNN',       'LF',   10,   16,  10, 0x19, None, True, ass_serv=[45]),
        FileTemplate(0x6fc6, 'EF.OPL',       'LF',    5,    8,  10, 0x1a, None, True, ass_serv=[46]),
        FileTemplate(0x6fc7, 'EF.MBDN',      'LF',    3,   24,   5, None, None, True, ass_serv=[47]),
        FileTemplate(0x6fc8, 'EF.EXT6',      'LF',   10,   13,   5, None, '00FF...FF', False, ass_serv=[47]),
        FileTemplate(0x6fc9, 'EF.MBI',       'LF',   10,    5,   5, None, None, True, ass_serv=[47]),
        FileTemplate(0x6fca, 'EF.MWIS',      'LF',   10,    6,   5, None, '00...00', False, ass_serv=[48], high_update=True),
        FileTemplate(0x6fcb, 'EF.CFIS',      'LF',   10,   16,   5, None, '0100FF...FF', False, ass_serv=[49]),
        FileTemplate(0x6fcb, 'EF.EXT7',      'LF',   10,   13,   5, None, '00FF...FF', False, ass_serv=[49]),
        FileTemplate(0x6fcd, 'EF.SPDI',      'TR', None,   17,   2, 0x1b, None, True, ass_serv=[51]),
        FileTemplate(0x6fce, 'EF.MMSN',      'LF',   10,    6,   5, None, '000000FF...FF', False, ass_serv=[52]),
        FileTemplate(0x6fcf, 'EF.EXT8',      'LF',   10,   13,   5, None, '00FF...FF', False, ass_serv=[53]),
        FileTemplate(0x6fd0, 'EF.MMSICP',    'TR', None,  100,   2, None, 'FF...FF', False, ass_serv=[52]),
        FileTemplate(0x6fd1, 'EF.MMSUP',     'LF', None, None,   5, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[52]),
        FileTemplate(0x6fd2, 'EF.MMSUCP',    'TR', None,  100,   5, None, 'FF...FF', False, ass_serv=[52,55]),
        FileTemplate(0x6fd3, 'EF.NIA',       'LF',    5,   11,   2, None, 'FF...FF', False, ass_serv=[56]),
        FileTemplate(0x6fd4, 'EF.VGCSCA',    'TR', None, None,   2, None, '00...00', False, ['size'], ass_serv=[64]),
        FileTemplate(0x6fd5, 'EF.VBSCA',     'TR', None, None,   2, None, '00...00', False, ['size'], ass_serv=[65]),
        FileTemplate(0x6fd6, 'EF.GBABP',     'TR', None, None,   5, None, 'FF...FF', False, ['size'], ass_serv=[68]),
        FileTemplate(0x6fd7, 'EF.MSK',       'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[69], high_update=True),
        FileTemplate(0x6fd8, 'EF.MUK',       'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[69]),
        FileTemplate(0x6fd9, 'EF.EHPLMN',    'TR', None,   15,   2, 0x1d, 'FF...FF', False, ass_serv=[71]),
        FileTemplate(0x6fda, 'EF.GBANL',     'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[68]),
        FileTemplate(0x6fdb, 'EF.EHPLMNPI',  'TR', None,    1,   2, None, '00', False, ass_serv=[71,73]),
        FileTemplate(0x6fdc, 'EF.LRPLMNSI',  'TR', None,    1,   2, None, '00', False, ass_serv=[74]),
        FileTemplate(0x6fdd, 'EF.NAFKCA',    'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[68,76]),
        FileTemplate(0x6fde, 'EF.SPNI',      'TR', None, None,  10, None, '00FF...FF', False, ['size'], ass_serv=[78]),
        FileTemplate(0x6fdf, 'EF.PNNI',      'LF', None, None,  10, None, '00FF...FF', False, ['nb_rec','size'], ass_serv=[79]),
        FileTemplate(0x6fe2, 'EF.NCP-IP',    'LF', None, None,   2, None, None, True, ['nb_rec','size'], ass_serv=[80]),
        FileTemplate(0x6fe6, 'EF.UFC',       'TR', None,   30,  10, None, '801E60C01E900080040000000000000000F0000000004000000000000080', False),
        FileTemplate(0x6fe8, 'EF.NASCONFIG', 'TR', None,   18,   2, None, None, True, ass_serv=[96]),
        FileTemplate(0x6fe7, 'EF.UICCIARI',  'LF', None, None,   2, None, None, True, ['nb_rec','size'], ass_serv=[95]),
        FileTemplate(0x6fec, 'EF.PWS',       'TR', None, None,  10, None, None, True, ['size'], ass_serv=[97]),
        FileTemplate(0x6fed, 'EF.FDNURI',    'LF', None, None,   8, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[2,99]),
        FileTemplate(0x6fee, 'EF.BDNURI',    'LF', None, None,   8, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[6,99]),
        FileTemplate(0x6fef, 'EF.SDNURI',    'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[4,99]),
        FileTemplate(0x6ff0, 'EF.IWL',       'LF', None, None,   3, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[102]),
        FileTemplate(0x6ff1, 'EF.IPS',       'CY', None,    4,  10, None, 'FF...FF', False, ['size'], ass_serv=[102], high_update=True),
        FileTemplate(0x6ff2, 'EF.IPD',       'LF', None, None,   3, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[102], high_update=True),
        FileTemplate(0x6ff3, 'EF.EPDGID',    'TR', None, None,   2, None, None, True, ['size'], ass_serv=[(106, 107)]),
        FileTemplate(0x6ff4, 'EF.EPDGSELECTION','TR',None,None,  2, None, None, True, ['size'], ass_serv=[(106, 107)]),
        FileTemplate(0x6ff5, 'EF.EPDGIDEM',  'TR', None, None,   2, None, None, True, ['size'], ass_serv=[(110, 111)]),
        FileTemplate(0x6ff6, 'EF.EPDGIDEMSEL','TR',None, None,   2, None, None, True, ['size'], ass_serv=[(110, 111)]),
        FileTemplate(0x6ff7, 'EF.FromPreferred','TR',None,  1,   2, None, '00', False, ass_serv=[114]),
        FileTemplate(0x6ff8, 'EF.IMSConfigData','BT',None,None,  2, None, None, True, ['size'], ass_serv=[115]),
        FileTemplate(0x6ff9, 'EF.3GPPPSDataOff','TR',None,  4,   2, None, None, True, ass_serv=[117]),
        FileTemplate(0x6ffa, 'EF.3GPPPSDOSLIST','LF',None, None, 2, None, None, True, ['nb_rec','size'], ass_serv=[118]),
        FileTemplate(0x6ffc, 'EF.XCAPConfigData','BT',None,None, 2, None, None, True, ['size'], ass_serv=[120]),
        FileTemplate(0x6ffd, 'EF.EARFCNLIST','TR', None, None,  10, None, None, True, ['size'], ass_serv=[121]),
        FileTemplate(0x6ffd, 'EF.MudMidCfgdata','BT', None, None,2, None, None, True, ['size'], ass_serv=[134]),
    ]

class FilesUsimOptionalV3(ProfileTemplate):
    """Optional Files at ADF.USIM as per Section 9.5.2.3 v3.3.1"""
    created_by_default = False
    optional = True
    oid = OID.ADF_USIMopt_not_by_default_v3
    base_path = Path('ADF.USIM')
    extends = FilesUsimMandatoryV2
    files = FilesUsimOptionalV2.files + [
        FileTemplate(0x6f01, 'EF.eAKA', 'TR', None, 1, 3, None, None, True, ['size'], ass_serv=[134]),
    ]

class FilesUsimDfPhonebook(ProfileTemplate):
    """DF.PHONEBOOK Files at ADF.USIM as per Section 9.5.3"""
    created_by_default = False
    oid = OID.DF_PHONEBOOK_ADF_USIM
    base_path = Path('ADF.USIM')
    files = df_pb_files


class FilesUsimDfGsmAccess(ProfileTemplate):
    """DF.GSM-ACCESS Files at ADF.USIM as per Section 9.5.4"""
    created_by_default = False
    oid = OID.DF_GSM_ACCESS_ADF_USIM
    base_path = Path('ADF.USIM')
    parent = FilesUsimMandatory
    files = [
        FileTemplate(0x5f3b, 'DF.GSM-ACCESS','DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv=[27]),
        FileTemplate(0x4f20, 'EF.Kc',        'TR', None,    9,   5, 0x01, 'FF...FF07', False, ass_serv=[27], high_update=True),
        FileTemplate(0x4f52, 'EF.KcGPRS',    'TR', None,    9,   5, 0x02, 'FF...FF07', False, ass_serv=[27], high_update=True),
        FileTemplate(0x4f63, 'EF.CPBCCH',    'TR', None,   10,   5, None, 'FF...FF', False, ass_serv=[39], high_update=True),
        FileTemplate(0x4f64, 'EF.InvScan',   'TR', None,    1,   2, None, '00', False, ass_serv=[40]),
    ]


class FilesUsimDf5GS(ProfileTemplate):
    """DF.5GS Files at ADF.USIM as per Section 9.5.11 v2.3.1"""
    created_by_default = False
    oid = OID.DF_5GS
    base_path = Path('ADF.USIM')
    parent = FilesUsimMandatory
    files = [
        FileTemplate(0x6fc0, 'DF.5GS',               'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv=[122,126,127,128,129,130], pe_name='df-df-5gs'),
        FileTemplate(0x4f01, 'EF.5GS3GPPLOCI',       'TR', None,   20,   5, 0x01, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f02, 'EF.5GSN3GPPLOCI',      'TR', None,   20,   5, 0x02, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f03, 'EF.5GS3GPPNSC',        'LF',    1,   57,   5, 0x03, 'FF...FF', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f04, 'EF.5GSN3GPPNSC',       'LF',    1,   57,   5, 0x04, 'FF...FF', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f05, 'EF.5GAUTHKEYS',        'TR', None,  110,   5, 0x05, None, True, ass_serv=[123], high_update=True),
        FileTemplate(0x4f06, 'EF.UAC_AIC',           'TR', None,    4,   2, 0x06, None, True, ass_serv=[126]),
        FileTemplate(0x4f07, 'EF.SUCI_Calc_Info',    'TR', None, None,   2, 0x07, 'FF...FF', False, ass_serv=[124]),
        FileTemplate(0x4f08, 'EF.OPL5G',             'LF', None,   10,  10, 0x08, 'FF...FF', False, ['nb_rec'], ass_serv=[129]),
        FileTemplate(0x4f09, 'EF.SUPI_NAI',          'TR', None, None,   2, 0x09, None, True, ['size'], ass_serv=[130]),
        FileTemplate(0x4f0a, 'EF.Routing_Indicator', 'TR', None,    4,   2, 0x0a, 'F0FFFFFF', False, ass_serv=[124]),
    ]


class FilesUsimDf5GSv2(ProfileTemplate):
    """DF.5GS Files at ADF.USIM as per Section 9.5.11.2"""
    created_by_default = False
    oid = OID.DF_5GS_v2
    base_path = Path('ADF.USIM')
    parent = FilesUsimMandatory
    files = [
        FileTemplate(0x6fc0, 'DF.5GS',               'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv=[122,126,127,128,129,130], pe_name='df-df-5gs'),
        FileTemplate(0x4f01, 'EF.5GS3GPPLOCI',       'TR', None,   20,   5, 0x01, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f02, 'EF.5GSN3GPPLOCI',      'TR', None,   20,   5, 0x02, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f03, 'EF.5GS3GPPNSC',        'LF',    1,   57,   5, 0x03, 'FF...FF', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f04, 'EF.5GSN3GPPNSC',       'LF',    1,   57,   5, 0x04, 'FF...FF', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f05, 'EF.5GAUTHKEYS',        'TR', None,  110,   5, 0x05, None, True, ass_serv=[123], high_update=True),
        FileTemplate(0x4f06, 'EF.UAC_AIC',           'TR', None,    4,   2, 0x06, None, True, ass_serv=[126]),
        FileTemplate(0x4f07, 'EF.SUCI_Calc_Info',    'TR', None, None,   2, 0x07, 'FF...FF', False, ass_serv=[124]),
        FileTemplate(0x4f08, 'EF.OPL5G',             'LF', None,   10,  10, 0x08, 'FF...FF', False, ['nb_rec'], ass_serv=[129]),
        FileTemplate(0x4f09, 'EF.SUPI_NAI',          'TR', None, None,   2, 0x09, None, True, ['size'], ass_serv=[130]),
        FileTemplate(0x4f0a, 'EF.Routing_Indicator', 'TR', None,    4,   2, 0x0a, 'F0FFFFFF', False, ass_serv=[124]),
        FileTemplate(0x4f0b, 'EF.URSP',              'BT', None, None,   2, None, None, False, ass_serv=[132]),
        FileTemplate(0x4f0c, 'EF.TN3GPPSNN',         'TR', None,    1,   2, 0x0c, '00', False, ass_serv=[135]),
    ]


class FilesUsimDf5GSv3(ProfileTemplate):
    """DF.5GS Files at ADF.USIM as per Section 9.5.11.3"""
    created_by_default = False
    oid = OID.DF_5GS_v3
    base_path = Path('ADF.USIM')
    parent = FilesUsimMandatory
    files = [
        FileTemplate(0x6fc0, 'DF.5GS',               'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv=[122,126,127,128,129,130], pe_name='df-df-5gs'),
        FileTemplate(0x4f01, 'EF.5GS3GPPLOCI',       'TR', None,   20,   5, 0x01, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f02, 'EF.5GSN3GPPLOCI',      'TR', None,   20,   5, 0x02, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f03, 'EF.5GS3GPPNSC',        'LF',    2,   62,   5, 0x03, 'FF...FF', False, ass_serv=[122,136], high_update=True),
        # ^ If Service n°136 is not "available" in EF UST, the Profile Creator shall ensure that these files shall contain one record; otherwise, they shall contain 2 records.
        FileTemplate(0x4f04, 'EF.5GSN3GPPNSC',       'LF',    2,   62,   5, 0x04, 'FF...FF', False, ass_serv=[122,136], high_update=True),
        # ^ If Service n°136 is not "available" in EF UST, the Profile Creator shall ensure that these files shall contain one record; otherwise, they shall contain 2 records.
        FileTemplate(0x4f05, 'EF.5GAUTHKEYS',        'TR', None,  110,   5, 0x05, None, True, ass_serv=[123], high_update=True),
        FileTemplate(0x4f06, 'EF.UAC_AIC',           'TR', None,    4,   2, 0x06, None, True, ass_serv=[126]),
        FileTemplate(0x4f07, 'EF.SUCI_Calc_Info',    'TR', None, None,   2, 0x07, 'FF...FF', False, ass_serv=[124]),
        FileTemplate(0x4f08, 'EF.OPL5G',             'LF', None,   10,  10, 0x08, 'FF...FF', False, ['nb_rec'], ass_serv=[129]),
        FileTemplate(0x4f09, 'EF.SUPI_NAI',          'TR', None, None,   2, 0x09, None, True, ['size'], ass_serv=[130], pe_name='ef-supinai'),
        FileTemplate(0x4f0a, 'EF.Routing_Indicator', 'TR', None,    4,   2, 0x0a, 'F0FFFFFF', False, ass_serv=[124]),
        FileTemplate(0x4f0b, 'EF.URSP',              'BT', None, None,   2, None, None, False, ass_serv=[132]),
        FileTemplate(0x4f0c, 'EF.TN3GPPSNN',         'TR', None,    1,   2, 0x0c, '00', False, ass_serv=[135]),
    ]

class FilesUsimDf5GSv4(ProfileTemplate):
    """DF.5GS Files at ADF.USIM as per Section 9.5.11.4"""
    created_by_default = False
    oid = OID.DF_5GS_v4
    base_path = Path('ADF.USIM')
    parent = FilesUsimMandatory
    files = [
        FileTemplate(0x6fc0, 'DF.5GS',               'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv=[122,126,127,128,129,130], pe_name='df-df-5gs'),
        FileTemplate(0x4f01, 'EF.5GS3GPPLOCI',       'TR', None,   20,   5, 0x01, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f02, 'EF.5GSN3GPPLOCI',      'TR', None,   20,   5, 0x02, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000001', False, ass_serv=[122], high_update=True),
        FileTemplate(0x4f03, 'EF.5GS3GPPNSC',        'LF',    2,   62,   5, 0x03, 'FF...FF', False, ass_serv=[122,136], high_update=True),
        # ^ If Service n°136 is not "available" in EF UST, the Profile Creator shall ensure that these files shall contain one record; otherwise, they shall contain 2 records.
        FileTemplate(0x4f04, 'EF.5GSN3GPPNSC',       'LF',    2,   62,   5, 0x04, 'FF...FF', False, ass_serv=[122,136], high_update=True),
        # ^ If Service n°136 is not "available" in EF UST, the Profile Creator shall ensure that these files shall contain one record; otherwise, they shall contain 2 records.
        FileTemplate(0x4f05, 'EF.5GAUTHKEYS',        'TR', None,  110,   5, 0x05, None, True, ass_serv=[123], high_update=True),
        FileTemplate(0x4f06, 'EF.UAC_AIC',           'TR', None,    4,   2, 0x06, None, True, ass_serv=[126]),
        FileTemplate(0x4f07, 'EF.SUCI_Calc_Info',    'TR', None, None,   2, 0x07, 'FF...FF', False, ass_serv=[124]),
        FileTemplate(0x4f08, 'EF.OPL5G',             'LF', None,   10,  10, 0x08, 'FF...FF', False, ['nb_rec'], ass_serv=[129]),
        FileTemplate(0x4f09, 'EF.SUPI_NAI',          'TR', None, None,   2, 0x09, None, True, ['size'], ass_serv=[130], pe_name='ef-supinai'),
        FileTemplate(0x4f0a, 'EF.Routing_Indicator', 'TR', None,    4,   2, 0x0a, 'F0FF0000', False, ass_serv=[124]),
        FileTemplate(0x4f0b, 'EF.URSP',              'BT', None, None,   2, None, None, False, ass_serv=[132]),
        FileTemplate(0x4f0c, 'EF.TN3GPPSNN',         'TR', None,    1,   2, 0x0c, '00', False, ass_serv=[135]),
        FileTemplate(0x4f0d, 'EF.CAG',               'TR', None,    2,   2, 0x0d, None, True, ass_serv=[137]),
        FileTemplate(0x4f0e, 'EF.SOR_CMCI',          'TR', None, None,   2, 0x0e, None, True, ass_serv=[138]),
        FileTemplate(0x4f0f, 'EF.DRI',               'TR', None,    7,   2, 0x0f, None, True, ass_serv=[150]),
        FileTemplate(0x4f10, 'EF.5GSEDRX',           'TR', None,    2,   2, 0x10, None, True, ass_serv=[141]),
        FileTemplate(0x4f11, 'EF.5GNSWO_CONF',       'TR', None,    1,   2, 0x11, None, True, ass_serv=[142]),
        FileTemplate(0x4f15, 'EF.MCHPPLMN',          'TR', None,    1,   2, 0x15, None, True, ass_serv=[144]),
        FileTemplate(0x4f16, 'EF.KAUSF_DERIVATION',  'TR', None,    1,   2, 0x16, None, True, ass_serv=[145]),
    ]


class FilesUsimDfSaip(ProfileTemplate):
    """DF.SAIP Files at ADF.USIM as per Section 9.5.12"""
    created_by_default = False
    oid = OID.DF_SAIP
    base_path = Path('ADF.USIM')
    parent = FilesUsimMandatory
    files = [
        FileTemplate(0x6fd0, 'DF.SAIP',        'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv=[(124, 125)], pe_name='df-df-saip'),
        FileTemplate(0x4f01, 'EF.SUCICalcInfo','TR', None, None, 3, None, 'FF...FF', False, ['size'], ass_serv=[125], pe_name='ef-suci-calc-info-usim'),
    ]

class FilesDfSnpn(ProfileTemplate):
    """DF.SNPN Files at ADF.USIM as per Section 9.5.13"""
    created_by_default = False
    oid = OID.DF_SNPN
    base_path = Path('ADF.USIM')
    parent = FilesUsimMandatory
    files = [
        FileTemplate(0x5fe0, 'DF.SNPN',         'DF', None, None,  14, None, None, False, ['pinStatusTemplateDO'], ass_serv=[143], pe_name='df-df-snpn'),
        FileTemplate(0x4f01, 'EF.PWS_SNPN',     'TR', None,    1,  10, None, None, True, ass_serv=[143]),
    ]

class FilesDf5GProSe(ProfileTemplate):
    """DF.ProSe Files at ADF.USIM as per Section 9.5.14"""
    created_by_default = False
    oid = OID.DF_5GProSe
    base_path = Path('ADF.USIM')
    parent = FilesUsimMandatory
    files = [
        FileTemplate(0x5ff0, 'DF.5G_ProSe',       'DF', None, None,  14, None, None, False, ['pinStatusTeimplateDO'], ass_serv=[139], pe_name='df-df-5g-prose'),
        FileTemplate(0x4f01, 'EF.5G_PROSE_ST',    'TR', None,    1,   2, 0x01, None,  True, ass_serv=[139]),
        FileTemplate(0x4f02, 'EF.5G_PROSE_DD',    'TR', None,   26,   2, 0x02, None,  True, ass_serv=[139,1001]),
        FileTemplate(0x4f03, 'EF.5G_PROSE_DC',    'TR', None,   12,   2, 0x03, None,  True, ass_serv=[139,1002]),
        FileTemplate(0x4f04, 'EF.5G_PROSE_U2NRU', 'TR', None,   32,   2, 0x04, None,  True, ass_serv=[139,1003]),
        FileTemplate(0x4f05, 'EF.5G_PROSE_RU',    'TR', None,   29,   2, 0x05, None,  True, ass_serv=[139,1004]),
        FileTemplate(0x4f06, 'EF.5G_PROSE_UIR',   'TR', None,   32,   2, 0x06, None,  True, ass_serv=[139,1005]),
    ]

class FilesIsimMandatory(ProfileTemplate):
    """Mandatory Files at ADF.ISIM as per Section 9.6.1"""
    created_by_default = True
    oid = OID.ADF_ISIM_by_default
    files = [
        FileTemplate(  None, 'ADF.ISIM',      'ADF', None, None,  14, None, None, False, ['aid','temporary_fid','pinStatusTemplateDO']),
        FileTemplate(0x6f02, 'EF.IMPI',        'TR', None, None,   2, 0x02, None, True, ['size']),
        FileTemplate(0x6f04, 'EF.IMPU',        'LF',    1, None,   2, 0x04, None, True, ['size']),
        FileTemplate(0x6f03, 'EF.Domain',      'TR', None, None,   2, 0x05, None, True, ['size']),
        FileTemplate(0x6f07, 'EF.IST',         'TR', None,   14,   2, 0x07, None, True),
        FileTemplate(0x6fad, 'EF.AD',          'TR', None,    3,  10, 0x03, '000000', False),
        FileTemplate(0x6f06, 'EF.ARR',         'LF', None, None,  10, 0x06, None, True, ['nb_rec','size']),
    ]


class FilesIsimOptional(ProfileTemplate):
    """Optional Files at ADF.ISIM as per Section 9.6.2 of v2.3.1"""
    created_by_default = False
    optional = True
    oid = OID.ADF_ISIMopt_not_by_default
    base_path = Path('ADF.ISIM')
    extends = FilesIsimMandatory
    files = [
        FileTemplate(0x6f09, 'EF.P-CSCF',      'LF',    1, None,   2, None, None, True, ['size'], ass_serv=[1,5]),
        FileTemplate(0x6f3c, 'EF.SMS',         'LF',   10,  176,   5, None, '00FF...FF', False, ass_serv=[6,8]),
        FileTemplate(0x6f42, 'EF.SMSP',        'LF',    1,   38,   5, None, 'FF...FF', False, ass_serv=[8]),
        FileTemplate(0x6f43, 'EF.SMSS',        'TR', None,    2,   5, None, 'FFFF', False, ass_serv=[6,8]),
        FileTemplate(0x6f47, 'EF.SMSR',        'LF',   10,   30,   5, None, '00FF...FF', False, ass_serv=[7,8]),
        FileTemplate(0x6fd5, 'EF.GBABP',       'TR', None, None,   5, None, 'FF...FF', False, ['size'], ass_serv=[2]),
        FileTemplate(0x6fd7, 'EF.GBANL',       'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[2]),
        FileTemplate(0x6fdd, 'EF.NAFKCA',      'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[2,4]),
        FileTemplate(0x6fe7, 'EF.UICCIARI',    'LF', None, None,   2, None, None, True, ['nb_rec','size'], ass_serv=[10]),
    ]


class FilesIsimOptionalv2(ProfileTemplate):
    """Optional Files at ADF.ISIM as per Section 9.6.2"""
    created_by_default = False
    optional = True
    oid = OID.ADF_ISIMopt_not_by_default_v2
    base_path = Path('ADF.ISIM')
    extends = FilesIsimMandatory
    files = [
        FileTemplate(0x6f09, 'EF.PCSCF',       'LF',    1, None,   2, None, None, True, ['size'], ass_serv=[1,5]),
        FileTemplate(0x6f3c, 'EF.SMS',         'LF',   10,  176,   5, None, '00FF...FF', False, ass_serv=[6,8]),
        FileTemplate(0x6f42, 'EF.SMSP',        'LF',    1,   38,   5, None, 'FF...FF', False, ass_serv=[8]),
        FileTemplate(0x6f43, 'EF.SMSS',        'TR', None,    2,   5, None, 'FFFF', False, ass_serv=[6,8]),
        FileTemplate(0x6f47, 'EF.SMSR',        'LF',   10,   30,   5, None, '00FF...FF', False, ass_serv=[7,8]),
        FileTemplate(0x6fd5, 'EF.GBABP',       'TR', None, None,   5, None, 'FF...FF', False, ['size'], ass_serv=[2]),
        FileTemplate(0x6fd7, 'EF.GBANL',       'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[2]),
        FileTemplate(0x6fdd, 'EF.NAFKCA',      'LF', None, None,   2, None, 'FF...FF', False, ['nb_rec','size'], ass_serv=[2,4]),
        FileTemplate(0x6fe7, 'EF.UICCIARI',    'LF', None, None,   2, None, None, True, ['nb_rec','size'], ass_serv=[10]),
        FileTemplate(0x6ff7, 'EF.FromPreferred','TR', None,   1,   2, None, '00', False, ass_serv=[17]),
        FileTemplate(0x6ff8, 'EF.ImsConfigData','BT', None,None,   2, None, None, True, ['size'], ass_serv=[18]),
        FileTemplate(0x6ffc, 'EF.XcapconfigData','BT',None,None,   2, None, None, True, ['size'], ass_serv=[19]),
        FileTemplate(0x6ffa, 'EF.WebRTCURI',   'LF', None, None,   2, None, None, True, ['nb_rec', 'size'], ass_serv=[20]),
        FileTemplate(0x6ffa, 'EF.MudMidCfgData','BT',None, None,   2, None, None, True, ['size'], ass_serv=[21]),
    ]


# TODO: CSIM


class FilesEap(ProfileTemplate):
    """Files at DF.EAP as per Section 9.8"""
    created_by_default = False
    oid = OID.DF_EAP
    files = [
        FileTemplate(  None, 'DF.EAP',         'DF', None, None,  14, None, None, False, ['fid','pinStatusTemplateDO'], ass_serv=[(124, 125)]),
        FileTemplate(0x4f01, 'EF.EAPKEYS',     'TR', None, None,   2, None, None, True, ['size'], high_update=True),
        FileTemplate(0x4f02, 'EF.EAPSTATUS',   'TR', None,    1,   2, None, '00', False, high_update=True),
        FileTemplate(0x4f03, 'EF.PUId',        'TR', None, None,   2, None, None, True, ['size']),
        FileTemplate(0x4f04, 'EF.Ps',          'TR', None, None,   5, None, 'FF...FF', False, ['size'], high_update=True),
        FileTemplate(0x4f20, 'EF.CurID',       'TR', None, None,   5, None, 'FF...FF', False, ['size'], high_update=True),
        FileTemplate(0x4f21, 'EF.RelID',       'TR', None, None,   5, None, None, True, ['size']),
        FileTemplate(0x4f22, 'EF.Realm',       'TR', None, None,   5, None, None, True, ['size']),
    ]


# Section 9.9 Access Rules Definition
ARR_DEFINITION = {
     1: ['8001019000', '800102A406830101950108', '800158A40683010A950108'],
     2: ['800101A406830101950108', '80015AA40683010A950108'],
     3: ['80015BA40683010A950108'],
     4: ['8001019000', '80011A9700', '800140A40683010A950108'],
     5: ['800103A406830101950108', '800158A40683010A950108'],
     6: ['800111A406830101950108', '80014AA40683010A950108'],
     7: ['800103A406830101950108', '800158A40683010A950108', '840132A406830101950108'],
     8: ['800101A406830101950108', '800102A406830181950108', '800158A40683010A950108'],
     9: ['8001019000', '80011AA406830101950108', '800140A40683010A950108'],
    10: ['8001019000', '80015AA40683010A950108'],
    11: ['8001019000', '800118A40683010A950108', '8001429700'],
    12: ['800101A406830101950108', '80015A9700'],
    13: ['800113A406830101950108', '800148A40683010A950108'],
    14: ['80015EA40683010A950108'],
}

class SaipSpecVersionMeta(type):
    def __getitem__(self, ver: str):
        """Syntactic sugar so that SaipSpecVersion['2.3.0'] will work."""
        return SaipSpecVersion.for_version(ver)

class SaipSpecVersion(object, metaclass=SaipSpecVersionMeta):
    """Represents a specific version of the SIMalliance / TCA eUICC Profile Package:
       Interoperable Format Technical Specification."""
    version = None
    oids = []

    @classmethod
    def suports_template_OID(cls, OID: OID.OID) -> bool:
        """Return if a given spec version supports a template of given OID."""
        return OID in cls.oids

    @classmethod
    def version_match(cls, ver: str) -> bool:
        """Check if the given version-string matches the classes version.  trailing zeroes are ignored,
        so that for example 2.2.0 will be considered equal to 2.2"""
        def strip_trailing_zeroes(l: List):
            while l[-1] == '0':
                l.pop()
        cls_ver_l = cls.version.split('.')
        strip_trailing_zeroes(cls_ver_l)
        ver_l = ver.split('.')
        strip_trailing_zeroes(ver_l)
        return cls_ver_l == ver_l

    @staticmethod
    def for_version(req_version: str) -> Optional['SaipSpecVersion']:
        """Return the subclass for the requested version number string."""
        for cls in all_subclasses(SaipSpecVersion):
            if cls.version_match(req_version):
                return cls


class SaipSpecVersion101(SaipSpecVersion):
    version = '1.0.1'
    oids = [OID.MF, OID.DF_CD, OID.DF_TELECOM, OID.ADF_USIM_by_default, OID.ADF_USIMopt_not_by_default,
            OID.DF_PHONEBOOK_ADF_USIM, OID.DF_GSM_ACCESS_ADF_USIM, OID.ADF_ISIM_by_default,
            OID.ADF_ISIMopt_not_by_default, OID.ADF_CSIM_by_default, OID.ADF_CSIMopt_not_by_default]

class SaipSpecVersion20(SaipSpecVersion):
    version = '2.0'
    # no changes in filesystem teplates to previous 1.0.1
    oids = SaipSpecVersion101.oids

class SaipSpecVersion21(SaipSpecVersion):
    version = '2.1'
    # no changes in filesystem teplates to previous 2.0
    oids = SaipSpecVersion20.oids

class SaipSpecVersion22(SaipSpecVersion):
    version = '2.2'
    oids = SaipSpecVersion21.oids + [OID.DF_EAP]

class SaipSpecVersion23(SaipSpecVersion):
    version = '2.3'
    oids = SaipSpecVersion22.oids + [OID.DF_5GS, OID.DF_SAIP]

class SaipSpecVersion231(SaipSpecVersion):
    version = '2.3.1'
    # no changes in filesystem teplates to previous 2.3
    oids = SaipSpecVersion23.oids

class SaipSpecVersion31(SaipSpecVersion):
    version = '3.1'
    oids = [OID.MF, OID.DF_CD, OID.DF_TELECOM_v2, OID.ADF_USIM_by_default_v2, OID.ADF_USIMopt_not_by_default_v2,
            OID.DF_PHONEBOOK_ADF_USIM, OID.DF_GSM_ACCESS_ADF_USIM, OID.DF_5GS_v2, OID.DF_5GS_v3, OID.DF_SAIP,
            OID.ADF_ISIM_by_default, OID.ADF_ISIMopt_not_by_default_v2, OID.ADF_CSIM_by_default_v2,
            OID.ADF_CSIMopt_not_by_default_v2, OID.DF_EAP]

class SaipSpecVersion32(SaipSpecVersion):
    version = '3.2'
    # no changes in filesystem teplates to previous 3.1
    oids = SaipSpecVersion31.oids

class SaipSpecVersion331(SaipSpecVersion):
    version = '3.3.1'
    oids = SaipSpecVersion32.oids + [OID.ADF_USIMopt_not_by_default_v3, OID.DF_5GS_v4, OID.DF_SAIP, OID.DF_SNPN, OID.DF_5GProSe, OID.IoT_by_default, OID.IoTopt_not_by_default]
