"""Implementation of SimAlliance/TCA Interoperable Profile validation."""

# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
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


from pySim.esim.saip import *

class ProfileError(Exception):
    """Raised when a ProfileConstraintChecker finds an error in a file [structure]."""
    pass

class ProfileConstraintChecker:
    """Base class of a constraint checker for a ProfileElementSequence."""
    def check(self, pes: ProfileElementSequence):
        """Execute all the check_* methods of the ProfileConstraintChecker against the given
        ProfileElementSequence"""
        for name in dir(self):
            if name.startswith('check_'):
                method = getattr(self, name)
                method(pes)

class CheckBasicStructure(ProfileConstraintChecker):
    """ProfileConstraintChecker for the basic profile structure constraints."""
    def _is_after_if_exists(self, pes: ProfileElementSequence, opt:str, after:str):
        opt_pe = pes.get_pe_for_type(opt)
        if opt_pe:
            after_pe = pes.get_pe_for_type(after)
            if not after_pe:
                raise ProfileError('PE-%s without PE-%s' % (opt.upper(), after.upper()))
            # FIXME: check order

    def check_start_and_end(self, pes: ProfileElementSequence):
        """Check for mandatory header and end ProfileElements at the right position."""
        if pes.pe_list[0].type != 'header':
            raise ProfileError('first element is not header')
        if pes.pe_list[1].type != 'mf':
            # strictly speaking: permitted, but we don't support MF via GenericFileManagement
            raise ProfileError('second  element is not mf')
        if pes.pe_list[-1].type != 'end':
            raise ProfileError('last element is not end')

    def check_number_of_occurrence(self, pes: ProfileElementSequence):
        """Check The number of occurrence of various ProfileElements."""
        # check for invalid number of occurrences
        if len(pes.get_pes_for_type('header')) != 1:
            raise ProfileError('multiple ProfileHeader')
        if len(pes.get_pes_for_type('mf')) != 1:
            # strictly speaking: 0 permitted, but we don't support MF via GenericFileManagement
            raise ProfileError('multiple PE-MF')
        for tn in ['end', 'cd', 'telecom',
                   'usim', 'isim', 'csim', 'opt-usim','opt-isim','opt-csim',
                   'df-saip', 'df-5gs']:
            if len(pes.get_pes_for_type(tn)) > 1:
                raise ProfileError('multiple PE-%s' % tn.upper())

    def check_optional_ordering(self, pes: ProfileElementSequence):
        """Check the ordering of optional PEs following the respective mandatory ones."""
        # ordering and required depenencies
        self._is_after_if_exists(pes,'opt-usim', 'usim')
        self._is_after_if_exists(pes,'opt-isim', 'isim')
        self._is_after_if_exists(pes,'gsm-access', 'usim')
        self._is_after_if_exists(pes,'phonebook', 'usim')
        self._is_after_if_exists(pes,'df-5gs', 'usim')
        self._is_after_if_exists(pes,'df-saip', 'usim')
        self._is_after_if_exists(pes,'opt-csim', 'csim')

    def check_mandatory_services(self, pes: ProfileElementSequence):
        """Ensure that the PE for the mandatory services exist."""
        m_svcs = pes.get_pe_for_type('header').decoded['eUICC-Mandatory-services']
        if 'usim' in m_svcs and not pes.get_pe_for_type('usim'):
            raise ProfileError('no PE-USIM for mandatory usim service')
        if 'isim' in m_svcs and not pes.get_pe_for_type('isim'):
            raise ProfileError('no PE-ISIM for mandatory isim service')
        if 'csim' in m_svcs and not pes.get_pe_for_type('csim'):
            raise ProfileError('no PE-ISIM for mandatory csim service')
        if 'gba-usim' in m_svcs and not 'usim' in m_svcs:
            raise ProfileError('gba-usim mandatory, but no usim')
        if 'gba-isim' in m_svcs and not 'isim' in m_svcs:
            raise ProfileError('gba-isim mandatory, but no isim')
        if 'multiple-usim' in m_svcs and not 'usim' in m_svcs:
            raise ProfileError('multiple-usim mandatory, but no usim')
        if 'multiple-isim' in m_svcs and not 'isim' in m_svcs:
            raise ProfileError('multiple-isim mandatory, but no isim')
        if 'multiple-csim' in m_svcs and not 'csim' in m_svcs:
            raise ProfileError('multiple-csim mandatory, but no csim')
        if 'get-identity' in m_svcs and not ('usim' in m_svcs or 'isim' in m_svcs):
            raise ProfileError('get-identity mandatory, but no usim or isim')
        if 'profile-a-x25519' in m_svcs and not ('usim' in m_svcs or 'isim' in m_svcs):
            raise ProfileError('profile-a-x25519 mandatory, but no usim or isim')
        if 'profile-a-p256' in m_svcs and not ('usim' in m_svcs or 'isim' in m_svcs):
            raise ProfileError('profile-a-p256 mandatory, but no usim or isim')

    def check_identification_unique(self, pes: ProfileElementSequence):
        """Ensure that each PE has a unique identification value."""
        id_list = [pe.header['identification'] for pe in pes.pe_list if pe.header]
        if len(id_list) != len(set(id_list)):
            raise ProfileError('PE identification values are not unique')

FileChoiceList = List[Tuple]

class FileError(ProfileError):
    """Raised when a FileConstraintChecker finds an error in a file [structure]."""
    pass

class FileConstraintChecker:
    def check(self, l: FileChoiceList):
        """Execute all the check_* methods of the FileConstraintChecker against the given FileChoiceList"""
        for name in dir(self):
            if name.startswith('check_'):
                method = getattr(self, name)
                method(l)

class FileCheckBasicStructure(FileConstraintChecker):
    """Validator for the basic structure of a decoded file."""
    def check_seqence(self, l: FileChoiceList):
        """Check the sequence/ordering."""
        by_type = {}
        for k, v in l:
            if k in by_type:
                by_type[k].append(v)
            else:
                by_type[k] = [v]
        if 'doNotCreate' in by_type:
            if len(l) != 1:
                raise FileError("doNotCreate must be the only element")
        if 'fileDescriptor' in by_type:
            if len(by_type['fileDescriptor']) != 1:
                raise FileError("fileDescriptor must be the only element")
            if l[0][0] != 'fileDescriptor':
                raise FileError("fileDescriptor must be the first element")

    def check_forbidden(self, l: FileChoiceList):
        """Perform checks for forbidden parameters as described in Section 8.3.3."""
