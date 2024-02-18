# Implementation of SimAlliance/TCA Interoperable Profile handling
#
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

import abc
from typing import List, Tuple

from pySim.esim.saip import ProfileElement, ProfileElementSequence

def remove_unwanted_tuples_from_list(l: List[Tuple], unwanted_keys: List[str]) -> List[Tuple]:
    """In a list of tuples, remove all tuples whose first part equals 'unwanted_key'."""
    return list(filter(lambda x: x[0] not in unwanted_keys, l))

def file_replace_content(file: List[Tuple], new_content: bytes):
    """Completely replace all fillFileContent of a decoded 'File' with the new_content."""
    # use [:] to avoid making a copy, as we're doing in-place modification of the list here
    file[:] = remove_unwanted_tuples_from_list(file, ['fillFileContent', 'fillFileOffset'])
    file.append(('fillFileContent', new_content))
    return file

class ClassVarMeta(abc.ABCMeta):
    """Metaclass that puts all additional keyword-args into the class. We use this to have one
    class definition for something like a PIN, and then have derived classes for PIN1, PIN2, ..."""
    def __new__(metacls, name, bases, namespace, **kwargs):
        #print("Meta_new_(metacls=%s, name=%s, bases=%s, namespace=%s, kwargs=%s)" % (metacls, name, bases, namespace, kwargs))
        x = super().__new__(metacls, name, bases, namespace)
        for k, v in kwargs.items():
            setattr(x, k, v)
        return x

class ConfigurableParameter(abc.ABC, metaclass=ClassVarMeta):
    """Base class representing a part of the eSIM profile that is configurable during the
    personalization process (with dynamic data from elsewhere)."""
    def __init__(self, value):
        self.value = value

    @abc.abstractmethod
    def apply(self, pes: ProfileElementSequence):
        pass

class Iccid(ConfigurableParameter):
    """Configurable ICCID.  Expects the value to be in EF.ICCID format."""
    name = 'iccid'
    def apply(self, pes: ProfileElementSequence):
        # patch the header; FIXME: swap nibbles!
        pes.get_pe_for_type('header').decoded['iccid'] = self.value
        # patch MF/EF.ICCID
        file_replace_content(pes.get_pe_for_type('mf').decoded['ef-iccid'], bytes(self.value))

class Imsi(ConfigurableParameter):
    """Configurable IMSI. Expects value to be n EF.IMSI format."""
    name = 'imsi'
    def apply(self, pes: ProfileElementSequence):
        # patch ADF.USIM/EF.IMSI
        for pe in pes.get_pes_by_type('usim'):
            file_replace_content(pe.decoded['ef-imsi'], self.value)
        # TODO: DF.GSM_ACCESS if not linked?

def obtain_singleton_pe_from_pelist(l: List[ProfileElement], wanted_type: str) -> ProfileElement:
    filtered = list(filter(lambda x: x.type == wanted_type, l))
    assert len(filtered) == 1
    return filtered[0]

def obtain_first_pe_from_pelist(l: List[ProfileElement], wanted_type: str) -> ProfileElement:
    filtered = list(filter(lambda x: x.type == wanted_type, l))
    return filtered[0]

class Puk(ConfigurableParameter, metaclass=ClassVarMeta):
    """Configurable PUK (Pin Unblock Code). String ASCII-encoded digits."""
    keyReference = None
    def apply(self, pes: ProfileElementSequence):
        mf_pes = pes.pes_by_naa['mf'][0]
        pukCodes = obtain_singleton_pe_from_pelist(mf_pes, 'pukCodes')
        for pukCode in pukCodes.decoded['pukCodes']:
            if pukCode['keyReference'] == self.keyReference:
                pukCode['pukValue'] = self.value
                return
        raise ValueError('cannot find pukCode')
class Puk1(Puk, keyReference=0x01):
    pass
class Puk2(Puk, keyReference=0x81):
    pass

class Pin(ConfigurableParameter, metaclass=ClassVarMeta):
    """Configurable PIN (Personal Identification Number).  String of digits."""
    keyReference = None
    def apply(self, pes: ProfileElementSequence):
        mf_pes = pes.pes_by_naa['mf'][0]
        pinCodes = obtain_first_pe_from_pelist(mf_pes, 'pinCodes')
        if pinCodes.decoded['pinCodes'][0] != 'pinconfig':
            return
        for pinCode in pinCodes.decoded['pinCodes'][1]:
            if pinCode['keyReference'] == self.keyReference:
                 pinCode['pinValue'] = self.value
                 return
        raise ValueError('cannot find pinCode')
class AppPin(ConfigurableParameter, metaclass=ClassVarMeta):
    """Configurable PIN (Personal Identification Number).  String of digits."""
    keyReference = None
    def _apply_one(self, pe: ProfileElement):
        pinCodes = obtain_first_pe_from_pelist(pe, 'pinCodes')
        if pinCodes.decoded['pinCodes'][0] != 'pinconfig':
            return
        for pinCode in pinCodes.decoded['pinCodes'][1]:
            if pinCode['keyReference'] == self.keyReference:
                pinCode['pinValue'] = self.value
                return
        raise ValueError('cannot find pinCode')

    def apply(self, pes: ProfileElementSequence):
        for naa in pes.pes_by_naa:
            if naa not in ['usim','isim','csim','telecom']:
                continue
            for instance in pes.pes_by_naa[naa]:
                self._apply_one(instance)
class Pin1(Pin, keyReference=0x01):
    pass
# PIN2 is special: telecom + usim + isim + csim
class Pin2(AppPin, keyReference=0x81):
    pass
class Adm1(Pin, keyReference=0x0A):
    pass
class Adm2(Pin, keyReference=0x0B):
    pass


class AlgoConfig(ConfigurableParameter, metaclass=ClassVarMeta):
    """Configurable Algorithm parameter.  bytes."""
    key = None
    def apply(self, pes: ProfileElementSequence):
        for pe in pes.get_pes_for_type('akaParameter'):
            algoConfiguration = pe.decoded['algoConfiguration']
            if algoConfiguration[0] != 'algoParameter':
                continue
            algoConfiguration[1][self.key] = self.value

class K(AlgoConfig, key='key'):
    pass
class Opc(AlgoConfig, key='opc'):
    pass
class AlgorithmID(AlgoConfig, key='algorithmID'):
    pass

