# JavaCard related utilities
#
# (C) 2024 by Sysmocom s.f.m.c. GmbH
# All Rights Reserved
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
#
import zipfile
import struct
import sys
import io
from osmocom.utils import b2h, Hexstr
from construct import Struct, Array, this, Int32ub, Int16ub, Int8ub
from osmocom.construct import *
from osmocom.tlv import *
from construct import Optional as COptional

def ijc_to_cap(in_file: io.IOBase, out_zip: zipfile.ZipFile, p : str = "foo"):
    """Convert an ICJ (Interoperable Java Card) file [back] to a CAP file.
    example usage:
        with io.open(sys.argv[1],"rb") as f, zipfile.ZipFile(sys.argv[2], "wb") as z:
        ijc_to_cap(f, z)
    """
    TAGS = ["Header", "Directory", "Applet", "Import", "ConstantPool", "Class", "Method", "StaticField", "RefLocation",
            "Export", "Descriptor", "Debug"]
    b = in_file.read()
    while len(b):
        tag, size = struct.unpack('!BH', b[0:3])
        out_zip.writestr(p+"/javacard/"+TAGS[tag-1]+".cap", b[0:3+size])
        b = b[3+size:]

class CapFile():

    # Java Card Platform Virtual Machine Specification, v3.2, section 6.4
    __header_component_compact = Struct('tag'/Int8ub,
                                        'size'/Int16ub,
                                        'magic'/Int32ub,
                                        'minor_version'/Int8ub,
                                        'major_version'/Int8ub,
                                        'flags'/Int8ub,
                                        'package'/Struct('minor_version'/Int8ub,
                                                         'major_version'/Int8ub,
                                                         'AID'/LV),
                                        'package_name'/COptional(LV)) #since CAP format 2.2

    # Java Card Platform Virtual Machine Specification, v3.2, section 6.6
    __applet_component_compact = Struct('tag'/Int8ub,
                                        'size'/Int16ub,
                                        'count'/Int8ub,
                                        'applets'/Array(this.count, Struct('AID'/LV,
                                                                           'install_method_offset'/Int16ub)),
                                       )

    def __init__(self, filename:str):

        # In this dictionary we will keep all nested .cap file components by their file names (without .cap suffix)
        # See also: Java Card Platform Virtual Machine Specification, v3.2, section 6.2.1
        self.__component = {}

        # Extract the nested .cap components from the .cap file
        # See also: Java Card Platform Virtual Machine Specification, v3.2, section 6.2.1
        cap = zipfile.ZipFile(filename)
        cap_namelist = cap.namelist()
        for i, filename in enumerate(cap_namelist):
            if filename.lower().endswith('.capx') and not filename.lower().endswith('.capx'):
                #TODO: At the moment we only support the compact .cap format, add support for the extended .cap format.
                raise ValueError("incompatible .cap file, extended .cap format not supported!")

            if filename.lower().endswith('.cap'):
                key = filename.split('/')[-1].removesuffix('.cap')
                self.__component[key] = cap.read(filename)

        # Make sure that all mandatory components are present
        # See also: Java Card Platform Virtual Machine Specification, v3.2, section 6.2
        required_components = {'Header' : 'COMPONENT_Header',
                               'Directory' : 'COMPONENT_Directory',
                               'Import' : 'COMPONENT_Import',
                               'ConstantPool' : 'COMPONENT_ConstantPool',
                               'Class' : 'COMPONENT_Class',
                               'Method' : 'COMPONENT_Method',
                               'StaticField' : 'COMPONENT_StaticField',
                               'RefLocation' : 'COMPONENT_ReferenceLocation',
                               'Descriptor' : 'COMPONENT_Descriptor'}
        for component in required_components:
            if component not in self.__component.keys():
                raise ValueError("invalid cap file, %s missing!" % required_components[component])

    def get_loadfile(self) -> bytes:
        """Get the executeable loadfile as hexstring"""
        # Concatenate all cap file components in the specified order
        # see also: Java Card Platform Virtual Machine Specification, v3.2, section 6.3
        loadfile = self.__component['Header']
        loadfile += self.__component['Directory']
        loadfile += self.__component['Import']
        if 'Applet' in self.__component.keys():
            loadfile += self.__component['Applet']
        loadfile += self.__component['Class']
        loadfile += self.__component['Method']
        loadfile += self.__component['StaticField']
        if 'Export' in self.__component.keys():
            loadfile += self.__component['Export']
        loadfile += self.__component['ConstantPool']
        loadfile += self.__component['RefLocation']
        if 'Descriptor' in self.__component.keys():
            loadfile += self.__component['Descriptor']
        return loadfile

    def get_loadfile_aid(self) -> Hexstr:
        """Get the loadfile AID as hexstring"""
        header = self.__header_component_compact.parse(self.__component['Header'])
        magic = header['magic'] or 0
        if magic != 0xDECAFFED:
            raise ValueError("invalid cap file, COMPONENT_Header lacks magic number (0x%08X!=0xDECAFFED)!" % magic)
        #TODO: check cap version and make sure we are compatible with it
        return header['package']['AID']

    def get_applet_aid(self, index:int = 0) -> Hexstr:
        """Get the applet AID as hexstring"""
        #To get the module AID, we must look into COMPONENT_Applet. Unfortunately, even though this component should
        #be present in any .cap file, it is defined as an optional component.
        if 'Applet' not in self.__component.keys():
            raise ValueError("can't get the AID, this cap file lacks the optional COMPONENT_Applet component!")

        applet = self.__applet_component_compact.parse(self.__component['Applet'])

        if index > applet['count']:
            raise ValueError("can't get the AID for applet with index=%u, this .cap file only has %u applets!" %
                             (index, applet['count']))

        return applet['applets'][index]['AID']

