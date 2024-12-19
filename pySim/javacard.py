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
from osmocom.utils import b2h
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

    #TODO: At the moment we only support the compact .cap format, add support for the extended .cap format.

    __component_header = None
    __component_directory = None
    __component_applet = None #optional
    __component_import = None
    __component_constantPool = None
    __component_class = None
    __component_method = None
    __component_staticField = None
    __component_referenceLocation = None
    __component_export = None #optional
    __component_descriptor = None
    __component_debug = None #optional, since CAP format 2.2

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
        # Extract the nested .cap components from the .cap file
        # See also: Java Card Platform Virtual Machine Specification, v3.2, section 6.2.1
        cap = zipfile.ZipFile(filename)
        cap_namelist = cap.namelist()
        for i, filename in enumerate(cap_namelist):
            if filename.lower().endswith('header.cap'):
                self.__component_header = cap.read(filename)
            elif filename.lower().endswith('directory.cap'):
                self.__component_directory = cap.read(filename)
            elif filename.lower().endswith('applet.cap'):
                self.__component_applet = cap.read(filename)
            elif filename.lower().endswith('import.cap'):
                self.__component_import = cap.read(filename)
            elif filename.lower().endswith('constantpool.cap'):
                self.__component_constantPool = cap.read(filename)
            elif filename.lower().endswith('class.cap'):
                self.__component_class = cap.read(filename)
            elif filename.lower().endswith('method.cap'):
                self.__component_method = cap.read(filename)
            elif filename.lower().endswith('staticfield.cap'):
                self.__component_staticField = cap.read(filename)
            elif filename.lower().endswith('reflocation.cap'):
                self.__component_referenceLocation = cap.read(filename)
            elif filename.lower().endswith('export.cap'):
                self.__component_export = cap.read(filename)
            elif filename.lower().endswith('descriptor.cap'):
                self.__component_descriptor = cap.read(filename)
            elif filename.lower().endswith('debug.cap'):
                self.__component_debug = cap.read(filename)

        # Make sure that all mandatory components are present
        # See also: Java Card Platform Virtual Machine Specification, v3.2, section 6.2
        if self.__component_header is None:
            raise ValueError("invalid cap file, COMPONENT_Header missing!")
        if self.__component_directory is None:
            raise ValueError("invalid cap file, COMPONENT_Directory missing!")
        if self.__component_import is None:
            raise ValueError("invalid cap file, COMPONENT_Import missing!")
        if self.__component_constantPool is None:
            raise ValueError("invalid cap file, COMPONENT_ConstantPool missing!")
        if self.__component_class is None:
            raise ValueError("invalid cap file, COMPONENT_Class missing!")
        if self.__component_method is None:
            raise ValueError("invalid cap file, COMPONENT_Method missing!")
        if self.__component_staticField is None:
            raise ValueError("invalid cap file, COMPONENT_StaticField missing!")
        if self.__component_referenceLocation is None:
            raise ValueError("invalid cap file, COMPONENT_ReferenceLocation missing!")
        if self.__component_descriptor is None:
            raise ValueError("invalid cap file, COMPONENT_Descriptor missing!")

    def get_loadfile(self):
        """Get the executeable loadfile as hexstring"""
        # Concatenate all cap file components in the specified order
        # see also: Java Card Platform Virtual Machine Specification, v3.2, section 6.3
        loadfile = self.__component_header
        loadfile += self.__component_directory
        loadfile += self.__component_import
        if self.__component_applet:
            loadfile += self.__component_applet
        loadfile += self.__component_class
        loadfile += self.__component_method
        loadfile += self.__component_staticField
        if self.__component_export:
            loadfile += self.__component_export
        loadfile += self.__component_constantPool
        loadfile += self.__component_referenceLocation
        if self.__component_descriptor:
            loadfile += self.__component_descriptor
        return b2h(loadfile)

    def get_loadfile_aid(self):
        """Get the loadfile AID as hexstring"""
        header = self.__header_component_compact.parse(self.__component_header)
        magic = header['magic'] or 0
        if magic != 0xDECAFFED:
            raise ValueError("invalid cap file, COMPONENT_Header lacks magic number (0x%08X!=0xDECAFFED)!" % magic)
        #TODO: check cap version and make sure we are compatible with it
        return header['package']['AID']

    def get_applet_aid(self, index:int = 0):
        """Get the applet AID as hexstring"""
        #To get the module AID, we must look into COMPONENT_Applet. Unfortunately, even though this component should
        #be present in any .cap file, it is defined as an optional component.
        if self.__component_applet is None:
            raise ValueError("can't get the AID, this cap file lacks the optional COMPONENT_Applet component!")

        applet = self.__applet_component_compact.parse(self.__component_applet)

        if index > applet['count']:
            raise ValueError("can't get the AID for applet with index=%u, this .cap file only has %u applets!" %
                             (index, applet['count']))

        return applet['applets'][index]['AID']

