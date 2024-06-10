# JavaCard related utilities

import zipfile
import struct
import sys
import io

def ijc_to_cap(in_file: io.IOBase, out_zip: zipfile.ZipFile, p : str = "foo"):
    """Convert an ICJ (Interoperable Java Card) file [back] to a CAP file."""
    TAGS = ["Header", "Directory", "Applet", "Import", "ConstantPool", "Class", "Method", "StaticField", "RefLocation", "Export", "Descriptor", "Debug"]
    b = in_file.read()
    while len(b):
        tag, size = struct.unpack('!BH', b[0:3])
        out_zip.writestr(p+"/javacard/"+TAGS[tag-1]+".cap", b[0:3+size])
        b = b[3+size:]

# example usage:
# with io.open(sys.argv[1],"rb") as f, zipfile.ZipFile(sys.argv[2], "wb") as z:
#     ijc_to_cap(f, z)
