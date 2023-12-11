import sys
from importlib import resources

import asn1tools

def compile_asn1_subdir(subdir_name:str):
    """Helper function that compiles ASN.1 syntax from all files within given subdir"""
    asn_txt = ''
    __ver = sys.version_info
    if (__ver.major, __ver.minor) >= (3, 9):
        for i in resources.files('pySim.esim').joinpath('asn1').joinpath(subdir_name).iterdir():
            asn_txt += i.read_text()
            asn_txt += "\n"
    #else:
        #print(resources.read_text(__name__, 'asn1/rsp.asn'))
    return asn1tools.compile_string(asn_txt, codec='der')
