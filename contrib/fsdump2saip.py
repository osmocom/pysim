#!/usr/bin/env python3

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


# This is a script to generate a [partial] eSIM profile from the 'fsdump' of another USIM/ISIM.  This is
# useful to generate an "as close as possible" eSIM from a physical USIM, as far as that is possible
# programmatically and in a portable way.
#
# Of course, this really only affects the file sytem aspects of the card.  It's not possible
# to read the K/OPc or other authentication related parameters off a random USIM, and hence
# we cannot replicate that.  Similarly, it's not possible to export the java applets from a USIM,
# and hence we cannot replicate those.

import argparse

from pySim.esim.saip import *
from pySim.ts_102_221 import *

class FsdumpToSaip:
    def __init__(self, pes: ProfileElementSequence):
        self.pes = pes

    @staticmethod
    def fcp_raw2saip_fcp(fname:str, fcp_raw: bytes) -> Dict:
        """Convert a raw TLV-encoded FCP to a SAIP dict-format (as needed by asn1encode)."""
        ftype = fname.split('.')[0]
        # use the raw FCP as basis so we don't get stuck with potentially old decoder bugs
        # ore future format incompatibilities
        fcp = FcpTemplate()
        fcp.from_tlv(fcp_raw)
        r = {}

        r['fileDescriptor'] = fcp.child_by_type(FileDescriptor).to_bytes()

        file_id = fcp.child_by_type(FileIdentifier)
        if file_id:
            r['fileID'] = file_id.to_bytes()
        else:
            if ftype in ['ADF']:
                print('%s is an ADF but has no [mandatory] file_id!' % fname)
                #raise ValueError('%s is an ADF but has no [mandatory] file_id!' % fname)
                r['fileID'] = b'\x7f\xff' # FIXME: auto-increment

        df_name = fcp.child_by_type(DfName)
        if ftype in ['ADF']:
            if not df_name:
                raise ValueError('%s is an ADF but has no [mandatory] df_name!' % fname)
            r['dfName'] = df_name.to_bytes()

        lcsi_byte = fcp.child_by_type(LifeCycleStatusInteger).to_bytes()
        if lcsi_byte != b'\x05':
            r['lcsi'] = lcsi_byte

        sa_ref = fcp.child_by_type(SecurityAttribReferenced)
        if sa_ref:
            r['securityAttributesReferenced'] = sa_ref.to_bytes()

        file_size = fcp.child_by_type(FileSize)
        if ftype in ['EF']:
            if file_size:
                r['efFileSize'] = file_size.to_bytes()

        psdo = fcp.child_by_type(PinStatusTemplate_DO)
        if ftype in ['MF', 'ADF', 'DF']:
            if not psdo:
                raise ValueError('%s is an %s but has no [mandatory] PinStatusTemplateDO' % fname)
            else:
                r['pinStatusTemplateDO'] = psdo.to_bytes()

        sfid = fcp.child_by_type(ShortFileIdentifier)
        if sfid and sfid.decoded:
            if ftype not in ['EF']:
                raise ValueError('%s is not an EF but has [forbidden] shortEFID' % fname)
            r['shortEFID'] = sfid.to_bytes()

        pinfo = fcp.child_by_type(ProprietaryInformation)
        if pinfo and ftype in ['EF']:
            spinfo = pinfo.child_by_type(SpecialFileInfo)
            fill_p = pinfo.child_by_type(FillingPattern)
            repeat_p = pinfo.child_by_type(RepeatPattern)
            # only exists for BER-TLV files
            max_fsize = pinfo.child_by_type(MaximumFileSize)

            if spinfo or fill_p or repeat_p or max_fsize:
                r['proprietaryEFInfo'] = {}
            if spinfo:
                r['proprietaryEFInfo']['specialFileInformation'] = spinfo.to_bytes()
            if fill_p:
                r['proprietaryEFInfo']['fillPattern'] = fill_p.to_bytes()
            if repeat_p:
                r['proprietaryEFInfo']['repeatPattern'] = repeat_p.to_bytes()
            if max_fsize:
                r['proprietaryEFInfo']['maximumFileSize'] = max_fsize.to_bytes()

        # TODO: linkPath
        return r

    @staticmethod
    def fcp_fsdump2saip(fsdump_ef: Dict):
        """Convert a file from its "fsdump" representation to the SAIP representation of a File type
        in the decoded format as used by the asn1tools-generated codec."""
        # first convert the FCP
        path = fsdump_ef['path']
        fdesc = FsdumpToSaip.fcp_raw2saip_fcp(path[-1], h2b(fsdump_ef['fcp_raw']))
        r = [
                ('fileDescriptor', fdesc),
        ]
        # then convert the body.  We're doing a straight-forward conversion without any optimization
        # like not encoding all-ff files.  This should be done by a subsequent optimizer
        if 'body' in fsdump_ef and fsdump_ef['body']:
            if isinstance(fsdump_ef['body'], list):
                for b_seg in fsdump_ef['body']:
                    r.append(('fillFileContent', h2b(b_seg)))
            else:
                r.append(('fillFileContent', h2b(fsdump_ef['body'])))
        print(fsdump_ef['path'])
        return r

    def add_file_from_fsdump(self, fsdump_ef: Dict):
        fid = int(fsdump_ef['fcp']['file_identifier'])
        # determine NAA
        if fsdump_ef['path'][0:1] == ['MF', 'ADF.USIM']:
            naa = NaaUsim
        elif fsdump_ef['path'][0:1] == ['MF', 'ADF.ISIM']:
            naa = NaaIsim
        else:
            print("Unable to determine NAA for %s" % fsdump_ef['path'])
            return
        pes.pes_by_naa[naa.name]
        for pe in pes:
            print("PE %s" % pe)
            if not isinstance(pe, FsProfileElement):
                print("Skipping PE %s" % pe)
                continue
            if not pe.template:
                print("No template for PE %s" % pe )
                continue
            if not fid in pe.template.files_by_fid:
                print("File %04x not available in template; must create it using GenericFileMgmt" % fid)

parser = argparse.ArgumentParser()
parser.add_argument('fsdump', help='')

def has_unsupported_path_prefix(path: List[str]) -> bool:
    # skip some paths from export as they don't exist in an eSIM profile
    UNSUPPORTED_PATHS = [
        ['MF', 'DF.GSM'],
    ]
    for p in UNSUPPORTED_PATHS:
        prefix = path[:len(p)]
        if prefix == p:
            return True
    # any ADF not USIM or ISIM are unsupported
    SUPPORTED_ADFS = [ 'ADF.USIM', 'ADF.ISIM' ]
    if len(path) == 2 and path[0] == 'MF' and path[1].startswith('ADF.') and path[1] not in SUPPORTED_ADFS:
        return True
    return False

import traceback

if __name__ == '__main__':
    opts = parser.parse_args()

    with open(opts.fsdump, 'r') as f:
        fsdump = json.loads(f.read())

    pes = ProfileElementSequence()

    # FIXME: fsdump has strting-name path, but we need FID-list path for ProfileElementSequence
    for path, fsdump_ef in fsdump['files'].items():
        print("=" * 80)
        #print(fsdump_ef)
        if not 'fcp_raw' in fsdump_ef:
            continue
        if has_unsupported_path_prefix(fsdump_ef['path']):
            print("Skipping eSIM-unsupported path %s" % ('/'.join(fsdump_ef['path'])))
            continue
        saip_dec = FsdumpToSaip.fcp_fsdump2saip(fsdump_ef)
        #print(saip_dec)
        try:
            f = pes.add_file_at_path(Path(path), saip_dec)
            print(repr(f))
        except Exception as e:
            print("EXCEPTION: %s" % traceback.format_exc())
            #print("EXCEPTION: %s" % e)
            continue

    print("=== Tree === ")
    pes.mf.print_tree()

    # FIXME: export the actual PE Sequence

