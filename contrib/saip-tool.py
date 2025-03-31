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

import os
import sys
import argparse
import logging
from pathlib import Path as PlPath
from typing import List
from osmocom.utils import h2b, b2h, swap_nibbles
from osmocom.construct import GreedyBytes, StripHeaderAdapter

from pySim.esim.saip import *
from pySim.esim.saip.validation import CheckBasicStructure
from pySim.pprint import HexBytesPrettyPrinter

pp = HexBytesPrettyPrinter(indent=4,width=500)

parser = argparse.ArgumentParser(description="""
Utility program to work with eSIM SAIP (SimAlliance Interoperable Profile) files.""")
parser.add_argument('INPUT_UPP', help='Unprotected Profile Package Input file')
parser.add_argument("--loglevel", dest="loglevel", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                    default='INFO', help="Set the logging level")
parser.add_argument('--debug', action='store_true', help='Enable DEBUG logging')
subparsers = parser.add_subparsers(dest='command', help="The command to perform", required=True)

parser_split = subparsers.add_parser('split', help='Split PE-Sequence into individual PEs')
parser_split.add_argument('--output-prefix', default='.', help='Prefix path/filename for output files')

parser_dump = subparsers.add_parser('dump', help='Dump information on PE-Sequence')
parser_dump.add_argument('mode', choices=['all_pe', 'all_pe_by_type', 'all_pe_by_naa'])
parser_dump.add_argument('--dump-decoded', action='store_true', help='Dump decoded PEs')

parser_check = subparsers.add_parser('check', help='Run constraint checkers on PE-Sequence')

parser_rpe = subparsers.add_parser('extract-pe', help='Extract specified PE to (DER encoded) file')
parser_rpe.add_argument('--pe-file', required=True, help='PE file name')
parser_rpe.add_argument('--identification', type=int, help='Extract PE matching specified identification')

parser_rpe = subparsers.add_parser('remove-pe', help='Remove specified PEs from PE-Sequence')
parser_rpe.add_argument('--output-file', required=True, help='Output file name')
parser_rpe.add_argument('--identification', default=[], type=int, action='append', help='Remove PEs matching specified identification')
parser_rpe.add_argument('--type', default=[], action='append', help='Remove PEs matching specified type')

parser_rn = subparsers.add_parser('remove-naa', help='Remove speciifed NAAs from PE-Sequence')
parser_rn.add_argument('--output-file', required=True, help='Output file name')
parser_rn.add_argument('--naa-type', required=True, choices=NAAs.keys(), help='Network Access Application type to remove')
# TODO: add an --naa-index or the like, so only one given instance can be removed

parser_info = subparsers.add_parser('info', help='Display information about the profile')
parser_info.add_argument('--apps', action='store_true', help='List applications and their related instances')

parser_eapp = subparsers.add_parser('extract-apps', help='Extract applications as loadblock file')
parser_eapp.add_argument('--output-dir', default='.', help='Output directory (where to store files)')
parser_eapp.add_argument('--format', default='cap', choices=['ijc', 'cap'], help='Data format of output files')

parser_aapp = subparsers.add_parser('add-app', help='Add application to PE-Sequence')
parser_aapp.add_argument('--output-file', required=True, help='Output file name')
parser_aapp.add_argument('--applet-file', required=True, help='Applet file name')
parser_aapp.add_argument('--aid', required=True, help='Load package AID')
parser_aapp.add_argument('--sd-aid', default=None, help='Security Domain AID')
parser_aapp.add_argument('--non-volatile-code-limit', default=None, type=int, help='Non volatile code limit (C6)')
parser_aapp.add_argument('--volatile-data-limit', default=None, type=int, help='Volatile data limit (C7)')
parser_aapp.add_argument('--non-volatile-data-limit', default=None, type=int, help='Non volatile data limit (C8)')
parser_aapp.add_argument('--hash-value', default=None, help='Hash value')

parser_rapp = subparsers.add_parser('remove-app', help='Remove application from PE-Sequence')
parser_rapp.add_argument('--output-file', required=True, help='Output file name')
parser_rapp.add_argument('--aid', required=True, help='Load package AID')

parser_aappi = subparsers.add_parser('add-app-inst', help='Add application instance to Application PE')
parser_aappi.add_argument('--output-file', required=True, help='Output file name')
parser_aappi.add_argument('--aid', required=True, help='Load package AID')
parser_aappi.add_argument('--class-aid', required=True, help='Class AID')
parser_aappi.add_argument('--inst-aid', required=True, help='Instance AID (must match Load package AID)')
parser_aappi.add_argument('--app-privileges', default='000000', help='Application privileges')
parser_aappi.add_argument('--volatile-memory-quota', default=None, type=int, help='Volatile memory quota (C7)')
parser_aappi.add_argument('--non-volatile-memory-quota', default=None, type=int, help='Non volatile memory quota (C8)')
parser_aappi.add_argument('--app-spec-pars', default='00', help='Application specific parameters (C9)')
parser_aappi.add_argument('--uicc-toolkit-app-spec-pars', help='UICC toolkit application specific parameters field')
parser_aappi.add_argument('--uicc-access-app-spec-pars', help='UICC Access application specific parameters field')
parser_aappi.add_argument('--uicc-adm-access-app-spec-pars', help='UICC Administrative access application specific parameters field')
parser_aappi.add_argument('--process-data', default=[], action='append', help='Process personalization APDUs')

parser_rappi = subparsers.add_parser('remove-app-inst', help='Remove application instance from Application PE')
parser_rappi.add_argument('--output-file', required=True, help='Output file name')
parser_rappi.add_argument('--aid', required=True, help='Load package AID')
parser_rappi.add_argument('--inst-aid', required=True, help='Instance AID')

esrv_flag_choices = [t.name for t in asn1.types['ServicesList'].type.root_members]
parser_esrv = subparsers.add_parser('edit-mand-srv-list', help='Add/Remove service flag from/to mandatory services list')
parser_esrv.add_argument('--output-file', required=True, help='Output file name')
parser_esrv.add_argument('--add-flag', default=[], choices=esrv_flag_choices, action='append', help='Add flag to mandatory services list')
parser_esrv.add_argument('--remove-flag', default=[], choices=esrv_flag_choices, action='append', help='Remove flag from mandatory services list')

parser_info = subparsers.add_parser('tree', help='Display the filesystem tree')

def write_pes(pes: ProfileElementSequence, output_file:str):
    """write the PE sequence to a file"""
    print("Writing %u PEs to file '%s'..." % (len(pes.pe_list), output_file))
    with open(output_file, 'wb') as f:
        f.write(pes.to_der())

def do_split(pes: ProfileElementSequence, opts):
    i = 0
    for pe in pes.pe_list:
        basename = PlPath(opts.INPUT_UPP).stem
        if not pe.identification:
            fname = '%s-%02u-%s.der' % (basename, i, pe.type)
        else:
            fname = '%s-%02u-%05u-%s.der' % (basename, i, pe.identification, pe.type)
        print("writing single PE to file '%s'" % fname)
        with open(os.path.join(opts.output_prefix, fname), 'wb') as outf:
            outf.write(pe.to_der())
        i += 1

def do_dump(pes: ProfileElementSequence, opts):
    def print_all_pe(pes: ProfileElementSequence, dump_decoded:bool = False):
        # iterate over each pe in the pes (using its __iter__ method)
        for pe in pes:
            print("="*70 + " " + pe.type)
            if dump_decoded:
                pp.pprint(pe.decoded)

    def print_all_pe_by_type(pes: ProfileElementSequence, dump_decoded:bool = False):
        # sort by PE type and show all PE within that type
        for pe_type in pes.pe_by_type.keys():
            print("="*70 + " " + pe_type)
            for pe in pes.pe_by_type[pe_type]:
                pp.pprint(pe)
                if dump_decoded:
                    pp.pprint(pe.decoded)

    def print_all_pe_by_naa(pes: ProfileElementSequence, dump_decoded:bool = False):
        for naa in pes.pes_by_naa:
            i = 0
            for naa_instance in pes.pes_by_naa[naa]:
                print("="*70 + " " + naa + str(i))
                i += 1
                for pe in naa_instance:
                    pp.pprint(pe.type)
                    if dump_decoded:
                        for d in pe.decoded:
                            print("    %s" % d)

    if opts.mode == 'all_pe':
        print_all_pe(pes, opts.dump_decoded)
    elif opts.mode == 'all_pe_by_type':
        print_all_pe_by_type(pes, opts.dump_decoded)
    elif opts.mode == 'all_pe_by_naa':
        print_all_pe_by_naa(pes, opts.dump_decoded)

def do_check(pes: ProfileElementSequence, opts):
    print("Checking PE-Sequence structure...")
    checker = CheckBasicStructure()
    checker.check(pes)
    print("All good!")

def do_extract_pe(pes: ProfileElementSequence, opts):
    new_pe_list = []
    for pe in pes.pe_list:
        if pe.identification == opts.identification:
            print("Extracting PE %s (id=%u) to file %s..." % (pe, pe.identification, opts.pe_file))
            with open(opts.pe_file, 'wb') as f:
                f.write(pe.to_der())

def do_remove_pe(pes: ProfileElementSequence, opts):
    new_pe_list = []
    for pe in pes.pe_list:
        identification = pe.identification
        if identification:
            if identification in opts.identification:
                print("Removing PE %s (id=%u) from Sequence..." % (pe, identification))
                continue
        if pe.type in opts.type:
            print("Removing PE %s (type=%s) from Sequence..." % (pe, pe.type))
            continue
        new_pe_list.append(pe)

    pes.pe_list = new_pe_list
    pes._process_pelist()
    write_pes(pes, opts.output_file)

def do_remove_naa(pes: ProfileElementSequence, opts):
    if not opts.naa_type in NAAs:
        raise ValueError('unsupported NAA type %s' % opts.naa_type)
    naa = NAAs[opts.naa_type]
    print("Removing NAAs of type '%s' from Sequence..." % opts.naa_type)
    pes.remove_naas_of_type(naa)
    write_pes(pes, opts.output_file)

def info_apps(pes:ProfileElementSequence):
    def show_member(dictionary:Optional[dict], member:str, indent:str="\t", mandatory:bool = False, limit:bool = False):
        if dictionary is None:
            return
        value = dictionary.get(member, None)
        if value is None and mandatory == True:
            print("%s%s: (missing!)" % (indent, member))
            return
        elif value is None:
            return

        if limit and len(value) > 40:
            print("%s%s: '%s...%s' (%u bytes)" % (indent, member, b2h(value[:20]), b2h(value[-20:]), len(value)))
        else:
            print("%s%s: '%s' (%u bytes)" % (indent, member, b2h(value), len(value)))

    apps = pes.pe_by_type.get('application', [])
    if len(apps) == 0:
        print("No Application PE present!")
        return;

    for app_pe in enumerate(apps):
        print("Application #%u:" % app_pe[0])
        print("\tloadBlock:")
        load_block = app_pe[1].decoded['loadBlock']
        show_member(load_block, 'loadPackageAID', "\t\t", True)
        show_member(load_block, 'securityDomainAID', "\t\t")
        show_member(load_block, 'nonVolatileCodeLimitC6', "\t\t")
        show_member(load_block, 'volatileDataLimitC7', "\t\t")
        show_member(load_block, 'nonVolatileDataLimitC8', "\t\t")
        show_member(load_block, 'hashValue', "\t\t")
        show_member(load_block, 'loadBlockObject', "\t\t", True, True)
        for inst in enumerate(app_pe[1].decoded.get('instanceList', [])):
            print("\tinstanceList[%u]:" % inst[0])
            show_member(inst[1], 'applicationLoadPackageAID', "\t\t", True)
            if inst[1].get('applicationLoadPackageAID', None) != load_block.get('loadPackageAID', None):
                print("\t\t(applicationLoadPackageAID should be the same as loadPackageAID!)")
            show_member(inst[1], 'classAID', "\t\t", True)
            show_member(inst[1], 'instanceAID', "\t\t", True)
            show_member(inst[1], 'extraditeSecurityDomainAID', "\t\t")
            show_member(inst[1], 'applicationPrivileges', "\t\t", True)
            show_member(inst[1], 'lifeCycleState', "\t\t", True)
            show_member(inst[1], 'applicationSpecificParametersC9', "\t\t", True)
            sys_specific_pars = inst[1].get('systemSpecificParameters', None)
            if sys_specific_pars:
                print("\t\tsystemSpecificParameters:")
                show_member(sys_specific_pars, 'volatileMemoryQuotaC7', "\t\t\t")
                show_member(sys_specific_pars, 'nonVolatileMemoryQuotaC8', "\t\t\t")
                show_member(sys_specific_pars, 'globalServiceParameters', "\t\t\t")
                show_member(sys_specific_pars, 'implicitSelectionParameter', "\t\t\t")
                show_member(sys_specific_pars, 'volatileReservedMemory', "\t\t\t")
                show_member(sys_specific_pars, 'nonVolatileReservedMemory', "\t\t\t")
                show_member(sys_specific_pars, 'ts102226SIMFileAccessToolkitParameter', "\t\t\t")
                additional_cl_pars = inst.get('ts102226AdditionalContactlessParameters', None)
                if additional_cl_pars:
                    print("\t\t\tts102226AdditionalContactlessParameters:")
                    show_member(additional_cl_pars, 'protocolParameterData', "\t\t\t\t")
                show_member(sys_specific_pars, 'userInteractionContactlessParameters', "\t\t\t")
                show_member(sys_specific_pars, 'cumulativeGrantedVolatileMemory', "\t\t\t")
                show_member(sys_specific_pars, 'cumulativeGrantedNonVolatileMemory', "\t\t\t")
            app_pars = inst[1].get('applicationParameters', None)
            if app_pars:
                print("\t\tapplicationParameters:")
                show_member(app_pars, 'uiccToolkitApplicationSpecificParametersField', "\t\t\t")
                show_member(app_pars, 'uiccAccessApplicationSpecificParametersField', "\t\t\t")
                show_member(app_pars, 'uiccAdministrativeAccessApplicationSpecificParametersField', "\t\t\t")
            ctrl_ref_tp = inst[1].get('controlReferenceTemplate', None)
            if ctrl_ref_tp:
                print("\t\tcontrolReferenceTemplate:")
                show_member(ctrl_ref_tp, 'applicationProviderIdentifier', "\t\t\t", True)
            process_data = inst[1].get('processData', None)
            if process_data:
                print("\t\tprocessData:")
                for proc in process_data:
                    print("\t\t\t" + b2h(proc))

def do_info(pes: ProfileElementSequence, opts):
    def get_naa_count(pes: ProfileElementSequence) -> dict:
        """return a dict with naa-type (usim, isim) as key and the count of NAA instances as value."""
        ret = {}
        for naa_type in pes.pes_by_naa:
            ret[naa_type] = len(pes.pes_by_naa[naa_type])
        return ret

    if opts.apps:
        info_apps(pes)
        return;

    pe_hdr_dec = pes.pe_by_type['header'][0].decoded
    print()
    print("SAIP Profile Version: %u.%u" % (pe_hdr_dec['major-version'], pe_hdr_dec['minor-version']))
    print("Profile Type: '%s'" % pe_hdr_dec['profileType'])
    print("ICCID: %s" % b2h(pe_hdr_dec['iccid']))
    print("Mandatory Services: %s" % ', '.join(pe_hdr_dec['eUICC-Mandatory-services'].keys()))
    print()
    naa_strs = ["%s[%u]" % (k, v) for k, v in get_naa_count(pes).items()]
    print("NAAs: %s" % ', '.join(naa_strs))
    for naa_type in pes.pes_by_naa:
        for naa_inst in pes.pes_by_naa[naa_type]:
            first_pe = naa_inst[0]
            adf_name = ''
            if hasattr(first_pe, 'adf_name'):
                adf_name = '(' + first_pe.adf_name + ')'
            print("NAA %s %s" % (first_pe.type, adf_name))
            if hasattr(first_pe, 'imsi'):
                print("\tIMSI: %s" % first_pe.imsi)

    # applications
    print()
    apps = pes.pe_by_type.get('application', [])
    print("Number of applications: %u" % len(apps))
    for app_pe in apps:
        print("App Load Package AID: %s" % b2h(app_pe.decoded['loadBlock']['loadPackageAID']))
        print("\tMandated: %s" % ('mandated' in app_pe.decoded['app-Header']))
        print("\tLoad Block Size: %s" % len(app_pe.decoded['loadBlock']['loadBlockObject']))
        for inst in app_pe.decoded.get('instanceList', []):
            print("\tInstance AID: %s" % b2h(inst['instanceAID']))

    # security domains
    print()
    sds = pes.pe_by_type.get('securityDomain', [])
    print("Number of security domains: %u" % len(sds))
    for sd in sds:
        print("Security domain Instance AID: %s" % b2h(sd.decoded['instance']['instanceAID']))
        # FIXME: 'applicationSpecificParametersC9' parsing to figure out enabled SCP
        for key in sd.keys:
            print("\tKVN=0x%02x, KID=0x%02x, %s" % (key.key_version_number, key.key_identifier, key.key_components))

    # RFM
    print()
    rfms = pes.pe_by_type.get('rfm', [])
    print("Number of RFM instances: %u" % len(rfms))
    for rfm in rfms:
        inst_aid = rfm.decoded['instanceAID']
        print("RFM instanceAID: %s" % b2h(inst_aid))
        print("\tMSL: 0x%02x" % rfm.decoded['minimumSecurityLevel'][0])
        adf = rfm.decoded.get('adfRFMAccess', None)
        if adf:
            print("\tADF AID: %s" % b2h(adf['adfAID']))
        tar_list = rfm.decoded.get('tarList', [inst_aid[-3:]])
        for tar in tar_list:
            print("\tTAR: %s" % b2h(tar))

def do_extract_apps(pes:ProfileElementSequence, opts):
    apps = pes.pe_by_type.get('application', [])
    for app_pe in apps:
        package_aid = b2h(app_pe.decoded['loadBlock']['loadPackageAID'])
        fname = os.path.join(opts.output_dir, '%s-%s.%s' % (pes.iccid, package_aid, opts.format))
        print("Writing Load Package AID: %s to file %s" % (package_aid, fname))
        app_pe.to_file(fname)

def do_add_app(pes:ProfileElementSequence, opts):
    print("Applying applet file: '%s'..." % opts.applet_file)
    app_pe = ProfileElementApplication.from_file(opts.applet_file,
                                                 opts.aid,
                                                 opts.sd_aid,
                                                 opts.non_volatile_code_limit,
                                                 opts.volatile_data_limit,
                                                 opts.non_volatile_data_limit,
                                                 opts.hash_value)

    security_domain = pes.pe_by_type.get('securityDomain', [])
    if len(security_domain) == 0:
        print("profile package does not contain a securityDomain, please add a securityDomain PE first!")
    elif len(security_domain) > 1:
        print("adding an application PE to profiles with multiple securityDomain is not supported yet!")
    else:
        pes.insert_after_pe(security_domain[0], app_pe)
        print("application PE inserted into PE Sequence after securityDomain PE AID: %s" %
              b2h(security_domain[0].decoded['instance']['instanceAID']))
        write_pes(pes, opts.output_file)

def do_remove_app(pes:ProfileElementSequence, opts):
    apps = pes.pe_by_type.get('application', [])
    for app_pe in apps:
        package_aid = b2h(app_pe.decoded['loadBlock']['loadPackageAID'])
        if opts.aid == package_aid:
            identification = app_pe.identification
            opts_remove_pe = argparse.Namespace()
            opts_remove_pe.identification = [app_pe.identification]
            opts_remove_pe.type = []
            opts_remove_pe.output_file = opts.output_file
            print("Found Load Package AID: %s, removing related PE (id=%u) from Sequence..." %
                  (package_aid, identification))
            do_remove_pe(pes, opts_remove_pe)
            return
    print("Load Package AID: %s not found in PE Sequence" % opts.aid)

def do_add_app_inst(pes:ProfileElementSequence, opts):
    apps = pes.pe_by_type.get('application', [])
    for app_pe in apps:
        package_aid = b2h(app_pe.decoded['loadBlock']['loadPackageAID'])
        if opts.aid == package_aid:
            print("Found Load Package AID: %s, adding new instance AID: %s to Application PE..." %
                  (opts.aid, opts.inst_aid))
            app_pe.add_instance(opts.aid,
                                opts.class_aid,
                                opts.inst_aid,
                                opts.app_privileges,
                                opts.app_spec_pars,
                                opts.uicc_toolkit_app_spec_pars,
                                opts.uicc_access_app_spec_pars,
                                opts.uicc_adm_access_app_spec_pars,
                                opts.volatile_memory_quota,
                                opts.non_volatile_memory_quota,
                                opts.process_data)
            write_pes(pes, opts.output_file)
            return
    print("Load Package AID: %s not found in PE Sequence" % opts.aid)

def do_remove_app_inst(pes:ProfileElementSequence, opts):
    apps = pes.pe_by_type.get('application', [])
    for app_pe in apps:
        if opts.aid == b2h(app_pe.decoded['loadBlock']['loadPackageAID']):
            print("Found Load Package AID: %s, removing instance AID: %s from Application PE..." %
                  (opts.aid, opts.inst_aid))
            app_pe.remove_instance(opts.inst_aid)
            write_pes(pes, opts.output_file)
            return
    print("Load Package AID: %s not found in PE Sequence" % opts.aid)

def do_edit_mand_srv_list(pes: ProfileElementSequence, opts):
    header = pes.pe_by_type.get('header', [])[0]

    for s in opts.add_flag:
        print("Adding service '%s' to mandatory services list..." % s)
        header.mandatory_service_add(s)
    for s in opts.remove_flag:
        if s in header.decoded['eUICC-Mandatory-services'].keys():
            print("Removing service '%s' from mandatory services list..." % s)
            header.mandatory_service_remove(s)
        else:
            print("Service '%s' not present in mandatory services list, cannot remove!" % s)

    print("The following services are now set mandatory:")
    for s in header.decoded['eUICC-Mandatory-services'].keys():
        print("\t%s" % s)

    write_pes(pes, opts.output_file)

def do_tree(pes:ProfileElementSequence, opts):
    pes.mf.print_tree()

if __name__ == '__main__':
    opts = parser.parse_args()

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.getLevelName(opts.loglevel))

    with open(opts.INPUT_UPP, 'rb') as f:
        pes = ProfileElementSequence.from_der(f.read())

    print("Read %u PEs from file '%s'" % (len(pes.pe_list), opts.INPUT_UPP))

    if opts.command == 'split':
        do_split(pes, opts)
    elif opts.command == 'dump':
        do_dump(pes, opts)
    elif opts.command == 'check':
        do_check(pes, opts)
    elif opts.command == 'extract-pe':
        do_extract_pe(pes, opts)
    elif opts.command == 'remove-pe':
        do_remove_pe(pes, opts)
    elif opts.command == 'remove-naa':
        do_remove_naa(pes, opts)
    elif opts.command == 'info':
        do_info(pes, opts)
    elif opts.command == 'extract-apps':
        do_extract_apps(pes, opts)
    elif opts.command == 'add-app':
        do_add_app(pes, opts)
    elif opts.command == 'remove-app':
        do_remove_app(pes, opts)
    elif opts.command == 'add-app-inst':
        do_add_app_inst(pes, opts)
    elif opts.command == 'remove-app-inst':
        do_remove_app_inst(pes, opts)
    elif opts.command == 'edit-mand-srv-list':
        do_edit_mand_srv_list(pes, opts)
    elif opts.command == 'tree':
        do_tree(pes, opts)
