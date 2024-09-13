#!/usr/bin/env python3

#
# Utility to deal with sim cards and program the 'magic' ones easily
#
#
# Part of the sim link code of inspired by pySimReader-Serial-src-v2
#
#
# Copyright (C) 2009  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2010  Harald Welte <laforge@gnumonks.org>
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

import hashlib
import argparse
import os
import random
import re
import sys
import traceback
import json
import csv
from osmocom.utils import h2b, swap_nibbles, rpad

from pySim.commands import SimCardCommands
from pySim.transport import init_reader, argparse_add_reader_args
from pySim.legacy.cards import _cards_classes, card_detect
from pySim.utils import derive_milenage_opc, calculate_luhn, dec_iccid
from pySim.ts_51_011 import EF_AD
from pySim.legacy.ts_51_011 import EF
from pySim.card_handler import *
from pySim.utils import *


def parse_options():

    parser = argparse.ArgumentParser()
    argparse_add_reader_args(parser)

    parser.add_argument("-t", "--type", dest="type",
                      help="Card type (user -t list to view) [default: %(default)s]",
                      default="auto",
                      )
    parser.add_argument("-T", "--probe", dest="probe",
                      help="Determine card type",
                      default=False, action="store_true"
                      )
    parser.add_argument("-a", "--pin-adm", dest="pin_adm",
                      help="ADM PIN used for provisioning (overwrites default)",
                      )
    parser.add_argument("-A", "--pin-adm-hex", dest="pin_adm_hex",
                      help="ADM PIN used for provisioning, as hex string (16 characters long",
                      )
    parser.add_argument("-e", "--erase", dest="erase", action='store_true',
                      help="Erase beforehand [default: %(default)s]",
                      default=False,
                      )

    parser.add_argument("-S", "--source", dest="source",
                      help="Data Source[default: %(default)s]",
                      default="cmdline",
                      )

    # if mode is "cmdline"
    parser.add_argument("-n", "--name", dest="name",
                      help="Operator name [default: %(default)s]",
                      default="Magic",
                      )
    parser.add_argument("-c", "--country", dest="country", type=int, metavar="CC",
                      help="Country code [default: %(default)s]",
                      default=1,
                      )
    parser.add_argument("-x", "--mcc", dest="mcc",
                      help="Mobile Country Code [default: %(default)s]",
                      default="901",
                      )
    parser.add_argument("-y", "--mnc", dest="mnc",
                      help="Mobile Network Code [default: %(default)s]",
                      default="55",
                      )
    parser.add_argument("--mnclen", dest="mnclen",
                      help="Length of Mobile Network Code [default: %(default)s]",
                      default="auto",
                      choices=["2", "3", "auto"],
                      )
    parser.add_argument("-m", "--smsc", dest="smsc",
                      help="SMSC number (Start with + for international no.) [default: '00 + country code + 5555']",
                      )
    parser.add_argument("-M", "--smsp", dest="smsp",
                      help="Raw SMSP content in hex [default: auto from SMSC]",
                      )

    parser.add_argument("-s", "--iccid", dest="iccid", metavar="ID",
                      help="Integrated Circuit Card ID",
                      )
    parser.add_argument("-i", "--imsi", dest="imsi",
                      help="International Mobile Subscriber Identity",
                      )
    parser.add_argument("--msisdn", dest="msisdn",
                      help="Mobile Subscriber Integrated Services Digital Number",
                      )
    parser.add_argument("-k", "--ki", dest="ki",
                      help="Ki (default is to randomize)",
                      )
    parser.add_argument("-o", "--opc", dest="opc",
                      help="OPC (default is to randomize)",
                      )
    parser.add_argument("--op", dest="op",
                      help="Set OP to derive OPC from OP and KI",
                      )
    parser.add_argument("--acc", dest="acc",
                      help="Set ACC bits (Access Control Code). not all card types are supported",
                      )
    parser.add_argument("--opmode", dest="opmode",
                      help="Set UE Operation Mode in EF.AD (Administrative Data)",
                      default=None,
                      choices=['{:02X}'.format(int(m)) for m in EF_AD.OP_MODE],
                      )
    parser.add_argument("-f", "--fplmn", dest="fplmn", action="append",
                      help="Set Forbidden PLMN. Add multiple time for multiple FPLMNS",
                      )
    parser.add_argument("--epdgid", dest="epdgid",
                      help="Set Home Evolved Packet Data Gateway (ePDG) Identifier. (Only FQDN format supported)",
                      )
    parser.add_argument("--epdgSelection", dest="epdgSelection",
                      help="Set PLMN for ePDG Selection Information. (Only Operator Identifier FQDN format supported)",
                      )
    parser.add_argument("--pcscf", dest="pcscf",
                      help="Set Proxy Call Session Control Function (P-CSCF) Address. (Only FQDN format supported)",
                      )
    parser.add_argument("--ims-hdomain", dest="ims_hdomain",
                      help="Set IMS Home Network Domain Name in FQDN format",
                      )
    parser.add_argument("--impi", dest="impi",
                      help="Set IMS private user identity",
                      )
    parser.add_argument("--impu", dest="impu",
                      help="Set IMS public user identity",
                      )
    parser.add_argument("--read-imsi", dest="read_imsi", action="store_true",
                      help="Read the IMSI from the CARD", default=False
                      )
    parser.add_argument("--read-iccid", dest="read_iccid", action="store_true",
                      help="Read the ICCID from the CARD", default=False
                      )
    parser.add_argument("-z", "--secret", dest="secret", metavar="STR",
                      help="Secret used for ICCID/IMSI autogen",
                      )
    parser.add_argument("-j", "--num", dest="num", type=int,
                      help="Card # used for ICCID/IMSI autogen",
                      )
    parser.add_argument("--batch", dest="batch_mode",
                      help="Enable batch mode [default: %(default)s]",
                      default=False, action='store_true',
                      )
    parser.add_argument("--batch-state", dest="batch_state", metavar="FILE",
                      help="Optional batch state file",
                      )

    # if mode is "csv"
    parser.add_argument("--read-csv", dest="read_csv", metavar="FILE",
                      help="Read parameters from CSV file rather than command line")

    parser.add_argument("--write-csv", dest="write_csv", metavar="FILE",
                      help="Append generated parameters in CSV file",
                      )
    parser.add_argument("--write-hlr", dest="write_hlr", metavar="FILE",
                      help="Append generated parameters to OpenBSC HLR sqlite3",
                      )
    parser.add_argument("--dry-run", dest="dry_run",
                      help="Perform a 'dry run', don't actually program the card",
                      default=False, action="store_true")
    parser.add_argument("--card_handler", dest="card_handler_config", metavar="FILE",
                      help="Use automatic card handling machine")

    options = parser.parse_args()

    if options.type == 'list':
        for kls in _cards_classes:
            print(kls.name)
        sys.exit(0)

    if options.probe:
        return options

    if options.source == 'csv':
        if (options.imsi is None) and (options.iccid is None)  and (options.read_imsi is False) and (options.read_iccid is False):
           parser.error("CSV mode requires one additional parameter: --read-iccid, --read-imsi, --iccid or --imsi")
        if options.read_csv is None:
            parser.error("CSV mode requires a CSV input file")
    elif options.source == 'cmdline':
        if ((options.imsi is None) or (options.iccid is None)) and (options.num is None):
            parser.error("If either IMSI or ICCID isn't specified, num is required")
    else:
        parser.error("Only `cmdline' and `csv' sources supported")

    if (options.read_csv is not None) and (options.source != 'csv'):
        parser.error("You cannot specify a CSV input file in source != csv")

    if (options.batch_mode) and (options.num is None):
        options.num = 0

    if (options.batch_mode):
        if (options.imsi is not None) or (options.iccid is not None):
            parser.error(
                "Can't give ICCID/IMSI for batch mode, need to use automatic parameters ! see --num and --secret for more information")

    return options


def _digits(secret, usage, len, num):
    seed = secret + usage + '%d' % num
    s = hashlib.sha1(seed.encode())
    d = ''.join(['%02d' % x for x in s.digest()])
    return d[0:len]


def _mcc_mnc_digits(mcc, mnc):
    return '%s%s' % (mcc, mnc)


def _cc_digits(cc):
    return ('%03d' if cc > 100 else '%02d') % cc


def _isnum(s, l=-1):
    return s.isdigit() and ((l == -1) or (len(s) == l))


def _ishex(s, l=-1):
    hc = '0123456789abcdef'
    return all([x in hc for x in s.lower()]) and ((l == -1) or (len(s) == l))


def _dbi_binary_quote(s):
    # Count usage of each char
    cnt = {}
    for c in s:
        cnt[c] = cnt.get(c, 0) + 1

    # Find best offset
    e = 0
    m = len(s)
    for i in range(1, 256):
        if i == 39:
            continue
        sum_ = cnt.get(i, 0) + cnt.get((i+1) & 0xff, 0) + \
            cnt.get((i+39) & 0xff, 0)
        if sum_ < m:
            m = sum_
            e = i
            if m == 0:  # No overhead ? use this !
                break

    # Generate output
    out = []
    out.append(chr(e))  # Offset
    for c in s:
        x = (256 + ord(c) - e) % 256
        if x in (0, 1, 39):
            out.append('\x01')
            out.append(chr(x+1))
        else:
            out.append(chr(x))

    return ''.join(out)


def gen_parameters(opts):
    """Generates Name, ICCID, MCC, MNC, IMSI, SMSP, Ki, PIN-ADM from the
    options given by the user"""

    # MCC/MNC
    mcc = opts.mcc
    mnc = opts.mnc

    if not mcc.isdigit() or not mnc.isdigit():
        raise ValueError('mcc & mnc must only contain decimal digits')
    if len(mcc) < 1 or len(mcc) > 3:
        raise ValueError('mcc must be between 1 .. 3 digits')
    if len(mnc) < 1 or len(mnc) > 3:
        raise ValueError('mnc must be between 1 .. 3 digits')

    # MCC always has 3 digits
    mcc = lpad(mcc, 3, "0")

    # The MNC must be at least 2 digits long. This is also the most common case.
    # The user may specify an explicit length using the --mnclen option.
    if opts.mnclen != "auto":
        if len(mnc) > int(opts.mnclen):
            raise ValueError('mcc is longer than specified in option --mnclen')
        mnc = lpad(mnc, int(opts.mnclen), "0")
    else:
        mnc = lpad(mnc, 2, "0")

    # Digitize country code (2 or 3 digits)
    cc_digits = _cc_digits(opts.country)

    # Digitize MCC/MNC (5 or 6 digits)
    plmn_digits = _mcc_mnc_digits(mcc, mnc)

    if opts.name is not None:
        if len(opts.name) > 16:
            raise ValueError('Service Provider Name must max 16 characters!')

    if opts.msisdn is not None:
        msisdn = opts.msisdn
        if msisdn[0] == '+':
            msisdn = msisdn[1:]
        if not msisdn.isdigit():
            raise ValueError('MSISDN must be digits only! '
                             'Start with \'+\' for international numbers.')
        if len(msisdn) > 10 * 2:
            # TODO: Support MSISDN of length > 20 (10 Bytes)
            raise ValueError(
                'MSISDNs longer than 20 digits are not (yet) supported.')

    # ICCID (19 digits, E.118), though some phase1 vendors use 20 :(
    if opts.iccid is not None:
        iccid = opts.iccid
        if not _isnum(iccid, 18) and not _isnum(iccid, 19) and not _isnum(iccid, 20):
            raise ValueError('ICCID must be 18, 19 or 20 digits !')

    else:
        if opts.num is None:
            raise ValueError('Neither ICCID nor card number specified !')

        iccid = (
            '89' +			# Common prefix (telecom)
            cc_digits +		# Country Code on 2/3 digits
            plmn_digits 		# MCC/MNC on 5/6 digits
        )

        ml = 18 - len(iccid)

        if opts.secret is None:
            # The raw number
            iccid += ('%%0%dd' % ml) % opts.num
        else:
            # Randomized digits
            iccid += _digits(opts.secret, 'ccid', ml, opts.num)

        # Add checksum digit
        iccid += ('%1d' % calculate_luhn(iccid))

    # IMSI (15 digits usually)
    if opts.imsi is not None:
        imsi = opts.imsi
        if not _isnum(imsi):
            raise ValueError('IMSI must be digits only !')

    else:
        if opts.num is None:
            raise ValueError('Neither IMSI nor card number specified !')

        ml = 15 - len(plmn_digits)

        if opts.secret is None:
            # The raw number
            msin = ('%%0%dd' % ml) % opts.num
        else:
            # Randomized digits
            msin = _digits(opts.secret, 'imsi', ml, opts.num)

        imsi = (
            plmn_digits +  # MCC/MNC on 5/6 digits
            msin			# MSIN
        )

    # SMSP
    if opts.smsp is not None:
        smsp = opts.smsp
        if not _ishex(smsp):
            raise ValueError('SMSP must be hex digits only !')
        if len(smsp) < 28*2:
            raise ValueError('SMSP must be at least 28 bytes')

    else:
        ton = "81"
        if opts.smsc is not None:
            smsc = opts.smsc
            if smsc[0] == '+':
                ton = "91"
                smsc = smsc[1:]
            if not _isnum(smsc):
                raise ValueError('SMSC must be digits only!\n \
					Start with \'+\' for international numbers')
        else:
            smsc = '00%d' % opts.country + '5555'  # Hack ...

        smsc = '%02d' % ((len(smsc) + 3)//2,) + ton + \
            swap_nibbles(rpad(smsc, 20))

        smsp = (
            'e1' +			# Parameters indicator
            'ff' * 12 +		# TP-Destination address
            smsc +			# TP-Service Centre Address
            '00' +			# TP-Protocol identifier
            '00' +			# TP-Data coding scheme
            '00'			# TP-Validity period
        )

    # ACC
    if opts.acc is not None:
        acc = opts.acc
        if not _ishex(acc):
            raise ValueError('ACC must be hex digits only !')
        if len(acc) != 2*2:
            raise ValueError('ACC must be exactly 2 bytes')

    else:
        acc = None

    # Ki (random)
    if opts.ki is not None:
        ki = opts.ki
        if not re.match('^[0-9a-fA-F]{32}$', ki):
            raise ValueError('Ki needs to be 128 bits, in hex format')
    else:
        ki = ''.join(['%02x' % random.randrange(0, 256) for i in range(16)])

    # OPC (random)
    if opts.opc is not None:
        opc = opts.opc
        if not re.match('^[0-9a-fA-F]{32}$', opc):
            raise ValueError('OPC needs to be 128 bits, in hex format')

    elif opts.op is not None:
        opc = derive_milenage_opc(ki, opts.op)
    else:
        opc = ''.join(['%02x' % random.randrange(0, 256) for i in range(16)])

    pin_adm = sanitize_pin_adm(opts.pin_adm, opts.pin_adm_hex)

    # ePDG Selection Information
    if opts.epdgSelection:
        if len(opts.epdgSelection) < 5 or len(opts.epdgSelection) > 6:
            raise ValueError('ePDG Selection Information is not valid')
        epdg_mcc = opts.epdgSelection[:3]
        epdg_mnc = opts.epdgSelection[3:]
        if not epdg_mcc.isdigit() or not epdg_mnc.isdigit():
            raise ValueError(
                'PLMN for ePDG Selection must only contain decimal digits')

    # Return that
    return {
        'name': opts.name,
        'iccid': iccid,
        'mcc': mcc,
        'mnc': mnc,
        'imsi': imsi,
        'smsp': smsp,
        'ki': ki,
        'opc': opc,
        'acc': acc,
        'pin_adm': pin_adm,
        'msisdn': opts.msisdn,
        'epdgid': opts.epdgid,
        'epdgSelection': opts.epdgSelection,
        'pcscf': opts.pcscf,
        'ims_hdomain': opts.ims_hdomain,
        'impi': opts.impi,
        'impu': opts.impu,
        'opmode': opts.opmode,
        'fplmn': opts.fplmn,
    }


def print_parameters(params):

    s = ["Generated card parameters :"]
    if 'name' in params:
        s.append(" > Name     : %(name)s")
    if 'smsp' in params:
        s.append(" > SMSP     : %(smsp)s")
    s.append(" > ICCID    : %(iccid)s")
    s.append(" > MCC/MNC  : %(mcc)s/%(mnc)s")
    s.append(" > IMSI     : %(imsi)s")
    s.append(" > Ki       : %(ki)s")
    s.append(" > OPC      : %(opc)s")
    if 'acc' in params:
        s.append(" > ACC      : %(acc)s")
    s.append(" > ADM1(hex): %(pin_adm)s")
    if 'opmode' in params:
        s.append(" > OPMODE   : %(opmode)s")
    print("\n".join(s) % params)


def write_params_csv(opts, params):
    # csv
    if opts.write_csv:
        import csv
        row = ['name', 'iccid', 'mcc', 'mnc', 'imsi', 'smsp', 'ki', 'opc']
        f = open(opts.write_csv, 'a')
        cw = csv.writer(f)
        cw.writerow([params[x] for x in row])
        f.close()


def find_row_in_csv_file(csv_file_name:str, num=None, iccid=None, imsi=None):
    """
    Pick a matching row in a CSV file by row number or ICCID or IMSI. When num
    is not None, the search parameters iccid and imsi are ignored. When
    searching for a specific ICCID or IMSI the caller must set num to None. It
    is possible to search for an ICCID or an IMSI at the same time. The first
    line that either contains a matching ICCID or IMSI is returned. Unused
    search parameters must be set to None.
    """

    f = open(csv_file_name, 'r')
    cr = csv.DictReader(f)

    # Make sure the CSV file contains at least the fields we are searching for
    if not 'iccid' in cr.fieldnames:
        raise Exception("wrong CSV file format - no field \"iccid\" or missing header!")
    if not 'imsi' in cr.fieldnames:
        raise Exception("wrong CSV file format - no field \"imsi\" or missing header!")

    # Enforce at least one search parameter
    if not num and not iccid and not imsi:
        raise Exception("no CSV file search parameters!")

    # Lower-case fieldnames
    cr.fieldnames = [field.lower() for field in cr.fieldnames]

    i = 0
    for row in cr:
        # Pick a specific row by line number (num)
        if num is not None and iccid is None and imsi is None:
            if num == i:
                f.close()
                return row

	# Pick the first row that contains the specified ICCID
        if row['iccid'] == iccid:
            f.close()
            return row

	# Pick the first row that contains the specified IMSI
        if row['imsi'] == imsi:
            f.close()
            return row

        i += 1

    f.close()
    print("Could not read card parameters from CSV file, no matching entry found.")
    return None


def read_params_csv(opts, imsi=None, iccid=None):
    """
    Read the card parameters from a CSV file. This function will generate the
    same dictionary that gen_parameters would generate from parameters passed as
    commandline arguments.
    """

    row = find_row_in_csv_file(opts.read_csv, opts.num, iccid=iccid, imsi=imsi)
    if row is not None:
        row['mcc'] = row.get('mcc', mcc_from_imsi(row.get('imsi')))

        # We cannot determine the MNC length (2 or 3 digits?) from the IMSI
        # alone. In cases where the user has specified an mnclen via the
        # commandline options we can use that info, otherwise we guess that
        # the length is 2, which is also the most common case.
        if opts.mnclen != "auto":
            if opts.mnclen == "2":
                row['mnc'] = row.get('mnc', mnc_from_imsi(row.get('imsi'), False))
            elif opts.mnclen == "3":
                row['mnc'] = row.get('mnc', mnc_from_imsi(row.get('imsi'), True))
            else:
                raise ValueError("invalid parameter --mnclen, must be 2 or 3 or auto")
        else:
            row['mnc'] = row.get('mnc', mnc_from_imsi(row.get('imsi'), False))

	# NOTE: We might concider to specify a new CSV field "mnclen" in our
	# CSV files for a better automatization. However, this only makes sense
	# when the tools and databases we export our files from will also add
	# such a field.

        pin_adm = None
        # We need to escape the pin_adm we get from the csv
        if 'pin_adm' in row:
            pin_adm = ''.join(['%02x' % (ord(x)) for x in row['pin_adm']])
        # Stay compatible to the odoo csv format
        elif 'adm1' in row:
            pin_adm = ''.join(['%02x' % (ord(x)) for x in row['adm1']])
        if pin_adm:
            row['pin_adm'] = rpad(pin_adm, 16)

        # If the CSV-File defines a pin_adm_hex field use this field to
        # generate pin_adm from that.
        pin_adm_hex = row.get('pin_adm_hex')
        if pin_adm_hex:
            if len(pin_adm_hex) == 16:
                row['pin_adm'] = pin_adm_hex
                # Ensure that it's hex-encoded
                try:
                    try_encode = h2b(pin_adm)
                except ValueError:
                    raise ValueError(
                        "pin_adm_hex needs to be hex encoded using this option")
            else:
                raise ValueError(
                    "pin_adm_hex needs to be exactly 16 digits (hex encoded)")

    return row


def write_params_hlr(opts, params):
    # SQLite3 OpenBSC HLR
    # FIXME: The format of the osmo-hlr database has evolved, so that the code below will no longer work.
    print("Warning: the database format of recent OsmoHLR versions is not compatible with pySim-prog!")

    if opts.write_hlr:
        import sqlite3
        conn = sqlite3.connect(opts.write_hlr)

        c = conn.execute(
            'INSERT INTO Subscriber ' +
            '(imsi, name, extension, authorized, created, updated) ' +
            'VALUES ' +
            '(?,?,?,1,datetime(\'now\'),datetime(\'now\'));',
            [
                params['imsi'],
                params['name'],
                '9' + params['iccid'][-5:-1]
            ],
        )
        sub_id = c.lastrowid
        c.close()

        c = conn.execute(
            'INSERT INTO AuthKeys ' +
            '(subscriber_id, algorithm_id, a3a8_ki)' +
            'VALUES ' +
            '(?,?,?)',
            [sub_id, 2, sqlite3.Binary(
                _dbi_binary_quote(h2b(params['ki'])))],
        )

        conn.commit()
        conn.close()


def write_parameters_to_csv_and_hlr(opts, params):
    write_params_csv(opts, params)
    write_params_hlr(opts, params)


BATCH_STATE = ['name', 'country', 'mcc', 'mnc', 'smsp', 'secret', 'num']
BATCH_INCOMPATIBLE = ['iccid', 'imsi', 'ki']


def init_batch(opts):
    # Need to do something ?
    if not opts.batch_mode:
        return

    for k in BATCH_INCOMPATIBLE:
        if getattr(opts, k):
            print("Incompatible option with batch_state: %s" % (k,))
            sys.exit(-1)

    # Don't load state if there is none ...
    if not opts.batch_state:
        return

    if not os.path.isfile(opts.batch_state):
        print("No state file yet")
        return

    # Get stored data
    fh = open(opts.batch_state)
    d = json.loads(fh.read())
    fh.close()

    for k, v in d.iteritems():
        setattr(opts, k, v)


def save_batch(opts):
    # Need to do something ?
    if not opts.batch_mode or not opts.batch_state:
        return

    d = json.dumps(dict([(k, getattr(opts, k)) for k in BATCH_STATE]))
    fh = open(opts.batch_state, 'w')
    fh.write(d)
    fh.close()


def process_card(scc, opts, first, ch):

    # Connect transport
    ch.get(first)

    # Get card
    card = card_detect(opts.type, scc)
    if card is None:
        print("No card detected!")
        return -1

    # Probe only
    if opts.probe:
        return 0

    # Erase if requested (not in dry run mode!)
    if opts.dry_run is False:
        if opts.erase:
            print("Formatting ...")
            card.erase()
            card.reset()

    cp = None

    # Generate parameters
    if opts.source == 'cmdline':
        cp = gen_parameters(opts)
    elif opts.source == 'csv':
        if opts.read_iccid:
            (res, _) = scc.read_binary(['3f00', '2fe2'], length=10)
            iccid = dec_iccid(res)
        else:
            iccid = opts.iccid
        if opts.read_imsi:
            (res, _) = scc.read_binary(EF['IMSI'])
            imsi = swap_nibbles(res)[3:]
        else:
            imsi = opts.imsi
        cp = read_params_csv(opts, imsi=imsi, iccid=iccid)
    if cp is None:
        return 2
    print_parameters(cp)

    if opts.dry_run is False:
        # Program the card
        print("Programming ...")
        card.program(cp)
    else:
        print("Dry Run: NOT PROGRAMMING!")

    # Write parameters to a specified CSV file or an HLR database (not the card)
    write_parameters_to_csv_and_hlr(opts, cp)

    # Batch mode state update and save
    if opts.num is not None:
        opts.num += 1
    save_batch(opts)

    ch.done()
    return 0


if __name__ == '__main__':

    # Parse options
    opts = parse_options()

    # Init card reader driver
    sl = init_reader(opts)

    # Create command layer
    scc = SimCardCommands(transport=sl)

    # If we use a CSV file as data input, check if the CSV file exists.
    if opts.source == 'csv':
        print("Using CSV file as data input: " + str(opts.read_csv))
        if not os.path.isfile(opts.read_csv):
            print("CSV file not found!")
            sys.exit(1)

    # Batch mode init
    init_batch(opts)

    if opts.card_handler_config:
        ch = CardHandlerAuto(sl, opts.card_handler_config)
    else:
        ch = CardHandler(sl)

    # Iterate
    first = True
    card = None

    while 1:
        try:
            rc = process_card(scc, opts, first, ch)
        except (KeyboardInterrupt):
            print("")
            print("Terminated by user!")
            sys.exit(0)
        except (SystemExit):
            raise
        except:
            print("")
            print("Card programming failed with an exception:")
            print("---------------------8<---------------------")
            traceback.print_exc()
            print("---------------------8<---------------------")
            print("")
            rc = -1

        # Something did not work as well as expected, however, lets
        # make sure the card is pulled from the reader.
        if rc != 0:
            ch.error()

        # If we are not in batch mode we are done in any case, so lets
        # exit here.
        if not opts.batch_mode:
            sys.exit(rc)

        first = False
