#!/usr/bin/env python3

# Tool to restore (sanitize) card contents from backup files
#
# (C) 2024 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Philipp Maier
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

import sys
import os
import argparse

# Make sure we are int the root directly of pySim
if not os.access("pySim-shell.py", os.R_OK):
    print("This script must be executed from the pySim root directory")
    sys.exit(1)
sys.path.append("./")

from smartcard.util import toHexString, toBytes
from smartcard.System import readers
from smartcard.scard import SCARD_SHARE_EXCLUSIVE
from pySim.utils import i2h, h2i, dec_iccid, boxed_heading_str

def backup(reader:int, atr:str, iccid:str):
    """ Create a backup of the card contents """

    script_dir = os.path.abspath(os.path.dirname(__file__))
    restore_script = script_dir + "/card_backup_" + atr + "_" + iccid + ".script"

    cmdline = os.getcwd() + "/pySim-shell.py"
    cmdline += " -p " + str(reader)
    cmdline += " -e \"verify_adm\""
    cmdline += " -e \"echo creating restore script...\""
    cmdline += " -e \"export > " + restore_script + " > /dev/null\""
    cmdline += " --noprompt --csv " + script_dir + "/card_data.csv"

    print("Executing: " + cmdline)
    rc = os.system(cmdline)
    if rc != 0:
        print("Backup failed!")
        return

    print("Backup done!")

def restore(reader:int, atr:str, iccid:str):
    """ Restore the card contents from backup """

    script_dir = os.path.abspath(os.path.dirname(__file__))

    for file in os.listdir(script_dir):
        if "card_backup" in file:
            file_atr = os.path.basename(file).split('.')[0].split('_')[2]
            file_iccid = os.path.basename(file).split('.')[0].split('_')[3]

            if file_atr == atr and file_iccid == iccid:
                print("Found file: %s" % file)

                cmdline = os.getcwd() + "/pySim-shell.py"
                cmdline += " -p " + str(reader)
                cmdline += " -e \"verify_adm\""
                cmdline += " -e \"echo running restore script...\""
                cmdline += " -e \"run_script " + script_dir + "/" + file + " > /dev/null\""
                cmdline += " --noprompt --csv " + script_dir + "/card_data.csv"

                print("Executing: " + cmdline)
                rc = os.system(cmdline)
                if rc != 0:
                    print("Restore failed!")
                    return

                print("Restore done!")
                return

    print("Restore failed, no backup file found for this card!")

def iterate_cards(action):
    """ iterate over all cards, read the ATR and the ICCID of each card and perform an action """
    reader_list=readers()

    for i in range(len(reader_list)):
        print("\n" + boxed_heading_str("reader: %u" % i))

        # Connect to card reader
        try:
            reader_connection = reader_list[i].createConnection()
            reader_connection.connect(mode = SCARD_SHARE_EXCLUSIVE)
        except:
            print("unresponsive card, skipping...")
            continue

        # Get ATR and ICCID
        atr = i2h(reader_connection.getATR())
        reader_connection.disconnect()
        reader_connection.connect(mode = SCARD_SHARE_EXCLUSIVE)
        response, sw1, sw2 = reader_connection.transmit(h2i("a0a40000022fe2"))
        if sw1 != 0x9f:
            print("Unable to select EF.ICCID on card %s (sw1=%02x, sw2=%02x), skipping..." % (atr, sw1, sw2))
            continue
        response, sw1, sw2 = reader_connection.transmit(h2i("a0b000000a"))
        if [sw1, sw2] != [0x90, 0x00]:
            print("Unable to read EF.ICCID from card %s (sw1=%02x, sw2=%02x), skipping..." % (atr, sw1, sw2))
            continue
        iccid = dec_iccid(i2h(response))
        print("Found ATR: %s, ICCID: %s" % (atr, iccid))
        reader_connection.disconnect()

        action(i, atr, iccid)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Tool to automatically restore (sanitize) card contents from backup files.')
    parser.add_argument("-b", "--backup", dest="backup", action='store_true', help="(re)create backup files",
                        default=False)
    opts = parser.parse_args()
    if opts.backup:
        iterate_cards(backup)
    else:
        iterate_cards(restore)
