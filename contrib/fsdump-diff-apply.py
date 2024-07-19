#!/usr/bin/env python3

# The purpose of this script is to
# * load two SIM card 'fsdump' files
# * determine which file contents in "B" differs from that of "A"
# * create a pySim-shell script to update the contents of "A" to match that of "B"

# (C) 2024 by Harald Welte <laforge@osmocom.org>
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

import json
import argparse

# Files that we should not update
FILES_TO_SKIP = [
    "MF/EF.ICCID",
    #"MF/DF.GSM/EF.IMSI",
    #"MF/ADF.USIM/EF.IMSI",
    ]

# Files that need zero-padding at the end, not ff-padding
FILES_PAD_ZERO = [
    "DF.GSM/EF.SST",
    "MF/ADF.USIM/EF.UST",
    "MF/ADF.USIM/EF.EST",
    "MF/ADF.ISIM/EF.IST",
    ]

def pad_file(path, instr, byte_len):
    if path in FILES_PAD_ZERO:
        pad = '0'
    else:
        pad = 'f'
    return pad_hexstr(instr, byte_len, pad)

def pad_hexstr(instr, byte_len:int, pad='f'):
    """Pad given hex-string to the number of bytes given in byte_len, using ff as padding."""
    if len(instr) == byte_len*2:
        return instr
    elif len(instr) > byte_len*2:
        raise ValueError('Cannot pad string of length %u to smaller length %u' % (len(instr)/2, byte_len))
    else:
        return instr + pad * (byte_len*2 - len(instr))

def is_all_ff(instr):
    """Determine if the entire input hex-string consists of f-digits."""
    if all([x == 'f' for x in instr.lower()]):
        return True
    else:
        return False

parser = argparse.ArgumentParser()
parser.add_argument('file_a')
parser.add_argument('file_b')


if __name__ == '__main__':
    opts = parser.parse_args()

    with open(opts.file_a, 'r') as file_a:
        json_a = json.loads(file_a.read())
    with open(opts.file_b, 'r') as file_b:
        json_b = json.loads(file_b.read())

    for path in json_b.keys():
        print()
        print("# %s" % path)

        if not path in json_a:
            raise ValueError("%s doesn't exist in file_a!" % path)

        if path in FILES_TO_SKIP:
            print("# skipped explicitly as it is in FILES_TO_SKIP")
            continue

        if not 'body' in json_b[path]:
            print("# file doesn't exist in B so we cannot possibly need to modify A")
            continue

        if not 'body' in json_a[path]:
            # file was not readable in original (permissions? deactivated?)
            print("# ERROR: %s not readable in A; please fix that" % path)
            continue

        body_a = json_a[path]['body']
        body_b = json_b[path]['body']
        if body_a == body_b:
            print("# file body is identical")
            continue

        file_size_a = json_a[path]['fcp']['file_size']
        file_size_b = json_b[path]['fcp']['file_size']

        cmds = []
        structure = json_b[path]['fcp']['file_descriptor']['file_descriptor_byte']['structure']
        if structure == 'transparent':
            val_a = body_a
            val_b = body_b
            if file_size_a < file_size_b:
                if not is_all_ff(val_b[2*file_size_a:]):
                    print("# ERROR: file_size_a (%u) < file_size_b (%u); please fix!" % (file_size_a, file_size_b))
                    continue
                else:
                    print("# WARN: file_size_a (%u) < file_size_b (%u); please fix!" % (file_size_a, file_size_b))
                    # truncate val_b to fit in A
                    val_b = val_b[:file_size_a*2]

            elif file_size_a != file_size_b:
                print("# NOTE: file_size_a (%u) != file_size_b (%u)" % (file_size_a, file_size_b))

            # Pad to file_size_a
            val_b = pad_file(path, val_b, file_size_a)
            if val_b != val_a:
                cmds.append("update_binary %s" % val_b)
            else:
                print("# padded file body is identical")
        elif structure in ['linear_fixed', 'cyclic']:
            record_len_a = json_a[path]['fcp']['file_descriptor']['record_len']
            record_len_b = json_b[path]['fcp']['file_descriptor']['record_len']
            if record_len_a < record_len_b:
                print("# ERROR: record_len_a (%u) < record_len_b (%u); please fix!" % (file_size_a, file_size_b))
                continue
            elif record_len_a != record_len_b:
                print("# NOTE: record_len_a (%u) != record_len_b (%u)" % (record_len_a, record_len_b))

            num_rec_a = file_size_a // record_len_a
            num_rec_b = file_size_b // record_len_b
            if num_rec_a < num_rec_b:
                if not all([is_all_ff(x) for x in body_b[num_rec_a:]]):
                    print("# ERROR: num_rec_a (%u) < num_rec_b (%u); please fix!" % (num_rec_a, num_rec_b))
                    continue
                else:
                    print("# WARN: num_rec_a (%u) < num_rec_b (%u); but they're empty" % (num_rec_a, num_rec_b))
            elif num_rec_a != num_rec_b:
                print("# NOTE: num_rec_a (%u) != num_rec_b (%u)" % (num_rec_a, num_rec_b))

            i = 0
            for r in body_b:
                if i < len(body_a):
                    break
                val_a = body_a[i]
                # Pad to record_len_a
                val_b = pad_file(path, body_b[i], record_len_a)
                if val_a != val_b:
                    cmds.append("update_record %u %s" % (i+1, val_b))
                i = i + 1
            if len(cmds) == 0:
                print("# padded file body is identical")
        elif structure == 'ber_tlv':
            print("# FIXME: Implement BER-TLV")
        else:
            raise ValueError('Unsupported structure %s' % structure)

        if len(cmds):
            print("select %s" % path)
            for cmd in cmds:
                print(cmd)
