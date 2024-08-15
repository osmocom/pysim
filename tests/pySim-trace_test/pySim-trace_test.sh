#!/bin/bash

# Utility to verify the functionality of pySim-trace.py
#
# (C) 2023 by Sysmocom s.f.m.c. GmbH
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

PYSIM_TRACE=./pySim-trace.py
GSMTAP_TRACE=./tests/pySim-trace_test/pySim-trace_test_gsmtap.pcapng
TEMPFILE=temp.tmp

export PYSIM_INTEGRATION_TEST=1
# to avoid termcolor.colored generating colors; https://github.com/termcolor/termcolor
export ANSI_COLORS_DISABLED=1

echo "pySim-trace_test - a test program to test pySim-trace.py"
echo "========================================================"

function usage {
    echo "Options:"
    echo "-o: generate .ok file"
}

function gen_ok_file {
    $PYSIM_TRACE gsmtap-pyshark-pcap -f $GSMTAP_TRACE > $GSMTAP_TRACE.ok
    echo "Generated file: $GSMTAP_TRACE.ok"
    echo "------------8<------------"
    cat $GSMTAP_TRACE.ok
    echo "------------8<------------"
}

function run_test {
    $PYSIM_TRACE gsmtap-pyshark-pcap -f $GSMTAP_TRACE | tee $TEMPFILE
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo ""
        echo "========================================================"
        echo "Testrun with $GSMTAP_TRACE failed (exception)."
        rm -f $TEMPFILE
        exit 1
    fi

    DIFF=`diff $GSMTAP_TRACE.ok $TEMPFILE`
    if ! [ -z "$DIFF" ]; then
        echo "Testrun with $GSMTAP_TRACE failed (unexpected output)."
        echo "------------8<------------"
        diff $GSMTAP_TRACE.ok $TEMPFILE
        echo "------------8<------------"
        rm -f $TEMPFILE
        exit 1
    fi

    echo ""
    echo "========================================================"
    echo "trace parsed without problems -- everything ok!"
    rm -f $TEMPFILE
}

OPT_GEN_OK_FILE=0
while getopts ":ho" OPT; do
    case $OPT in
        h)
            usage
            exit 0
            ;;
        o)
            OPT_GEN_OK_FILE=1
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
        ;;
    esac
done

if [ $OPT_GEN_OK_FILE -eq 1 ]; then
    gen_ok_file
    exit 0
else
    run_test
    exit 0
fi
