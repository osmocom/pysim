#!/bin/bash

# Utility to verify the functionality of pySim-trace.py
#
# (C) 2026 by sysmocom - s.f.m.c. GmbH
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

PYSIM_SMPP2SIM=./pySim-smpp2sim.py
PYSIM_SMPP2SIM_LOG=./pySim-smpp2sim.log
PYSIM_SMPP2SIM_PORT=2775
PYSIM_SMPP2SIM_TIMEOUT=10
PYSIM_SMPPOTATOOL=./contrib/smpp-ota-tool.py
PYSIM_SMPPOTATOOL_LOG=./smpp-ota-tool.log
PYSIM_SHELL=./pySim-shell.py

function dump_logs {
    echo ""
    echo "$PYSIM_SMPPOTATOOL_LOG"
    echo "------------8<------------"
    cat $PYSIM_SMPPOTATOOL_LOG
    echo "------------8<------------"
    echo ""
    echo "$PYSIM_SMPP2SIM_LOG"
    echo "------------8<------------"
    cat $PYSIM_SMPP2SIM_LOG
    echo "------------8<------------"
}

function send_test_request {
    echo ""
    echo "Sending request to SMPP server:"
    TAR=$1
    C_APDU=$2
    R_APDU_EXPECTED=$3

    echo "Sending: $C_APDU"
    COMMANDLINE="$PYSIM_SMPPOTATOOL --verbose --port $PYSIM_SMPP2SIM_PORT --kic $KIC --kid $KID --tar $TAR --apdu $C_APDU"
    echo "Commandline: $COMMANDLINE"
    R_APDU=`$COMMANDLINE 2> $PYSIM_SMPPOTATOOL_LOG`
    if [ $? -ne 0 ]; then
	echo "Unable to send request! -- failed!"
	dump_logs
	exit 1
    fi

    echo "Got response from SMPP server:"
    echo "Sent: $C_APDU"
    echo "Received: $R_APDU"
    echo "Expected: $R_APDU_EXPECTED"
    if [ "$R_APDU" != "$R_APDU_EXPECTED" ]; then
	echo "Response does not match the expected response! -- failed!"
	dump_logs
	exit 1
    fi
    echo "Response matches the expected response -- success!"
    echo ""
}

function start_smpp_server {
    PCSC_READER=$1

    # Start the SMPP server
    echo ""
    echo "Starting SMPP server:"

    COMMANDLINE="$PYSIM_SMPP2SIM -p $PCSC_READER --smpp-bind-port $PYSIM_SMPP2SIM_PORT --apdu-trace"
    echo "Commandline: $COMMANDLINE"
    $COMMANDLINE > $PYSIM_SMPP2SIM_LOG 2>&1 &
    PYSIM_SMPP2SIM_PID=$!
    trap 'kill $PYSIM_SMPP2SIM_PID' EXIT
    echo "SMPP server started (PID=$PYSIM_SMPP2SIM_PID)"

    # Wait until the SMPP server is reachable
    RC=1
    RETRY_COUNT=0
    while [ $RC -ne 0 ]; do
	nc -z localhost $PYSIM_SMPP2SIM_PORT
	RC=$?
	((RETRY_COUNT++))
	if [ $RETRY_COUNT -gt $PYSIM_SMPP2SIM_TIMEOUT ]; then
	    echo "SMPP server not reachable (port=$PYSIM_SMPP2SIM_PORT) -- abort"
	    dump_logs
	    exit 1
	fi
	sleep 1
    done
    echo "SMPP server reachable (port=$PYSIM_SMPP2SIM_PORT)"
}

function find_card_by_iccid {
    # Find reader number of the card
    ICCID=$1

    echo ""
    echo "Searching for card:"
    echo "ICCID: \"$ICCID\""

    if [ -z "$ICCID" ]; then
	echo "invalid ICCID, zero length ICCID is not allowed! -- abort"
	exit 1
    fi

    PCSC_READER_COUNT=`pcsc_scan -rn | wc -l`
    for PCSC_READER in $(seq 0 $(($PCSC_READER_COUNT-1))); do
	echo "probing card in reader $PCSC_READER ..."
	EF_ICCID_DECODED=`$PYSIM_SHELL -p $PCSC_READER --noprompt -e 'select EF.ICCID' -e 'read_binary_decoded --oneline' 2> /dev/null | tail -1`
	echo $EF_ICCID_DECODED | grep $ICCID > /dev/null
	if [ $? -eq 0 ]; then
	    echo "Found card in reader $PCSC_READER"
	    return $PCSC_READER
	fi
    done

    echo "Card with ICCID \"$ICCID\" not found -- abort"
    exit 1
}

export PYTHONPATH=./

echo "pySim-smpp2sim_test - a test program to test pySim-smpp2sim.py"
echo "=============================================================="

# TODO: At the moment we can only have one card and one testcase. This is
# sufficient for now. We can extend this later as needed.

# Read test parameters from config from file
TEST_CONFIG_FILE=${0%.*}.cfg
echo "using config file: $TEST_CONFIG_FILE"
if ! [ -e "$TEST_CONFIG_FILE" ]; then
   echo "test configuration file does not exist! -- abort"
   exit 1
fi
. $TEST_CONFIG_FILE

# Execute testcase
find_card_by_iccid $ICCID
start_smpp_server $?
send_test_request $TAR $APDU "$EXPECTED_RESPONSE"



