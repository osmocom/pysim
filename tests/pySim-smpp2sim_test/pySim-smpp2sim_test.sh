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

PYSIM_SHELL=./pySim-shell.py
PYSIM_SHELL_LOG=./pySim-shell.log
PYSIM_SMPP2SIM=./pySim-smpp2sim.py
PYSIM_SMPP2SIM_LOG=./pySim-smpp2sim.log
PYSIM_SMPP2SIM_PORT=2775
PYSIM_SMPP2SIM_TIMEOUT=10
PYSIM_SMPPOTATOOL=./contrib/smpp-ota-tool.py
PYSIM_SMPPOTATOOL_LOG=./smpp-ota-tool.log

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
    C_APDU=$1
    R_APDU_EXPECTED=$2

    echo "Sending: $C_APDU"
    COMMANDLINE="$PYSIM_SMPPOTATOOL --verbose --port $PYSIM_SMPP2SIM_PORT --kic $KIC --kid $KID --kic_idx $KEY_INDEX --kid_idx $KEY_INDEX --algo-crypt $ALGO_CRYPT --algo-auth $ALGO_AUTH --tar $TAR --apdu $C_APDU"
    echo "Commandline: $COMMANDLINE"
    R_APDU=`$COMMANDLINE 2> $PYSIM_SMPPOTATOOL_LOG`
    if [ $? -ne 0 ]; then
	echo "Unable to send request! -- failed!"
	dump_logs
	exit 1
    fi
    echo ""
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
}

function start_smpp_server {
    PCSC_READER=$1
    echo ""
    echo "Starting SMPP server:"

    # Start the SMPP server
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

function stop_smpp_server {
    echo ""
    echo "Stopping SMPP server:"
    kill $PYSIM_SMPP2SIM_PID
    echo "SMPP server stopped (PID=$PYSIM_SMPP2SIM_PID)"
    trap EXIT
}

function find_card_by_iccid_or_eid {
    ICCID=$1
    EID=$2
    echo ""
    echo "Searching for card:"
    echo "ICCID: \"$ICCID\""
    if [ -n "$EID" ]; then
	echo "EID: \"$EID\""
    fi

    # Determine number of available PCSC readers
    PCSC_READER_COUNT=`pcsc_scan -rn | wc -l`

    # In case an EID is set, search for a card with that EID first
    if [ -n "$EID" ]; then
	for PCSC_READER in $(seq 0 $(($PCSC_READER_COUNT-1))); do
	    echo "probing card (eID) in reader $PCSC_READER ..."
	    RESULT_JSON=`$PYSIM_SHELL -p $PCSC_READER --noprompt -e "select ADF.ISD-R" -e "get_eid" 2> /dev/null | tail -3`
	    echo $RESULT_JSON | grep $EID > /dev/null
	    if [ $? -eq 0 ]; then
		echo "Found card (eID) in reader $PCSC_READER"
		return $PCSC_READER
	    fi
	done
    fi

    # Search for card with the given ICCID
    if [ -z "$ICCID" ]; then
	echo "invalid ICCID, zero length ICCID is not allowed! -- abort"
	exit 1
    fi
    for PCSC_READER in $(seq 0 $(($PCSC_READER_COUNT-1))); do
	echo "probing card (ICCID) in reader $PCSC_READER ..."
	RESULT_JSON=`$PYSIM_SHELL -p $PCSC_READER --noprompt -e "select EF.ICCID" -e "read_binary_decoded" 2> /dev/null | tail -3`
	echo $RESULT_JSON | grep $ICCID > /dev/null
	if [ $? -eq 0 ]; then
	    echo "Found card (by ICCID) in reader $PCSC_READER"
	    return $PCSC_READER
	fi
    done

    echo "Card not found -- abort"
    exit 1
}

function enable_profile {
    PCSC_READER=$1
    ICCID=$2
    EID=$3
    if [ -z "$EID" ]; then
	# This is no eUICC, nothing to enable
	return 0
    fi
    echo ""
    echo "Enabeling profile:"
    echo "ICCID: \"$ICCID\""
    RESULT_JSON=`$PYSIM_SHELL -p $PCSC_READER --noprompt -e "select ADF.ISD-R" -e "enable_profile --iccid $ICCID" 2> /dev/null | tail -3`
    echo $RESULT_JSON | grep "ok\|profileNotInDisabledState" > /dev/null
    if [ $? -ne 0 ]; then
	echo "unable to enable profile with \"$ICCID\""
	exit 1
    fi
    echo "profile enabled"
}

export PYTHONPATH=./

echo "pySim-smpp2sim_test - a test program to test pySim-smpp2sim.py"
echo "=============================================================="

TESTCASE_DIR=`dirname $0`
for TEST_CONFIG_FILE in $TESTCASE_DIR/testcase_*.cfg ; do
    echo ""
    echo "running testcase: $TEST_CONFIG_FILE"
    . $TEST_CONFIG_FILE
    find_card_by_iccid_or_eid $ICCID $EID
    PCSC_READER=$?
    enable_profile $PCSC_READER $ICCID $EID
    start_smpp_server $PCSC_READER
    send_test_request $APDU "$EXPECTED_RESPONSE"
    stop_smpp_server
    echo ""
    echo "testcase ok"
    echo "--------------------------------------------------------------"
done

echo "done."
