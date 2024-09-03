#!/bin/bash

# Utility to verify the functionality of pySim-prog.py
#
# (C) 2018 by Sysmocom s.f.m.c. GmbH
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

PYSIM_PROG=../../pySim-prog.py
PYSIM_READ=../../pySim-read.py
TEMPFILE=temp.tmp
PYTHON=python3

export PYSIM_INTEGRATION_TEST=1
set -e

echo "pySim-prog_test - a test program to test pySim-prog.py"
echo "======================================================"

# Generate a list of the cards we expect to see by checking which .ok files
# are present
function gen_card_list {
    N_CARDS=0

    echo "Expecting to see the following cards:"

    for I in *.data ; do
	CARD_NAMES[$N_CARDS]=${I%.*}
	CARD_SEEN[$N_CARDS]=0
	N_CARDS=$((N_CARDS+1))
    done

    for I in $(seq 0 $((N_CARDS-1))); do
	echo ${CARD_NAMES[$I]}
    done
}

# Increment counter in card list for a specified card name (type)
function inc_card_list {
    CARD_NAME=$1
    for I in $(seq 0 $((N_CARDS-1))); do
	if [ $CARD_NAME = ${CARD_NAMES[$I]} ]; then
	    CARD_SEEN[$I]=$((${CARD_NAMES[$I]}+1))
	fi
    done
}

# Check the card list, each card must be seen exactly one times
function check_card_list {
    for I in $(seq 0 $((N_CARDS-1))); do
	if [ ${CARD_SEEN[$I]} -ne 1 ]; then
	    echo "Error: Card ${CARD_NAMES[$I]} seen ${CARD_SEEN[$I]} times!"
	    exit 1
	fi
    done

    echo "All cards seen -- everything ok!"
}

# Verify the contents of a card by reading them and then diffing against the
# previously created .ok file
function check_card {
    TERMINAL=$1
    CARD_NAME=$2
    echo "Verifying card ..."
    stat ./$CARD_NAME.ok > /dev/null
    $PYTHON $PYSIM_READ -p $TERMINAL > $TEMPFILE
    set +e
    CARD_DIFF=$(diff $TEMPFILE ./$CARD_NAME.ok)
    set -e

    if [ "$CARD_DIFF" != "" ]; then
	echo "Card contents do not match the test data:"
	echo "Expected: $CARD_NAME.ok"
	echo "------------8<------------"
	cat "$CARD_NAME.ok"
	echo "------------8<------------"
	echo "Got:"
	echo "------------8<------------"
	cat $TEMPFILE
	echo "------------8<------------"
	rm *.tmp
	exit 1
    fi

    inc_card_list $CARD_NAME

    echo "Card contents match the test data -- success!"
    rm $TEMPFILE
}

# Read out the card using pysim-read and store the result as .ok file. This
# data will be used later in order to verify the results of our write tests.
function gen_ok_file {
    TERMINAL=$1
    CARD_NAME=$2
    $PYTHON $PYSIM_READ -p $TERMINAL > "$CARD_NAME.ok"
    echo "Generated file: $CARD_NAME.ok"
    echo "------------8<------------"
    cat "$CARD_NAME.ok"
    echo "------------8<------------"
}

# Find out the type (card name) of the card that is installed in the specified
# reader
function probe_card {
    TERMINAL=$1
    RESULT=$(timeout 5 $PYSIM_PROG -p $TERMINAL -T 2> /dev/null | cut -d ":" -f 2 | tail -n 1 | xargs)
    echo $RESULT
}

# Read out all cards and store the results as .ok files
function gen_ok_files {
    echo "== OK FILE GENERATION =="
    for I in $(seq 0 $((N_TERMINALS-1))); do
	echo "Probing card in terminal #$I"
	CARD_NAME=$(probe_card $I)
	if [ -z "$CARD_NAME" ]; then
	    echo "Warning: Unresponsive card!"
	    continue
	fi
	echo "Card is of type: $CARD_NAME"

	if ! [ -r "$CARD_NAME.data" ]; then
	    echo "Warning: no .data file for this card, skipping..."
	    continue
	fi
	gen_ok_file $I $CARD_NAME
    done
}

# Execute tests. Each card is programmed and the contents are checked
# afterwards.
function run_test {
    for I in $(seq 0 $((N_TERMINALS-1))); do
	echo "== EXECUTING TEST =="
	echo "Probing card in terminal #$I"
	CARD_NAME=$(probe_card $I)
	if [ -z "$CARD_NAME" ]; then
	    echo "Warning: Unresponsive card, trying next terminal..."
	    continue
	fi
	echo "Card is of type: $CARD_NAME"

	# Make sure some default data is set
	MCC=001
	MNC=01
	ICCID=1122334455667788990
	KI=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
	OPC=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
	IMSI=001010000000001
	MSISDN=6766266
	ADM=00000000
	ADM_HEX=""
	ADM_OPT="-a"

	if ! [ -r "$CARD_NAME.data" ]; then
	    echo "Warning: no .data file for this card, skipping..."
	    continue
	fi

	source "$CARD_NAME.data"
	if [ -n "$ADM_HEX" ]; then
		ADM_OPT="-A"
		ADM=$ADM_HEX
	fi
	$PYTHON $PYSIM_PROG -p $I -t $CARD_NAME -o $OPC -k $KI -x $MCC -y $MNC -i $IMSI -s $ICCID --msisdn $MSISDN $ADM_OPT $ADM
	check_card $I $CARD_NAME
	echo ""
    done
}

function usage {
    echo "Options:"
    echo "-n: number of card terminals"
    echo "-o: generate .ok files"
}

# Make sure that the pathes to the python scripts always work, regardless from
# where the script is called.
CURDIR=$PWD
SCRIPTDIR=$(dirname $0)
cd $SCRIPTDIR
PYSIM_PROG=$(realpath $PYSIM_PROG)
PYSIM_READ=$(realpath $PYSIM_READ)
cd $CURDIR

OPT_N_TERMINALS=0
OPT_GEN_OK_FILES=0
while getopts ":hon:" OPT; do
  case $OPT in
      h)
	  usage
	  exit 0
	  ;;
      o)
	  OPT_GEN_OK_FILES=1
	  ;;
      n)
	  OPT_N_TERMINALS=$OPTARG
	  ;;
      \?)
	  echo "Invalid option: -$OPTARG" >&2
	  exit 1
      ;;
  esac
done

N_TERMINALS=$OPT_N_TERMINALS

# Generate a list of available cards, if no explicit reader number is given
# then the number of cards will be used as reader number.
gen_card_list
if [ $N_TERMINALS -eq 0 ]; then
    N_TERMINALS=`pcsc_scan -r | sed '$!d' | cut -d ':' -f 1`
    ((N_TERMINALS++))
fi
echo "Number of card terminals installed: $N_TERMINALS"
echo ""

if [ $OPT_GEN_OK_FILES -eq 1 ]; then
    gen_ok_files
    exit 0
else
    run_test
    check_card_list
    exit 0
fi
