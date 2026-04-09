#!/bin/bash
. ./params.cfg

set -x
PYTHONPATH=$PYSIM_DIR ../rcp_client.py $VERBOSE \
		      -h
