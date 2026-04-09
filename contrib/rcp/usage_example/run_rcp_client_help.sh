#!/bin/bash
. ./params.cfg

set -x
PYTHONPATH=$PYSIM_DIR $PYSIM_DIR/contrib/rcp/rcp_client.py $VERBOSE \
		      -h
