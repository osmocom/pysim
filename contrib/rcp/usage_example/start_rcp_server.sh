#!/bin/bash
. ./params.cfg

set -x
PYTHONPATH=$PYSIM_DIR ../rcp_server.py $VERBOSE \
		      --rcpc-server-addr $RCPC_SERVER_ADDR \
		      --rcpc-server-port $RCPC_SERVER_PORT \
		      --rcpc-server-cert $RCPC_SERVER_CERT \
		      --rcpm-server-addr $RCPM_SERVER_ADDR \
		      --rcpm-server-port $RCPM_SERVER_PORT \
		      --rcpm-server-cert $RCPM_SERVER_CERT \
		      --rcpm-module-ca-cert $CA_CERT

