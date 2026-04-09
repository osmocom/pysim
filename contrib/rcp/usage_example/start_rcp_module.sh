#!/bin/bash
. ./params.cfg

set -x
PYTHONPATH=$PYSIM_DIR:$RCP_DIR ./rcp_module.py $VERBOSE \
			       --uri $RCPM_SERVER_URI \
			       --rcps-ca-cert $CA_CERT \
			       --rcpm-cmd-server-addr $RCPM_CMD_SERVER_ADDR \
			       --rcpm-cmd-server-port $RCPM_CMD_SERVER_PORT \
			       --rcpm-cmd-server-cert $RCPM_CMD_SERVER_CERT

