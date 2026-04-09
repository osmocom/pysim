#!/bin/bash
. ./params.cfg

set -x
PYTHONPATH=$PYSIM_DIR:$PYSIM_DIR/contrib/rcp ./rcp_module.py $VERBOSE \
					     --uri $RCPM_SERVER_URI \
					     --rcps-ca-cert $CA_CERT \
					     --rcpm-cmd-server-addr $RCPM_CMD_SERVER_ADDR \
					     --rcpm-cmd-server-port $RCPM_CMD_SERVER_PORT \
					     --rcpm-cmd-server-cert $RCPM_CMD_SERVER_CERT \
					     --column-key kic:$CSV_COLUMN_KEY \
					     --column-key kid:$CSV_COLUMN_KEY \
					     --column-key kik:$CSV_COLUMN_KEY

