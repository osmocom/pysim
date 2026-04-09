#!/bin/bash
. ./params.cfg

set -x

PYTHONPATH=$PYSIM_DIR ../rcp_client.py $VERBOSE \
		      --uri $RCPC_SERVER_URI \
		      --ca-cert $CA_CERT \
		      -p $PCSC_READER \
		      rcp_module_reset --help

PYTHONPATH=$PYSIM_DIR ../rcp_client.py $VERBOSE \
		      --uri $RCPC_SERVER_URI \
		      --ca-cert $CA_CERT \
		      -p $PCSC_READER \
		      rcp_module_read_binary --help

PYTHONPATH=$PYSIM_DIR ../rcp_client.py $VERBOSE \
		      --uri $RCPC_SERVER_URI \
		      --ca-cert $CA_CERT \
		      -p $PCSC_READER \
		      rcp_module_read_record --help
