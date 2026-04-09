#!/bin/bash
. ./params.cfg

set -x

PYTHONPATH=$PYSIM_DIR ../rcp_client.py $VERBOSE \
		      --uri $RCPC_SERVER_URI\
		      --ca-cert $CA_CERT \
		      -p $PCSC_READER \
		      rcp_module_reset

PYTHONPATH=$PYSIM_DIR ../rcp_client.py $VERBOSE \
		      --uri $RCPC_SERVER_URI \
		      --ca-cert $CA_CERT \
		      -p $PCSC_READER \
		      rcp_module_read_binary --fid 3f00 --fid 2fe2

PYTHONPATH=$PYSIM_DIR ../rcp_client.py $VERBOSE \
		      --uri $RCPC_SERVER_URI \
		      --ca-cert $CA_CERT \
		      -p $PCSC_READER \
		      rcp_module_read_record --fid 3f00 --fid 2f00 --record 1
