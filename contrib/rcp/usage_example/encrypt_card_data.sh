#!/bin/bash
. ./params.cfg

PYTHONPATH=$PYSIM_DIR $PYSIM_DIR/contrib/csv-encrypt-columns.py \
		      --csv-column-key kic:$CSV_COLUMN_KEY \
		      --csv-column-key kid:$CSV_COLUMN_KEY \
		      --csv-column-key kik:$CSV_COLUMN_KEY \
		      card_data.csv
