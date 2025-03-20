#!/bin/bash
# This is an example script to illustrate how to remove a JAVA card applet from an existing eUICC profile package.

PYSIMPATH=../
INPATH=../smdpp-data/upp/TS48V1-A-UNIQUE-hello.der
OUTPATH=../smdpp-data/upp/TS48V1-A-UNIQUE-no-hello.der

# Remove application PE entirely
PYTHONPATH=$PYSIMPATH python3 $PYSIMPATH/contrib/saip-tool.py $INPATH remove-app \
		      --output-file $OUTPATH --aid 'D07002CA44'

# Display the contents of the resulting application PE:
PYTHONPATH=$PYSIMPATH python3 $PYSIMPATH/contrib/saip-tool.py $OUTPATH info --apps
