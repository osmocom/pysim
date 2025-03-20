#!/bin/bash
# This is an example script to illustrate how to remove a JAVA card applet instance from an application PE inside an
# existing eUICC profile package.

PYSIMPATH=../
INPATH=../smdpp-data/upp/TS48V1-A-UNIQUE-hello.der
OUTPATH=../smdpp-data/upp/TS48V1-A-UNIQUE-hello-no-inst.der

# Remove application PE entirely
PYTHONPATH=$PYSIMPATH python3 $PYSIMPATH/contrib/saip-tool.py $INPATH remove-app-inst \
		      --output-file $OUTPATH --aid 'd07002ca44' --inst-aid 'd07002ca44900101'

# Display the contents of the resulting application PE:
PYTHONPATH=$PYSIMPATH python3 $PYSIMPATH/contrib/saip-tool.py $OUTPATH info --apps
