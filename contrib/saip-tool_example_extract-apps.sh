#!/bin/bash
# This is an example script to illustrate how to extract JAVA card applets from an existing eUICC profile package.

PYSIMPATH=../
INPATH=../smdpp-data/upp/TS48V1-A-UNIQUE-hello.der
OUTPATH=./

PYTHONPATH=$PYSIMPATH python3 $PYSIMPATH/contrib/saip-tool.py $INPATH extract-apps --output-dir ./ --format ijc
