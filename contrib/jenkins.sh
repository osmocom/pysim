#!/bin/sh

set -e

if [ ! -d "./pysim-testdata/" ] ; then
	echo "###############################################"
	echo "Please call from pySim-prog top directory"
	echo "###############################################"
	exit 1
fi

virtualenv -p python3 venv --system-site-packages
. venv/bin/activate
pip install pytlv
pip install pyyaml

cd pysim-testdata
../tests/pysim-test.sh

