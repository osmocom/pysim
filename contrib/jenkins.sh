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
pip install cmd2

# Execute automatically discovered unit tests first
python -m unittest discover -v -s tests/

cd pysim-testdata
../tests/pysim-test.sh

