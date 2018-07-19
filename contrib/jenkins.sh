#!/bin/sh

set -e

if [ ! -d "$HOME/pysim-testdata/" ] ; then
	echo "###############################################"
	echo "Please create testdata in $HOME/pysim-testdata!"
	echo "###############################################"
	exit 1
fi

virtualenv -p python2 venv --system-site-packages
. venv/bin/activate
pip install pytlv

cp -a "$HOME/pysim-testdata/" pysim-testdata/
cd pysim-testdata
../tests/pysim-test.sh

