#!/bin/sh
# jenkins build helper script for pysim.  This is how we build on jenkins.osmocom.org
#
# environment variables:
# * WITH_MANUALS: build manual PDFs if set to "1"
# * PUBLISH: upload manuals after building if set to "1" (ignored without WITH_MANUALS = "1")
#

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
pip install jsonpath-ng
pip install construct

# Execute automatically discovered unit tests first
python -m unittest discover -v -s tests/

# attempt to build documentation
pip install sphinx
pip install sphinxcontrib-napoleon
pip3 install -e 'git+https://github.com/osmocom/sphinx-argparse@master#egg=sphinx-argparse'
(cd docs && make html latexpdf)

# run the test with physical cards
cd pysim-testdata
../tests/pysim-test.sh

if [ "$WITH_MANUALS" = "1" ] && [ "$PUBLISH" = "1" ]; then
	make -C "$base/docs" publish
fi
