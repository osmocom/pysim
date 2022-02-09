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
pip install 'pyyaml>=5.1'
pip install cmd2==1.5
pip install jsonpath-ng
pip install construct
pip install bidict
pip install gsm0338

# Execute automatically discovered unit tests first
python -m unittest discover -v -s tests/

# Run pylint to find potential errors
# Ignore E1102: not-callable
#   pySim/filesystem.py: E1102: method is not callable (not-callable)
# Ignore E0401: import-error
#   pySim/utils.py:276: E0401: Unable to import 'Crypto.Cipher' (import-error)
#   pySim/utils.py:277: E0401: Unable to import 'Crypto.Util.strxor' (import-error)
pip install pylint
python -m pylint --errors-only \
	--disable E1102 \
	--disable E0401 \
	--enable W0301 \
	pySim *.py

# attempt to build documentation
pip install sphinx
pip install sphinxcontrib-napoleon
pip3 install -e 'git+https://github.com/osmocom/sphinx-argparse@master#egg=sphinx-argparse'
(cd docs && make html latexpdf)

if [ "$WITH_MANUALS" = "1" ] && [ "$PUBLISH" = "1" ]; then
	make -C "docs" publish publish-html
fi

# run the test with physical cards
cd pysim-testdata
../tests/pysim-test.sh
