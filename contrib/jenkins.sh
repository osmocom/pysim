#!/bin/sh -xe
# jenkins build helper script for pysim.  This is how we build on jenkins.osmocom.org
#
# environment variables:
# * WITH_MANUALS: build manual PDFs if set to "1"
# * PUBLISH: upload manuals after building if set to "1" (ignored without WITH_MANUALS = "1")
# * JOB_TYPE: one of 'test', 'distcheck', 'pylint', 'docs'
#

export PYTHONUNBUFFERED=1

if [ ! -d "./pysim-testdata/" ] ; then
	echo "###############################################"
	echo "Please call from pySim-prog top directory"
	echo "###############################################"
	exit 1
fi

case "$JOB_TYPE" in
"test")
	virtualenv -p python3 venv --system-site-packages
	. venv/bin/activate

	pip install -r requirements.txt
	pip install pyshark

	# Execute automatically discovered unit tests first
	python -m unittest discover -v -s tests/

	# Run the test with physical cards
	cd pysim-testdata
	../tests/pySim-prog_test.sh
	../tests/pySim-trace_test.sh
	;;
"distcheck")
	virtualenv -p python3 venv --system-site-packages
	. venv/bin/activate

	pip install .
	pip install pyshark

	for prog in venv/bin/pySim-*.py; do
		$prog --help > /dev/null
	done
	;;
"pylint")
	# Print pylint version
	pip3 freeze | grep pylint
	# Run pylint to find potential errors
	# Ignore E1102: not-callable
	#   pySim/filesystem.py: E1102: method is not callable (not-callable)
	# Ignore E0401: import-error
	#   pySim/utils.py:276: E0401: Unable to import 'Crypto.Cipher' (import-error)
	#   pySim/utils.py:277: E0401: Unable to import 'Crypto.Util.strxor' (import-error)
	python3 -m pylint -j0 --errors-only \
		--disable E1102 \
		--disable E0401 \
		--enable W0301 \
		pySim tests/*.py *.py \
		contrib/es2p_client.py
	;;
"docs")
	rm -rf docs/_build
	make -C "docs" html latexpdf

	if [ "$WITH_MANUALS" = "1" ] && [ "$PUBLISH" = "1" ]; then
		make -C "docs" publish publish-html
	fi
	;;
*)
	set +x
	echo "ERROR: JOB_TYPE has unexpected value '$JOB_TYPE'."
	exit 1
esac
