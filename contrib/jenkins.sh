#!/bin/sh -xe
# jenkins build helper script for pysim.  This is how we build on jenkins.osmocom.org
#
# environment variables:
# * WITH_MANUALS: build manual PDFs if set to "1"
# * PUBLISH: upload manuals after building if set to "1" (ignored without WITH_MANUALS = "1")
# * JOB_TYPE: one of 'test', 'distcheck', 'pylint', 'docs'
# * SKIP_CLEAN_WORKSPACE: don't run osmo-clean-workspace.sh (for pyosmocom CI)
#

export PYTHONUNBUFFERED=1

if [ ! -d "./tests/" ] ; then
	echo "###############################################"
	echo "Please call from pySim-prog top directory"
	echo "###############################################"
	exit 1
fi

if [ -z "$SKIP_CLEAN_WORKSPACE" ]; then
	osmo-clean-workspace.sh
fi

case "$JOB_TYPE" in
"test")
	virtualenv -p python3 venv --system-site-packages
	. venv/bin/activate

	pip install -r requirements.txt
	pip install pyshark

	# Execute automatically discovered unit tests first
	python -m unittest discover -v -s tests/unittests

	# Run pySim-prog integration tests (requires physical cards)
	cd tests/pySim-prog_test/
        ./pySim-prog_test.sh
	cd ../../

	# Run pySim-trace test
	tests/pySim-trace_test/pySim-trace_test.sh

	# Run pySim-shell integration tests (requires physical cards)
	python3 -m unittest discover -v -s ./tests/pySim-shell_test/
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

	virtualenv -p python3 venv --system-site-packages
	. venv/bin/activate

	pip install .

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
		pySim tests/unittests/*.py *.py \
		contrib/*.py
	;;
"docs")
	virtualenv -p python3 venv --system-site-packages
	. venv/bin/activate

	pip install -r requirements.txt

	# XXX: workaround for https://github.com/python-cmd2/cmd2/issues/1414
	# 2.4.3 was the last stable release not affected by this bug (OS#6776)
	pip install cmd2==2.4.3

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

osmo-clean-workspace.sh
