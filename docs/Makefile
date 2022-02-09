# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?=
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

# for osmo-gsm-manuals
OSMO_GSM_MANUALS_DIR=$(shell pkg-config osmo-gsm-manuals --variable=osmogsmmanualsdir 2>/dev/null)
OSMO_REPOSITORY = "pysim"
UPLOAD_FILES = $(BUILDDIR)/latex/osmopysim-usermanual.pdf
CLEAN_FILES = $(UPLOAD_FILES)

# Put it first so that "make" without argument is like "make help".
.PHONY: help
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

$(BUILDDIR)/latex/pysim.pdf: latexpdf
	@/bin/true

publish-html: html
	rsync -avz -e "ssh -o 'UserKnownHostsFile=$(OSMO_GSM_MANUALS_DIR)/build/known_hosts' -p 48" $(BUILDDIR)/html/ docs@ftp.osmocom.org:web-files/latest/pysim/

# put this before the catch-all below
include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc


# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%:
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
