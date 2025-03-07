#!/bin/sh
python3 -m pylint -j0 --errors-only --disable E1102 --disable E0401 --enable W0301 pySim
