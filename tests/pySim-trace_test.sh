#/bin/bash

PYSIM_TRACE=../pySim-trace.py
GSMTAP_TRACE=pySim-trace_test_gsmtap.pcapng

echo "pySim-trace_test - a test program to test pySim-trace.py"
echo "========================================================"

$PYSIM_TRACE gsmtap-pyshark-pcap -f $GSMTAP_TRACE
if [ $? -ne 0 ]; then
	echo ""
	echo "========================================================"
	echo "Testrun with $GSMTAP_TRACE failed."
	exit 1
fi

echo ""
echo "========================================================"
echo "trace parsed without problems -- everything ok!"

