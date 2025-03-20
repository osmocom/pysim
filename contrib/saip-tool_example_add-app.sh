#!/bin/bash
# This is an example script to illustrate how to add JAVA card applets to an existing eUICC profile package.

PYSIMPATH=../
INPATH=../smdpp-data/upp/TS48V1-A-UNIQUE.der
OUTPATH=../smdpp-data/upp/TS48V1-A-UNIQUE-hello.der
APPPATH=./HelloSTK_09122024.cap

# Download example applet (see also https://gitea.osmocom.org/sim-card/hello-stk):
if ! [ -f $APPPATH ]; then
    wget https://osmocom.org/attachments/download/8931/HelloSTK_09122024.cap
fi

# Step #1: Create the application PE and load the ijc contents from the .cap file:
PYTHONPATH=$PYSIMPATH python3 $PYSIMPATH/contrib/saip-tool.py $INPATH add-app \
		      --output-file $OUTPATH --applet-file $APPPATH --aid 'D07002CA44'

# Step #2: Create the application instance inside the application PE created in step #1:
PYTHONPATH=$PYSIMPATH python3 $PYSIMPATH/contrib/saip-tool.py $OUTPATH add-app-inst --output-file $OUTPATH \
		      --aid 'D07002CA44' \
		      --class-aid 'D07002CA44900101' \
		      --inst-aid 'D07002CA44900101' \
		      --app-privileges '00' \
		      --app-spec-pars '00' \
		      --uicc-toolkit-app-spec-pars '01001505000000000000000000000000'

# Display the contents of the resulting application PE:
PYTHONPATH=$PYSIMPATH python3 $PYSIMPATH/contrib/saip-tool.py $OUTPATH info --apps

# For an explaination of --uicc-toolkit-app-spec-pars, see:
# ETSI TS 102 226, section 8.2.1.3.2.2.1
