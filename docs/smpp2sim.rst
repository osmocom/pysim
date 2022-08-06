pySim-smpp2sim
==============

This is a program to emulate the entire communication path SMSC-CN-RAN-ME
that is usually between an OTA backend and the SIM card.  This allows
to play with SIM OTA technology without using a mobile network or even
a mobile phone.

An external application can act as SMPP ESME and must encode (and
encrypt/sign) the OTA SMS and submit them via SMPP to this program, just
like it would submit it normally to a SMSC (SMS Service Centre).  The
program then re-formats the SMPP-SUBMIT into a SMS DELIVER TPDU and
passes it via an ENVELOPE APDU to the SIM card that is locally inserted
into a smart card reader.

The path from SIM to external OTA application works the opposite way.

The default SMPP system_id is `test`.  Likewise, the default SMPP
password is `test`

Running pySim-smpp2sim
----------------------

The command accepts the same command line arguments for smart card interface device selection as pySim-shell,
as well as a few SMPP specific arguments:

.. argparse::
   :module: pySim-smpp2sim
   :func: option_parser
   :prog: pySim-smpp2sim.py


Example execution with sample output
------------------------------------

So for a simple system with a single PC/SC device, you would typically use something like
`./pySim-smpp2sim.py -p0` to start the program.  You will see output like this at start-up
::

  Using reader PCSC[HID Global OMNIKEY 3x21 Smart Card Reader [OMNIKEY 3x21 Smart Card Reader] 00 00]
  INFO     root: Binding Virtual SMSC to TCP Port 2775 at ::

The application has hence bound to local TCP port 2775 and expects your SMS-sending applications to send their
SMS there.  Once you do, you will see log output like below:
::

  WARNING  smpp.twisted.protocol: SMPP connection established from ::ffff:127.0.0.1 to port 2775
  INFO     smpp.twisted.server: Added CommandId.bind_transceiver bind for 'test'. Active binds: CommandId.bind_transceiver: 1, CommandId.bind_transmitter: 0, CommandId.bind_receiver: 0. Max binds: 2
  INFO     smpp.twisted.protocol: Bind request succeeded for test. 1 active binds

And once your external program is sending SMS to the simulated SMSC, it will log something like
::

  INFO     root: SMS_DELIVER(MTI=0, MMS=False, LP=False, RP=False, UDHI=True, SRI=False, OA=AddressField(TON=international, NPI=unknown, 12), PID=7f, DCS=f6, SCTS=bytearray(b'"pR\x00\x00\x00\x00'), UDL=45, UD=b"\x02p\x00\x00(\x15\x16\x19\x12\x12\xb0\x00\x01'\xfa(\xa5\xba\xc6\x9d<^\x9d\xf2\xc7\x15]\xfd\xdeD\x9c\x82k#b\x15Ve0x{0\xe8\xbe]")
  SMSPPDownload(DeviceIdentities({'source_dev_id': 'network', 'dest_dev_id': 'uicc'}),Address({'ton_npi': 0, 'call_number': '0123456'}),SMS_TPDU({'tpdu': '400290217ff6227052000000002d02700000281516191212b0000127fa28a5bac69d3c5e9df2c7155dfdde449c826b236215566530787b30e8be5d'}))
  INFO     root: ENVELOPE: d147820283818604001032548b3b400290217ff6227052000000002d02700000281516191212b0000127fa28a5bac69d3c5e9df2c7155dfdde449c826b236215566530787b30e8be5d
  INFO     root: SW 9000: 027100002412b000019a551bb7c28183652de0ace6170d0e563c5e949a3ba56747fe4c1dbbef16642c
