sim-rest-server
===============

Sometimes there are use cases where a [remote] application will need
access to a USIM for authentication purposes.  This is, for example, in
case an IMS test client needs to perform USIM based authentication
against an IMS core.

The pysim repository contains two programs: `sim-rest-server.py` and
`sim-rest-client.py` that implement a simple approach to achieve the
above:

`sim-rest-server.py` speaks to a [usually local] USIM via the PC/SC
API and provides a high-level REST API towards [local or remote]
applications that wish to perform UMTS AKA using the USIM.

`sim-rest-client.py` implements a small example client program to
illustrate how the REST API provided by `sim-rest-server.py` can be
used.

REST API Calls
--------------

POST /sim-auth-api/v1/slot/SLOT_NR
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

where SLOT_NR is the integer-encoded slot number (corresponds to PC/SC
reader number).  When using a single sysmoOCTSIM board, this is in the range of 0..7

Example: `/sim-auth-api/v1/slot/0` for the first slot.

Request Body
############

The request body is a JSON document, comprising of
    1. the RAND and AUTN parameters as hex-encoded string
    2. the application against which to authenticate (USIM, ISIM)

Example:
::

        {
            "rand": "bb685a4b2fc4d697b9d6a129dd09a091",
            "autn": "eea7906f8210000004faf4a7df279b56"
        }

HTTP Status Codes
#################

HTTP status codes are used to represent errors within the REST server
and the SIM reader hardware.  They are not used to communicate protocol
level errors reported by the SIM Card.  An unsuccessful authentication
will hence have a `200 OK` HTTP Status code and then encode the SIM
specific error information in the Response Body.

======  =========== ================================
Status  Code        Description
------  ----------- --------------------------------
200     OK          Successful execution
400     Bad Request Request body is malformed
404     Not Found   Specified SIM Slot doesn't exist
410     Gone        No SIM card inserted in slot
======  =========== ================================

Response Body
#############

The response body is a JSON document, either

#. a successful outcome; encoding RES, CK, IK as hex-encoded string
#. a sync failure; encoding AUTS as hex-encoded string
#. errors
   #. authentication error (incorrect MAC)
   #. authentication error (security context not supported)
   #. key freshness failure
   #. unspecified card error

Example (success):
::

        {
           "successful_3g_authentication": {
                "res": "b15379540ec93985",
                "ck": "713fde72c28cbd282a4cd4565f3d6381",
                "ik": "2e641727c95781f1020d319a0594f31a",
                "kc": "771a2c995172ac42"
            }
        }

Example (re-sync case):
::

        {
            "synchronisation_failure": {
                "auts": "dc2a591fe072c92d7c46ecfe97e5"
            }
        }

Concrete example using the included sysmoISIM-SJA2
--------------------------------------------------

This was tested using SIMs ending in IMSI numbers 45890...45899

The following command were executed successfully:

Slot 0
::

        $ /usr/local/src/pysim/contrib/sim-rest-client.py -c 1 -n 0 -k 841EAD87BC9D974ECA1C167409357601 -o 3211CACDD64F51C3FD3013ECD9A582A0
        -> {'rand': 'fb195c7873b20affa278887920b9dd57', 'autn': 'd420895a6aa2000089cd016f8d8ae67c'}
        <- {'successful_3g_authentication': {'res': '131004db2ff1ce8e', 'ck': 'd42eb5aa085307903271b2422b698bad', 'ik': '485f81e6fd957fe3cad374adf12fe1ca', 'kc': '64d3f2a32f801214'}}

Slot 1
::

        $ /usr/local/src/pysim/contrib/sim-rest-client.py -c 1 -n 1 -k 5C2CE9633FF9B502B519A4EACD16D9DF -o 9834D619E71A02CD76F00CC7AA34FB32
        -> {'rand': '433dc5553db95588f1d8b93870930b66', 'autn': '126bafdcbe9e00000026a208da61075d'}
        <- {'successful_3g_authentication': {'res': '026d7ac42d379207', 'ck': '83a90ba331f47a95c27a550b174c4a1f', 'ik': '31e1d10329ffaf0ca1684a1bf0b0a14a', 'kc': 'd15ac5b0fff73ecc'}}
