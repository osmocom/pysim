Remote Card Procedure Framework
===============================

The Remote Card Procedure Framework `(RCPF)` is a modular system to provide custom,
remote controlled, procedures to card `(UICC or eUICC)` holders. The card holder
uses a minimal client program `(RCP Client)` together with a PC/SC reader. The
client program will then connect to a remote server `(RCP Server)`. The remote
server maintains a list and connections to custom modules `(RCP Modules)`, where
each module implements a set of procedures (commands). Based on its internal list,
the remote server will offer a set of suitable commands to the client. The card
holder may then chose a command to request the execution of a specific remote
card procedure. The server will make the connection to the matching module and act
as a proxy between the module and the client program.

.. graphviz::

   digraph foo {

      subgraph cluster_server {
         label = "server (card issuer)"
         RCPS [label = "RCP Server"];
         RCPM [label = "RCP Module"];
	 CKP [label = "CardKeyProvider"];
      }

      subgraph cluster_field {
         label = "field (card holder)"
         ICC [label = "UICC/eUICC"];
         RCPC [label = "RCP Client"];
      }

      RCPC -> ICC [label="PC/SC, APDU"];
      RCPC -> RCPS [label="WS, JSON"];
      RCPS -> CKP [label="pgSQL or CSV"];
      RCPS -> RCPM [label="WS, JSON", headlabel="n", taillabel="1", dir=both];

   }

in case the procedure requires a secure channel, the key material is retrieved
using a `CardKeyProvider` [1]. Since the retrieval of the key material
as well as the secure channel establishment happens internally, the related
key material is never disclosed to the client side.

This solves a major problem many card deployments suffer from: Due to security
reasons it is not always be possible to disclose key material to the card
holder. This becomes a problem in case card contents have to be modified after
the card had been deployed. This often means that the card issuer has to
physically replace the already deployed cards. With `RCPF`, the card issuer can
replace this process by deploying a suitable RCP Module on his server to offer
a fix-up procedure that the card holder can call remotely.

[1] :ref:`Retrieving card-individual keys via CardKeyProvider`

In the following we will describe the system components in further detail. We
will also give an introduction on how users can implement custom `RCP Modules`

RCP Server
~~~~~~~~~~

The `RCP Server` is the core component in the overall system. It acts as a proxy
between the `RCP Modules` (see below) and the `RCP Client` (see below). The
`RCP Server` is permanently aware of which `RCP Modules` are available and knows
their properties. With this knowledge, the `RCP Server` is able to check which
module provides suitable procedures for specific card type.

Another responsibility of the `RCP Server` is to retrieve the key material using
the `CardKeyProvider`. As far as the `CardKeyProvider` is concerned, the RCP
Server takes the exact same commandline options as pySim-shell.py. However, in
case column encryption is used. The decryption key shall be passed to the
`RCP Module` instead to the `RCP Server`. This moves the decryption to the point
where the key material is actually needed.

To ensure the privacy of the traffic exchanged between `RCP Client`,
`RCP Server` and the `RCP Modules`, all links use SSL/TLS encrypted channels.
This is in particular relevant for the `RCP Client` which usually connects to
the `RCP Server` via the public internet.

Since the `RCP Server` is exposed to the public internet, it also requires some
level of protection against malicious requests. To minimize the risk arising
from malformed requests, each incoming and outgoing message is validated against
a JSON schema (also on the internal interfaces). Incoming requests from the
RCP Client side are also rate-limited to guard against excessive requests (DoS)

To monitor the `RCP Client` requests, the `RCP Server` support logging to an
`OpenObserve` monitoring entity. For each request exactly one report es
generated and sent to `OpenObserve`. For successful request, this report will
only contain metadata. In case of crashes or when the return code of the
`RCP Module` procedure is not 0, a full debug log is included as well.

.. argparse::
   :module: contrib.rcp.rcp_server
   :func: option_parser
   :prog: contrib/rcp/rcp_server.py


RCP Client
~~~~~~~~~~

The `RCP Client` is used in the field by the card holder to request command
lists and to request the execution of procedures from the `RCP Server`.

The execution of a procedure is usually done in two steps. In the first step,
the card holder will request a list with available commands using the `--help`
option. The command list is then requested from the `RCP Server` displayed as
a regular commandline help-screen. The list will only contain commands, which
are actually suitable for the specific card type/model that card holder owns.

In the second step, the card holder will choose a command to request the
execution of the related procedure. In case the user already knows exactly
which command to execute, the first step may also be skipped. The request of
command lists for the purpose of displaying commandline help-screens is
entirely optional.

To avoid having to upgrade the RCP Client too often, the implementation is kept
as simple as possible. Technically, the RCP Client is not much more than a
proxy between a PC/SC-Reader and the RCP Server. All higher level tasks, like
requesting the ICCID (UICC or eSIM) or the EID (eUICC) are implemented on the
server side.

.. argparse::
   :module: contrib.rcp.rcp_client
   :func: option_parser
   :prog: contrib/rcp/rcp_client.py


RCP Module
~~~~~~~~~~

The processing chain terminates in one of multiple `RCP Modules`. The `RCP Module`
is the custom implementation that implements one or more procedures. The
framework is designed in such a way that `RCP Modules` have minimal boilerplate
code. The implementation is kept simple. Users, which are familiar with
`pySim-shell` and its API will find the implementation of custom `RCP Modules`
as simple as implementing a new `pySim-shell` command.

From inside a procedure, the API user has access to the same objects (rs, card,
lchan) that are also usually available in `pySim-shell` environment.

To reset the card, retrieve the ATR and to exchange APDUs, the `pySim.transport`
API together with a custom `LinkBase (RcpsSimLink)` object is used. This means
that all modules which depend on the `pySim.transport` API can be used right
away without modification.

A procedure always runs in a dedicated thread, which means no special
precautions are necessary. A procedure may wait or sleep without disturbing
other requests.

Even though there are similarities to `pySim-shell` one has to keep in mind that
`RCP Modules` are intended to run non-interactively, which means they naturally
do not provide any support for `cmd2` API calls. This means that before code
from `pySim-shell` commands can be re-used, any `cmd2` entanglement must be
removed or separated otherwise.

.. argparse::
   :module: contrib.rcp.usage_example.rcp_module
   :func: option_parser
   :prog: contrib/rcp/usage_example/rcp_module.py


Usage Example
~~~~~~~~~~~~~

All system components and related modules can be found in `contrib/rcp`. The
sub directory `usage_example` contains an example `RCP Module` and scripts to
make it easier to get started. The following steps explain in detail how to get
the `usage_example` running.

Parameters
----------

The `usage_example` contains a file `params.cfg`. This file contains variables,
which hold the parameters for the shell-scripts included in the example. The
parameters set up the system in such a way that everything runs locally.
Normally no changes are required, but it is strongly advised to review the
parameters to verify there are no clashes with other services.

Preparing Card Keys
-------------------

The example assumes a PC/SC reader and a `sysmoISIM-SJA5` or similar. To run
the `usage_example`, no modification to the card itself are required, but the
example key material (SCP02) in `card_data.csv` must match the test card.

The following example assumes that the card has the ICCID ``8949440000001155306``
and the following SCP02 keys:

+---------+----------------------------------+
| Keyname | Keyvalue                         |
+=========+==================================+
| ENC/KIC | F09C43EE1A0391665CC9F05AF4E0BD10 |
+---------+----------------------------------+
| MAC/KID | 01981F4A20999F62AF99988007BAF6CA |
+---------+----------------------------------+
| DEK/KIK | 8F8AEE5CDCC5D361368BC45673D99195 |
+---------+----------------------------------+

This would result into a `card_data.csv` file with the following content:

::

   iccid,kic,kid,kik
   8949440000001155306,F09C43EE1A0391665CC9F05AF4E0BD10,01981F4A20999F62AF99988007BAF6CA,8F8AEE5CDCC5D361368BC45673D99195


See also: :ref:`Retrieving card-individual keys via CardKeyProvider` and :ref:`Guide: Managing GP Keys`

When `card_data.csv` is re-aligned, the columns containing key material need to
be encrypted. This is done by running `encrypt_card_data.sh`. This script will
output a file `card_data.csv.encr` which contains the encrypted key material.

Running the RCP Server
----------------------

The `RCP Server` can be started using the included `start_rcp_server.sh` script.

::

   $ ./start_rcp_server.sh
   + PYTHONPATH=../../../
   + ../../..//contrib/rcp/rcp_server.py --rcpc-server-addr 127.0.0.1 --rcpc-server-port 8000 --rcpc-server-cert ./certs/example_ssl_rcpc_rcps_cert.pem --rcpm-server-addr 127.0.0.1 --rcpm-server-port 8010 --rcpm-server-cert ./certs/example_ssl_rcpm_rcps_cert.pem --rcpm-module-ca-cert ./certs/example_ssl_rcp_ca_cert.crt --csv ./card_data.csv.encr
   INFO: loading SSL/TLS CA certificate (RCP Module Command Server Client): ./certs/example_ssl_rcp_ca_cert.crt
   INFO: Using CSV file as card key data source: ./card_data.csv.encr
   WARNING: Reporting to OpenObserve: (disabled)
   INFO: Rate-Limit: max 10 requests per sec.
   INFO: RCP Client Server at: 127.0.0.1:8000
   INFO: RCP Module server at: 127.0.0.1:8010

We can see that now to ports have been opened. `127.0.0.1:8000` is the port
where `RCP Clients` can connect. In a productive setup, this port would
normally be reachable from outside. The other port on `127.0.0.1:8010` is
accepting connections from `RCP Modules` This port should not be reachable
from the outside. It is intended to be used for the interprocess communication
between the `RCP Server` and the `RCP Modules`

In this state, the `RCP Server` waits for requests from both `RCP Clients` and
`RCP Modules`. However, there are not `RCP Modules` registered yet, so any
request from an `RCP Client` would be quilted with an error message.

Running the RCP Module
----------------------

For a functioning setup a suitable `RCP Module` is needed. The provided
`rcp_module.py` python program implements a few procedures which are suitable
for a `sysmoISIM-SJA5` card.

We can start the `RCP Module` with the provided start script
`start_rcp_module.sh`

::

   $ ./start_rcp_module.sh
   + PYTHONPATH=../../../:../../..//contrib/rcp
   + ./rcp_module.py --uri wss://127.0.0.1:8010 --rcps-ca-cert ./certs/example_ssl_rcp_ca_cert.crt --rcpm-cmd-server-addr 127.0.0.1 --rcpm-cmd-server-port 8020 --rcpm-cmd-server-cert ./certs/example_ssl_rcps_rcpm_cert.pem --column-key kic:00112233445566778899AABBCCDDEEFF --column-key kid:00112233445566778899AABBCCDDEEFF --column-key kik:00112233445566778899AABBCCDDEEFF
   INFO: RCP Module startup: rcp_module
   INFO: loading SSL/TLS CA certificate (RCPM Server Client): ./certs/example_ssl_rcp_ca_cert.crt
   INFO: RCPC command server at: 127.0.0.1:8020

The `RCP Module` is now connected to the `RCP Server`. The log output of the
`RCP Server` also confirms that there is a new `RCP Module` available.

::

   INFO: new RCP module, RCP modules available: 'rcp_module'

On the output of the `RCP Module` we can see that the `RCP Module` has
opened another port on `127.0.0.1:8020`. This is where the `RCP Module` accepts
dedicated connections from the `RCP Server` when an `RCP Client` requests a
procedure. In an installation with multiple `RCP Modules`, each `RCP Module`
must use a dedicated port number.

Note that we also pass the column key for the key material using the
`--column-key` parameter. This parameter works exactly as in `pySim-shell`.
We supply the column key to the `RCP Module` and not to the `RCP Server`
move the decryption as close as possible to where it is needed.


Running the RCP Client
----------------------

The `usage_example` provides a shello-script `run_rcp_client.sh` that which
requests commandline help and requests procedures by calling other scripts.
However to get an understanding how the `RCP Client` is supposed to be used, it
makes more sense to call the sub scripts individually. We will now go through
step by step.

The first shell-script `./run_rcp_client_help.sh` assumes that the card holder
uses the `RCP Client` for the first time. He does not know which commandline
arguments are available, so he just calls `rcp_client.py` with the option `-h`.

::

   $ ./run_rcp_client_help.sh
   + PYTHONPATH=../../../
     + ../../..//contrib/rcp/rcp_client.py -h
       usage: rcp_client.py [-h] [-d DEV] [-b BAUD] [--pcsc-shared] [-p PCSC | --pcsc-regex REGEX] [--modem-device DEV] [--modem-baud BAUD] [--osmocon PATH]
                     [--apdu-trace] [--verbose] [--uri URI] [--ca-cert CA_CERT]

   RCP Client

   options:
     -h, --help            show this help message and exit
     --apdu-trace          Trace the command/response APDUs exchanged with the card (default: False)
     --verbose             Enable verbose logging (default: False)
     --uri URI             URI of the RCP-Server (default: None)
     --ca-cert CA_CERT     SSL/TLS CA-Certificate of the RCP-Server (default: None)
     ...

   PC/SC Reader:
     Use a PC/SC card reader to talk to the SIM card. PC/SC is a standard API for how applications access smart card readers, and is available on a variety of
     operating systems, such as Microsoft Windows, MacOS X and Linux. Most vendors of smart card readers provide drivers that offer a PC/SC interface, if not even
     a generic USB CCID driver is used. You can use a tool like ``pcsc_scan -r`` to obtain a list of readers available on your system.

     --pcsc-shared         Open PC/SC reaer in SHARED access (default: EXCLUSIVE) (default: False)
     -p, --pcsc-device PCSC
                           Number of PC/SC reader to use for SIM access (default: None)
     --pcsc-regex REGEX    Regex matching PC/SC reader to use for SIM access (default: None)
     ...


From the output the card holder learns that there is an `--uri` parameter and
that the same PC/SC options like in `pySim-shell.py` are supported. There is
also a `--ca-cert` parameter where a CA certificate can be supplied in case the
`RCP Server` uses a self-signed CA (which applies to this example)

The second script `run_rcp_client_help_cmd.sh` assumes that the card holder now
knows that the minimum required parameters are the `--uri` of the `RCP Server`,
the `--ca-cert` of the `RCP Server` and `-p` to tell the `RCP Client` which PC/SC
reader to use.

::

   $ ./run_rcp_client_help_cmd.sh
   + PYTHONPATH=../../../
   + ../../..//contrib/rcp/rcp_client.py --uri wss://127.0.0.1:8000 --ca-cert ./certs/example_ssl_rcp_ca_cert.crt -p 0 -h
   INFO: loading SSL/TLS CA certificate (RCP Server CA): ./certs/example_ssl_rcp_ca_cert.crt
   INFO: Using reader PCSC[Alcor Micro AU9540 00 00]
   INFO: Detected Card with ATR: 3B9F96801F878031E073FE211B674A357530350265F8
   INFO: RCP Server URI: wss://127.0.0.1:8000
   INFO: Checking version ...
   INFO: RCP Client version: software=1.0.0, protocol=1.0.0
   INFO: RCP Server version: software=1.0.0, protocol=1.0.0
   INFO: Requesting module descriptions from RCP Server ...
   usage: rcp_client.py [-h] [-d DEV] [-b BAUD] [--pcsc-shared] [-p PCSC | --pcsc-regex REGEX] [--modem-device DEV] [--modem-baud BAUD] [--osmocon PATH]
                     [--apdu-trace] [--verbose] [--uri URI] [--ca-cert CA_CERT]
                     {rcp_module_reset,rcp_module_read_binary,rcp_module_read_record,rcp_module_unlock_aram} ...

   RCP Client

   positional arguments:
     {rcp_module_reset,rcp_module_read_binary,rcp_module_read_record,rcp_module_unlock_aram}
                           RCP command to use
       rcp_module_reset    reset the card
       rcp_module_read_binary
                           read binary data from a transparent file.
       rcp_module_read_record
                           read binary data from a transparent file.
       rcp_module_unlock_aram
                           unlock a locked ARA-M applet on a sysmoISIM-SJA5
   ...

The help screen now shows additional positional arguments. Those positional
arguments are the commands which the card holder can use to request a
procedure. In this example we have four procedures we can call:
`rcp_module_reset`, `rcp_module_read_binary`, `rcp_module_read_record`,
and `rcp_module_unlock_aram`

In the log output above the help screen, we can also see that a connection was
made and that the `RCP Client` has requested module descriptions from the
server. The `RCP Client` has sent the ATR of the card to the `RCP Server`. The
`RCP Server` has used this information to look through its internal list to
find modules which offer procedures suitable for this specific card.

The card holder now knows which commands or procedures are available, but he
still does not know if arguments are required and what those arguments are.
The third script `run_rcp_client_help_cmd_specific.sh` shows how the card
holder can request a dedicated help-screen for each of the commands.

::

   $ ./run_rcp_client_help_cmd_specific.sh
   ...
   + PYTHONPATH=../../../
   + ../../..//contrib/rcp/rcp_client.py --uri wss://127.0.0.1:8000 --ca-cert ./certs/example_ssl_rcp_ca_cert.crt -p 0 rcp_module_read_record --help
   INFO: loading SSL/TLS CA certificate (RCP Server CA): ./certs/example_ssl_rcp_ca_cert.crt
   INFO: Using reader PCSC[Alcor Micro AU9540 00 00]
   INFO: Detected Card with ATR: 3B9F96801F878031E073FE211B674A357530350265F8
   INFO: RCP Server URI: wss://127.0.0.1:8000
   INFO: Checking version ...
   INFO: RCP Client version: software=1.0.0, protocol=1.0.0
   INFO: RCP Server version: software=1.0.0, protocol=1.0.0
   INFO: Requesting module descriptions from RCP Server ...
   usage: rcp_client.py rcp_module_read_record [-h] --fid FID --record RECORD

   options:
     -h, --help       show this help message and exit
     --fid FID        File identifier to of the file to read
     --record RECORD  File record to read
   ...

We can see in the log that the `RCP Client` again sends a request to the
`RCP Server` and retrieves the `RCP Module` descriptions. Then a dedicated
help-screen for the `rcp_module_read_record` command is displayed. Now the card
holder knows which parameters are required to perform the related procedure.

Until this point there was only interaction with the `RCP Client` and the
`RCP Server`. The `RCP Module` has not seen any requests yet. The provided
script `run_rcp_client_cmd.sh` illustrates how the card holder can run an
command that performs an actual procedure with the `RCP Module`.

::

   $ ./run_rcp_client_cmd.sh
   ...
   + PYTHONPATH=../../../
   + ../../..//contrib/rcp/rcp_client.py --uri wss://127.0.0.1:8000 --ca-cert ./certs/example_ssl_rcp_ca_cert.crt -p 0 rcp_module_read_record --fid 3f00 --fid 2f00 --record 1
   INFO: loading SSL/TLS CA certificate (RCP Server CA): ./certs/example_ssl_rcp_ca_cert.crt
   INFO: Using reader PCSC[Alcor Micro AU9540 00 00]
   INFO: Detected Card with ATR: 3B9F96801F878031E073FE211B674A357530350265F8
   INFO: RCP Server URI: wss://127.0.0.1:8000
   INFO: Checking version ...
   INFO: RCP Client version: software=1.0.0, protocol=1.0.0
   INFO: RCP Server version: software=1.0.0, protocol=1.0.0
   INFO: Requesting module descriptions from RCP Server ...
   INFO: Executing command with RCP Server ...
   INFO: RcpcCltConnHdlr(140335960510480) -- reading linear-fixed file: ['3f00', '2f00'] ...
   INFO: RcpcCltConnHdlr(140335960510480) -- file content is: 61294F10A0000000871002FFFFFFFF890709000050055553696D31730EA00C80011781025F608203454150
   INFO: Command execution done, rc: 0

The example reads record 1 from the file ``3F00/2F00`` and returns the file
content. We also can see by the return code that the procedure was successful.
The return code is also passed to `sys.exit()`, so that the card holder can
use it in a script.

The APDUs required to perform this action were entirely generated under the
control of the `RCP Module`. In the log of the `RCP Server` we can see which
command was executed on which `RCP Module` was used. We also see the return
code here as well.

::

   ...
   INFO: RcpcSrvConnHdlr(140093766623552) -- executing procedure for command "rcp_module_read_record" on module "rcp_module" at: wss://127.0.0.1:8020
   INFO: RcpcSrvConnHdlr(140093766623552) -- command execution done, rc: 0
   ...

In the log of the `RCP Module` we can follow up on how the procedure was
carried out.

::

   ...
   INFO: RcpmCmdSrvConnHdlr(140156091028880) -- executing command: rcp_module_read_record ['--fid', '3f00', '--fid', '2f00', '--record', '1']
   INFO: Waiting for card...
   INFO: Card is of type: UICC
   INFO: Detected UICC Add-on "SIM"
   INFO: Detected UICC Add-on "GSM-R"
   INFO: Detected UICC Add-on "RUIM"
   WARNING: EF.DIR seems to be empty!
   INFO:  ADF.ISD: a000000003000000
   INFO:  ARA-M: a00000015141434c00
   INFO:  ISIM: a0000000871004
   INFO:  USIM: a0000000871002
   INFO: Detected CardModel: SysmocomSJA5
   INFO: RcpmCmdSrvConnHdlr(140156091028880) -- reading linear-fixed file: ['3f00', '2f00'] ...
   INFO: RcpmCmdSrvConnHdlr(140156091028880) -- file content is: 61294F10A0000000871002FFFFFFFF890709000050055553696D31730EA00C80011781025F608203454150
   INFO: RcpmCmdSrvConnHdlr(140156091028880) -- command execution done, rc: 0
   ...

In first line we see the command and its parameters. The lines that follow will
look familiar to `pySim-shell` users. The last three log lines carry the print
statements which we also see in the log messages on the `RCP Client`. The last
line informs about the conclusion of the procedure and also shows the return
code.


Implementing an RCP Module
~~~~~~~~~~~~~~~~~~~~~~~~~~

To make use of the Remote Card Procedure Framework, it is eventually necessary
to implement a custom `RCP Module`. In the following section, we will go
through the implementation of the `RCP Module` that is provided with the
`usage_example`.

NOTE: much of the following is explained in greater detail in the comments
found in `rcp_module_utils.py`.

Overview
~~~~~~~~

`RCP Modules` are normal python programs that can started directly from the
command prompt. However, due to the location of the file it is necessary that
`PYTHONPATH` points to the location of the `pySim` modules as well as to the
modules found in `contrib/rcp` (see `start_rcp_module.sh` for reference).

As mentioned earlier `RCP Modules` may use the `pySim` API like any other
`pySim` program, given that there is no dependency to `cmd2`. So it is no
surprise that we find some `pySim` modules in the import section of the
provided example.

The utilities required to implement an `RCP Module` are imported from
`rcp_module_utils.py`. From this module we import two functions
`rcpm_setup_argparse` and `rcpm_run_module` and the two classes `RCP Module`
and `RcpModuleHdlr`.

Function: rcpm_setup_argparse
------------------------------

The first function `rcpm_setup_argparse` returns an argument parser that is already
equipped with the basic commandline arguments that an `RCP Module` needs. In
case the specific `RCP Module` implementation requires additional arguments,
those can be added using normal `argparse` API calls.

Function: rcpm_run_module
-------------------------

The second function `rcpm_run_module` is used to run the `RCP Module`. This
function gets the parsed commandline options (`opts`) and the `RcpModule` class
(`module`) as parameters. In addition to that, `rcpm_run_module` also accepts
custom `*args` and `**kwargs` arguments, which are passed to the constructor of
the `RcpModule` class.

When `rcpm_run_module` is called. It registers the `RCP Module` and starts the
RCP Client command server. It also takes care of the proper instantiation of the
`RcpModule` class, which were passed with the `module` parameter.

Class: RcpModule
----------------

The Class `RcpModule` is the base class that is used to create a concrete
`RCP Module` implementaion. Through this class, the API user defines the
properties of the `RCP Module` as well as the command methods, which implement
the related `Remote Card Procedures`.

Class: RcpModuleHdlr
--------------------

The class `RcpModuleHdlr` is used by the framework to instantiate a handler
object (`hdlr`), which is passed to each of the aforementioned command methods.
The handler object is used as a vehicle to provide access the resources we need
to send APDUs, print messages on the `RCP Client`, etc.

Module Properties
~~~~~~~~~~~~~~~~~

Before we can define any module properties, we first need to create a derived
class from the `RcpModule` class we have imported from `rcp_module_utils.py`.
In that class, we then define the basic properties of the `RCP Module`.

name
----

Each `RCP Module` needs a distinct name. The name must not collide with the
names of other `RCP Modules`. The name uniquely identifies the `RCP Module` and
is used as a prefix for the command names used with the user interface of the
`RCP Client`. Therefore a short name is desirable.

cmd_descr
---------

The `cmd_descr` property defines the command properties. Since an `RCP Module`
may offer multiple commands (procedures), this property is an array, where
each item holds the definition for one specific command.

The command definitions are formatted as a python dict. Like the `RCP Module`
itself, each command has a `name`. As mentioned before. This name is concatenated
with the name of the `RCP Module`.

Each command definition also gets a `help` string. The help string will show up
in the commandline help of the `RCP Client`. It should be short and concise.

Command definitions also need to define commandline arguments. For this an
`args` array is added to the command definition as well. In case no arguments
are provided. The array is empty. Otherwise it will contain one or more dict
members, where each specifies a `name` and a `spec`. The `name` sets the
argument name (e.g. --fid), and the `spec` specifies the properties of the
argument. The concept is borrowed from `argparse` and works very similar. API
users can specify `required`, `help`, `default` and a type. However, to avoid
name-space collisions, the type field is called `pytype` and the type identifier
must be passed as a string (e.g. 'int').

In case a procedure requires key material from the `CardKeyProvider`, the API
user may add a `get_keys` field to the command definition. In case eUICC keys
are needed. The API user will add a dict member with key `euicc` and populate
the value with an array that holds the column names of the columns where the
keys are found. The same also works for UICC keys by using 'uicc' as dict key.
When `get_keys` is correctly populated and the correct column keys are supplied
to the `RCP Module` at runtime. The `RCP Framework` will automatically retrieve
the key material, decrypt it and make it available to the related command
method.

suitable_for
------------

`suitable_for` is the third and last property, the API user must define. This
property holds an array where each member is a dict that defines a distinct
property of the card for which the module is suitable for. The `RCP Server`
uses this information to see which modules are suitable for a specific request.
As of now, the only property we can use to make the distinction, is the ATR of
the card.

custom resources
----------------

In case an RCP Module requires custom resources, those may be initialized using
a custom constructor in the derived class. This constructor receives the
`*args` and `**kwargs` arguments passed to `rcpm_run_module`. However, this is
an optional step. In case no constructor is defined, the default constructor
is used.

In addition to that, the API user may also define additional properties and
methods, provided they do not collide with existing methods of the base class
`RcpModule`.

Command Methods
~~~~~~~~~~~~~~~

Command methods are essentially normal python methods. However, since those
methods are called by the `RCP Framework`, they must follow a distinct scheme,
which we will go through in the following.

Each command defined in `cmd_descr` requires a corresponding command method. A
command method is always prefixed with `cmd_`. Then the exact name of the
command follows as defined in `cmd_descr`. For example if we have defined a
command with the name `read_record`, we must also define a method with the name
`cmd_read_record`.

The parameter list of a command method always contains only `self` and `hdlr`.
The `hdlr` parameter is the handler object (`RcpModuleHdlr`) through which we
access the resources provided by the `RCP Framework`.

Inside a command method, the API user is free to perform any task he wants.
Command Methods always run in a dedicated thread and may sleep or wait at any
time without disturbing running procedures from other requestors.

A command method should always return an integer as return code. In case the
procedure ends successfully, the return code shall be `0`. The return code is
passed through to the `RCP Client`, which returns it on exit to the operating
system


Handler Resources
~~~~~~~~~~~~~~~~~

As mentioned earlier, a commend method receives a handler object via
the `hdlr` parameter. This object is of type `RcpModuleHdlr` and vaguely
comparable to the `app` (`PysimApp`) object found in `pySim-shell.py`.

The handler object provides the command method with the resources it needs to
perform the card procedure.

rs, card, lchan
---------------

The Runtime State (`rs`), the Card (`card`)  and the Lchan (`lchan`) Object
have the same objectives asn in `pySim-shell.py`. Those objects work and are
used the same way as they would in `pySim-shell.py`. It is assumed that the
API user is already familiar with those objects.

cmd_args
--------

The command arguments (`cmd_args`) contains the command line arguments as they
were passed by the card holder on the `RCP Client` commandline in the form of
a `Namespace` object.

Even though the command arguments are syntax-checked against the `args`
description given in `cmd_descr`, caution is required to avoid security
problems arising from malicious input.

keys_uicc and keys_euicc
------------------------

In case key material was requested via the `get_keys` in `cmd_descr`,
`keys_uicc` and `keys_euicc` will contain those keys in the form of a dict. The
dict key is the is the `CardKeyProvider` column name and the related dict value
is the key material in its decrypted form.

When accessing `keys_uicc` and `keys_euicc`, extra care should be taken. It may
make sense to delete/overwrite those dictionaries as soon as the keys were used
for the intended purpose. However, due to python's internal memory management
key material may remain longer in the system memory as expected.

print
-----

The `hdlr` object also provides a `print` method. This method accepts a string
as the only parameter and can be used to display custom messages in the log
output of the `RCP Client`. The method can be used to inform the card holder
about the progress of a procedure or to print error messages in case a
procedure fails.
