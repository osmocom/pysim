WebSocket Remote Card (WSRC)
============================

WSRC (*Web Socket Remote Card*) is a mechanism by which card readers can be made remotely available
via a computer network.  The transport mechanism is (as the name implies) a WebSocket.  This transport
method was chosen to be as firewall/NAT friendly as possible.

WSRC Network Architecture
-------------------------

In a WSRC network, there are three major elements:

* The **WSRC Card Client** which exposes a locally attached smart card (usually via a Smart Card Reader)
  to a remote *WSRC Server*
* The **WSRC Server** manges incoming connections from both *WSRC Card Clients* as well as *WSRC User Clients*
* The **WSRC User Client** is a user application, like for example pySim-shell, which is accessing a remote
  card by connecting to the *WSRC Server* which relays the information to the selected *WSRC Card Client*

WSRC Protocol
-------------

The WSRC protocl consits of JSON objects being sent over a websocket.  The websocket communication itself
is based on HTTP and should usually operate via TLS for security reasons.

The detailed protocol is currently still WIP. The plan is to document it here.


pySim implementations
---------------------

TBD
