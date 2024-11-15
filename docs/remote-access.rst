
Remote access to an UICC/eUICC
==============================

To access a card with pySim-shell, it is not strictly necessary to have physical
access to it. There are solutions that allow remote access to UICC/eUICC cards.
In this section we will give a brief overview.


osmo-remsim
-----------

osmo-remsim is a suite of software programs enabling physical/geographic
separation of a cellular phone (or modem) on the one hand side and the
UICC/eUICC card on the other side.

Using osmo-remsim, you can operate an entire fleet of modems/phones, as well as
banks of SIM cards and dynamically establish or remove the connections between
modems/phones and cards.

To access remote cards with pySim-shell via osmo-remseim (RSPRO), the
provided libifd_remsim_client would be used to provide a virtual PC/SC reader
on the local machine. pySim-shell can then access this reader like any other
PC/SC reader.

More information on osmo-remsim can be found under:
 * https://osmocom.org/projects/osmo-remsim/wiki
 * https://ftp.osmocom.org/docs/osmo-remsim/master/osmo-remsim-usermanual.pdf


Android APDU proxy
------------------

Android APDU proxy is an Android app that provides a bridge between a host
computer and the UICC/eUICC slot of an Android smartphone.

The APDU proxy connects to VPCD server that runs on the remote host (in this
case the local machine where pySim-shell is running). The VPCD server then
provides a virtual PC/SC reader, that pySim-shell can access like any other
PC/SC reader.

On the Android side the UICC/eUICC is accessed via OMAPI (Open Mobile API),
which is available in Android since API level Android 8 (API level 29).

More information Android APDU proxy can be found under:
 * https://gitea.osmocom.org/sim-card/android-apdu-proxy
