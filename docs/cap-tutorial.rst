
Guide: Installing JAVA-card applets
===================================

Almost all modern-day UICC cards have some form of JAVA-card / Sim-Toolkit support, which allows the installation
of customer specific JAVA-card applets. The installation of JAVA-card applets is usually done via the standardized
GlobalPlatform (GPC_SPE_034) ISD (Issuer Security Domain) application interface during the card provisioning process.
(it is also possible to load JAVA-card applets in field via OTA-SMS, but that is beyond the scope of this guide). In
this guide we will go through the individual steps that are required to load JAVA-card applet onto an UICC card.


Preparation
~~~~~~~~~~~

In this example we will install the CAP file HelloSTK_09122024.cap [1] on an sysmoISIM-SJA2 card. Since the interface
is standardized, the exact card model does not matter.

The example applet makes use of the STK (Sim-Toolkit), so we must supply STK installation parameters. Those
parameters are supplied in the form of a hexstring and should be provided by the applet manufacturer. The available
parameters and their exact encoding is specified in ETSI TS 102 226, section 8.2.1.3.2.1. The installation of
HelloSTK_09122024.cap [1], will require the following STK installation parameters: "010001001505000000000000000000000000"

During the installation, we also have to set a memory quota for the volatile and for the non volatile card memory.
Those values also should be provided by the applet manufacturer. In this example, we will allow 255 bytes of volatile
memory and 255 bytes of non volatile memory to be consumed by the applet.

To install JAVA-card applets, one must be in the possession of the key material belonging to the card. The keys are
usually provided by the card manufacturer. The following example will use the following keyset:

+---------+----------------------------------+
| Keyname | Keyvalue                         |
+=========+==================================+
| DEK/KIK | 5524F4BECFE96FB63FC29D6BAAC6058B |
+---------+----------------------------------+
| ENC/KIC | 542C37A6043679F2F9F71116418B1CD5 |
+---------+----------------------------------+
| MAC/KID | 34F11BAC8E5390B57F4E601372339E3C |
+---------+----------------------------------+

[1] https://osmocom.org/projects/cellular-infrastructure/wiki/HelloSTK


Applet Installation
~~~~~~~~~~~~~~~~~~~

To prepare the installation, a secure channel to the ISD must be established first:

::

    pySIM-shell (00:MF)> select ADF.ISD
    {
        "application_id": "a000000003000000",
	"proprietary_data": {
	    "maximum_length_of_data_field_in_command_message": 255
        }
    }
    pySIM-shell (00:MF/ADF.ISD)> establish_scp02 --key-dek 5524F4BECFE96FB63FC29D6BAAC6058B --key-enc 542C37A6043679F2F9F71116418B1CD5 --key-mac 34F11BAC8E5390B57F4E601372339E3C --security-level 1
    Successfully established a SCP02[01] secure channel

.. warning:: In case you get an "EXCEPTION of type 'ValueError' occurred with message: card cryptogram doesn't match" error message, it is very likely that there is a problem with the key material. The card may lock the ISD access after a certain amount of failed tries. Carefully check the key material any try again.


When the secure channel is established, we are ready to install the applet. The installation normally is a multi step
procedure, where the loading of an executable load file is announced first, then loaded and then installed in a final
step. The pySim-shell command ``install_cap`` automatically takes care of those three steps.

::

    pySIM-shell (SCP02[01]:00:MF/ADF.ISD)> install_cap /home/user/HelloSTK_09122024.cap --install-parameters-non-volatile-memory-quota 255 --install-parameters-volatile-memory-quota 255 --install-parameters-stk 010001001505000000000000000000000000
    loading cap file: /home/user/HelloSTK_09122024.cap ...
    parameters:
     security-domain-aid: a000000003000000
     load-file: 569 bytes
     load-file-aid: d07002ca44
     module-aid: d07002ca44900101
     application-aid: d07002ca44900101
     install-parameters: c900ef1cc80200ffc70200ffca12010001001505000000000000000000000000
    step #1: install for load...
    step #2: load...
    Loaded a total of 573 bytes in 3 blocks. Don't forget install_for_install (and make selectable) now!
    step #3: install_for_install (and make selectable)...
    done.

The applet is now installed on the card. We can now quit pySim-shell and remove the card from the reader and test the
applet in a mobile phone. There should be a new STK application with one menu entry shown, that will greet the user
when pressed.


Applet Removal
~~~~~~~~~~~~~~

To remove the applet, we must establish a secure channel to the ISD (see above). Then we can delete the applet using the
``delete_card_content`` command.

::

    pySIM-shell (SCP02[01]:00:MF/ADF.ISD)> delete_card_content D07002CA44 --delete-related-objects

The parameter "D07002CA44" is the load-file-AID of the applet. The load-file-AID is encoded in the .cap file and also
displayed during the installation process. It is also important to note that when the applet is installed, it cannot
be installed (under the same AID) again until it is removed.


