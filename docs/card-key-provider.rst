
Retrieving card-individual keys via CardKeyProvider
==================================================

When working with a batch of cards, or more than one card in general, it
is a lot of effort to manually retrieve the card-specific PIN (like
ADM1) or key material (like SCP02/SCP03 keys).

To increase productivity in that regard, pySim has a concept called the
`CardKeyProvider`.  This is a generic mechanism by which different parts
of the pySim[-shell] code can programmatically request card-specific key material
from some data source (*provider*).

For example, when you want to verify the ADM1 PIN using the `verify_adm`
command without providing an ADM1 value yourself, pySim-shell will
request the ADM1 value for the ICCID of the card via the
CardKeyProvider.

There can in theory be multiple different CardKeyProviders.  You can for
example develop your own CardKeyProvider that queries some kind of
database for the key material, or that uses a key derivation function to
derive card-specific key material from a global master key.

The only actual CardKeyProvider implementation included in pySim is the
`CardKeyProviderCsv` which retrieves the key material from a
[potentially encrypted] CSV file.


The CardKeyProviderCsv
----------------------

The `CardKeyProviderCsv` allows you to retrieve card-individual key
material from a CSV (comma separated value) file that is accessible to pySim.

The CSV file must have the expected column names, for example `ICCID`
and `ADM1` in case you would like to use that CSV to obtain the
card-specific ADM1 PIN when using the `verify_adm` command.

You can specify the CSV file to use via the `--csv` command-line option
of pySim-shell.  If you do not specify a CSV file, pySim will attempt to
open a CSV file from the default location at
`~/.osmocom/pysim/card_data.csv`, and use that, if it exists.


Field naming
------------

* For look-up of UICC/SIM/USIM/ISIM or eSIM profile specific key
  material, pySim uses the `ICCID` field as lookup key.

* For look-up of eUICC specific key material (like SCP03 keys for the
  ISD-R, ECASD), pySim uses the `EID` field as lookup key.

As soon as the CardKeyProviderCsv finds a line (row) in your CSV where
the ICCID or EID match, it looks for the column containing the requested
data.


ADM PIN
~~~~~~~

The `verify_adm` command will attempt to look up the `ADM1` column
indexed by the ICCID of the SIM/UICC.


SCP02 / SCP03
~~~~~~~~~~~~~

SCP02 and SCP03 each use key triplets consisting if ENC, MAC and DEK
keys.  For more details, see the applicable GlobalPlatform
specifications.

If you do not want to manually enter the key material for each specific
card as arguments to the `establish_scp02` or `establish_scp03`
commands, you can make use of the `--key-provider-suffix` option.  pySim
uses this suffix to compose the column names for the CardKeyProvider as
follows.

* `SCP02_ENC_` + suffix for the SCP02 ciphering key
* `SCP02_MAC_` + suffix for the SCP02 MAC key
* `SCP02_DEK_` + suffix for the SCP02 DEK key
* `SCP03_ENC_` + suffix for the SCP03 ciphering key
* `SCP03_MAC_` + suffix for the SCP03 MAC key
* `SCP03_DEK_` + suffix for the SCP03 DEK key

So for example, if you are using a command like `establish_scp03
--key-provider-suffix ISDR`, then the column names for the key material
look-up are `SCP03_ENC_ISDR`, `SCP03_MAC_ISDR` and `SCP03_DEK_ISDR`,
respectively.

The identifier used for look-up is determined by the definition of the
Security Domain.  For example, the eUICC ISD-R and ECASD will use the EID
of the eUICC.  On the other hand, the ISD-P of an eSIM or the ISD of an
UICC will use the ICCID.
