Integration Testsuite for pySim-shell
=====================================

The testsuite presented here is build on python's unittest framework, which is
extended via a UnittestUtils class, which can be found in utils.py. This class
contains methods to execute pySim-shell, compare files, load file contents,
generate pySim-shell scripts from templates, etc. It also cares about managing
the cards and their related data (ICCIDs, ADM pins, keys, etc.)

Each testcase has its own subdirectory and can be executed separately. The sub
directory of each testcase usually contains a single python script (test.py),
one or more pySim-shell scripts or templates and also one or more .ok files.
The .ok files are auto-generated using a known-to-work version of pySim-shell
and can be re-generated at any-time if required.

This testsuite is designed to be executed automatically on a build sever, but
it can also be executed on a developer workstation.

Requirements
------------

The testsuite is executes pySim-shell on physical cards. This means all card
models for which the tests were written must be physially present in PCSC
readers.

(see `config.yaml` for which card models are required)

Configuration
-------------

The card models, which are present in the testsuite are set up via
`config.yaml`. All cards are listed by their model ´name´, ´atr´ and ´iccid´
(or eid for eUICCs). The testsuite user should not add or remove models. The
only change that is required is to adjust the iccid and eid fields so that they
match the values of the cards that are used for the test.

Card data, such as ADM, PIN1, PIN2, etc. are configured in ´card_data.csv´. This
file is used with the --csv parameter of pySim-shell. The format is described
in the osmopysim-usermanual. Each card configured in ´config.yaml´ has a
coresponding entry in ´card_data.csv´. The entries are connected via either
the ´iccid´ or the eid as ´key´. Like with ´config.yaml´, the testsuite user
must adjust the values, so that they match the actual cards.

The file card_data.csv is also read by the testsuite, so that all contained
fields are also available to the testcases.

Data collection
---------------

On startup, the testsuite will check the presence of each card configured in
´config.yaml´. While doing that, the PCSC reader number is determined. Then it
will use either the ´iccid´ or the ´eid´ to fetch the card data from
card_data.csv.

All information, that is gathered during the startup procedure is collected
in a dict that is available to the testcase. The testsuite will list all cards
and their related information on startup.

Running
-------

Testcases are implemented as python unittests and the execution of the testcases
is no different from the execution of other python unittests.

To run all tests, run the following command line from the top directory of the
pySim repository:

```
python3 -m unittest discover ./tests/pySim-shell_test/
```

It is also possible to run a specific test only:
```
python3 -m unittest discover -k export_fs ./tests/pySim-shell_test
```

Regenerating .ok files
----------------------

The testsuite ships with a set of .ok files. Those files are used to compare
the output of certain pySim-shell commands. In case the .ok files contain card
specific data (IMSI values, ICCID values, etc.) the comparison happens in such
a way that this data is ignored. This means a card with a different IMSI,
ICCID, Ki etc. should work with the included .ok files. However, there may be
changes in the code or in the file system structure that may cause a certain
testcase to fial anyway. In this case a regeneration of the .ok files may be
necessary.

To instruct the testsuite to regenerate all .ok files, change the ´regenerate´
field in config.yaml to True and run the testsuite once. The testsuite will then
overwrite the .ok files with the output it got from pySim-shell. When the
testcase execution is done, the regenerate field must be set back to False and
the new content of the .ok files must be reviewed.

Keeping temporary files
-----------------------

During development of new testcases or for debugging, it can be helpful not to
delete all temporary files after a test run. To keep the temporary files, the
´keepfiles´ field in config.yaml can be set to True.

Printing file contents
----------------------

To locate testcase failures more easily, the user has the option to display the
content of files that are compared or loaded from a testcase. To display the
file contents, set the field ´print_content´ in config.yaml to true
