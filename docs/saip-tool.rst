saip-tool
=========

eSIM profiles are stored as a sequence of profile element (PE) objects in an ASN.1 DER encoded binary file. To inspect,
verify or make changes to those files, the `saip-tool.py` utility can be used.

NOTE: The file format, eSIM SAIP (SimAlliance Interoperable Profile) is specified in `TCA eUICC Profile Package:
Interoperable Format Technical Specification`


Profile Package Examples
~~~~~~~~~~~~~~~~~~~~~~~~

pySim ships with a set of TS48 profile package examples. Those examples can be found in `pysim/smdpp-data/upp`. The
files can be used as input for `saip-tool.py`. (see also GSMA TS.48 - Generic eUICC Test Profile for Device Testing)

See also: https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public

JAVA card applets
~~~~~~~~~~~~~~~~~

The `saip-tool.py` can also be used to manage JAVA-card applets (Application PE) inside a profile package. The user has
the option to add, remove and inspect applications and their instances. In the following we will discuss a few JAVA-card
related use-cases of `saip-tool.py`

NOTE: see also `contrib` folder for script examples (`saip-tool_example_*.sh`)

Inserting applications
----------------------

An application is usually inserted in two steps. In the first step, the application PE is created and populated with
the executable code from a provided `.cap` or `.ijc` file. The user also has to pick a suitable load block AID.

The application instance, which exists inside the application PE, is created in a second step. Here the user must
reference the load block AID and pick, among other application related parameters, a suitable class and instance AID.

Example: Adding a JAVA-card applet to an existing profile package
::

  # Step #1: Create the application PE and load the ijc contents from the .cap file:
  $ ./contrib/saip-tool.py upp.der add-app --output-file upp_with_app.der --applet-file app.cap --aid '1122334455'
  Read 28 PEs from file 'upp.der'
  Applying applet file: 'app.cap'...
  application PE inserted into PE Sequence after securityDomain PE AID: a000000151000000
  Writing 29 PEs to file 'upp_with_app.der'...

  # Step #2: Create the application instance inside the application PE created in step #1:
  $ ./contrib/saip-tool.py upp_with_app.der add-app-inst --output-file upp_with_app_and_instance.der \
          --aid '1122334455' \
          --class-aid '112233445501' \
          --inst-aid '112233445501' \
          --app-privileges '00' \
          --app-spec-pars '00' \
          --uicc-toolkit-app-spec-pars '01001505000000000000000000000000'
  Read 29 PEs from file 'upp_with_app.der'
  Found Load Package AID: 1122334455, adding new instance AID: 112233445501 to Application PE...
  Writing 29 PEs to file 'upp_with_app_and_instance.der'...

NOTE: The parameters of the sub-commands `add-app` and `add-app-inst` are application specific. It is up to the application
developer to pick parameters that suit the application correctly. For an exact command reference see section
`saip-tool syntax`. For parameter details see `TCA eUICC Profile Package: Interoperable Format Technical Specification`,
section 8.7 and ETSI TS 102 226, section 8.2.1.3.2


Inspecting applications
-----------------------

To inspect the application PE contents of an existing profile package, sub-command `info` with parameter '--apps' can
be used. This command lists out all application and their parameters in detail. This allows an application developer
to check if the applet insertaion was carried out as expected.

Example: Listing applications and their parameters
::

  $ ./contrib/saip-tool.py upp_with_app_and_instance.der info --apps
  Read 29 PEs from file 'upp_with_app_and_instance.der'
  Application #0:
          loadBlock:
                  loadPackageAID: '1122334455' (5 bytes)
                  loadBlockObject: '01000fdecaffed010204000105d07002ca440200...681080056810a00633b44104b431066800a10231' (569 bytes)
          instanceList[0]:
                  applicationLoadPackageAID: '1122334455' (5 bytes)
                  classAID: '112233445501' (8 bytes)
                  instanceAID: '112233445501' (8 bytes)
                  applicationPrivileges: '00' (1 bytes)
                  lifeCycleState: '07' (1 bytes)
                  applicationSpecificParametersC9: '00' (1 bytes)
                  applicationParameters:
                          uiccToolkitApplicationSpecificParametersField: '01001505000000000000000000000000' (16 bytes)

In case further analysis with external tools or transfer of applications from one profile package to another is
necessary, the executable code in the `loadBlockObject` field can be extracted to an `.ijc` or an `.cap` file.

Example: Extracting applications from a profile package
::

  $ ./contrib/saip-tool.py upp_with_app_and_instance.der extract-apps --output-dir ./apps --format ijc
  Read 29 PEs from file 'upp_with_app_and_instance.der'
  Writing Load Package AID: 1122334455 to file ./apps/8949449999999990023f-1122334455.ijc


Removing applications
---------------------

An application PE can be removed using sub-command `remove-app`. The user passes the load package AID as parameter. Then
`saip-tool.py` will search for the related application PE and delete it from the PE sequence.

Example: Remove an application from a profile package
::

  $ ./contrib/saip-tool.py upp_with_app_and_instance.der remove-app --output-file upp_without_app.der --aid '1122334455'
  Read 29 PEs from file 'upp_with_app_and_instance.der'
  Found Load Package AID: 1122334455, removing related PE (id=23) from Sequence...
  Removing PE application (id=23) from Sequence...
  Writing 28 PEs to file 'upp_without_app.der'...

In some cases it is useful to remove only an instance from an existing application PE. This may be the case when the
an application developer wants to modify parameters of an application by removing and re-adding the instance. The
operation basically rolls the state back to step 1 explained in section :ref:`Inserting applications`

Example: Remove an application instance from an application PE
::

  $ ./contrib/saip-tool.py upp_with_app_and_instance.der remove-app-inst --output-file upp_without_app.der --aid '1122334455' --inst-aid '112233445501'
  Read 29 PEs from file 'upp_with_app_and_instance.der'
  Found Load Package AID: 1122334455, removing instance AID: 112233445501 from Application PE...
  Removing instance from Application PE...
  Writing 29 PEs to file 'upp_with_app.der'...


saip-tool syntax
~~~~~~~~~~~~~~~~

.. argparse::
   :module: contrib.saip-tool
   :func: parser
   :prog: contrib/saip-tool.py
