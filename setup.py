from setuptools import setup

setup(
    name='pySim',
    version='1.0',
    packages=[
        'pySim',
        'pySim.apdu',
        'pySim.apdu_source',
        'pySim.esim',
        'pySim.esim.saip',
        'pySim.global_platform',
        'pySim.legacy',
        'pySim.transport',
    ],
    url='https://osmocom.org/projects/pysim/wiki',
    license='GPLv2',
    author_email='simtrace@lists.osmocom.org',
    description='Tools related to SIM/USIM/ISIM cards',
    install_requires=[
        "pyscard",
        "pyserial",
        "pytlv",
        "cmd2 >= 1.5.0",
        "jsonpath-ng",
        "construct >= 2.10.70",
        "bidict",
        "pyosmocom >= 0.0.8",
        "pyyaml >= 5.1",
        "termcolor",
        "colorlog",
        "pycryptodomex",
        "packaging",
        "smpp.pdu @ git+https://github.com/hologram-io/smpp.pdu",
        "asn1tools",
    ],
    scripts=[
        'pySim-prog.py',
        'pySim-read.py',
        'pySim-shell.py',
        'pySim-trace.py',
    ],
    package_data={
        'pySim.esim':
            [
                'asn1/rsp/*.asn',
                'asn1/saip/*.asn',
            ],
    },
)
