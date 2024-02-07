from setuptools import setup

setup(
    name='pySim',
    version='1.0',
    packages=['pySim', 'pySim.legacy', 'pySim.transport', 'pySim.apdu', 'pySim.apdu_source',
              'pySim.esim'],
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
        "construct >= 2.9.51",
        "bidict",
        "gsm0338",
        "pyyaml >= 5.1",
        "termcolor",
        "colorlog",
        "pycryptodomex",
        "packaging",
        "smpp.pdu @ git+https://github.com/hologram-io/smpp.pdu",
    ],
    scripts=[
        'pySim-prog.py',
        'pySim-read.py',
        'pySim-shell.py',
        'pySim-trace.py',
    ]
)
