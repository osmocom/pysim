from setuptools import setup

setup(
    name='pySim',
    version='1.0',
    packages=['pySim', 'pySim.transport'],
    url='https://osmocom.org/projects/pysim/wiki',
    license='GPLv2',
    author_email='simtrace@lists.osmocom.org',
    description='Tools related to SIM/USIM/ISIM cards',
    install_requires=[
        "pyscard",
        "serial",
        "pytlv",
        "cmd2 >= 1.3.0, < 2.0.0",
        "jsonpath-ng",
        "construct >= 2.9",
        "bidict",
        "gsm0338",
        "termcolor",
        "colorlog"
    ],
    scripts=[
        'pySim-prog.py',
        'pySim-read.py',
        'pySim-shell.py'
    ]
)
