from setuptools import setup
from pybind11.setup_helpers import Pybind11Extension, build_ext

ext_modules = [
    Pybind11Extension(
        "bsp_crypto",
        ["bsp_python_bindings.cpp"],
        libraries=["ssl", "crypto"],
        extra_compile_args=["-ggdb", "-O0"],
        cxx_std=17,
    ),
]

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
        "pyosmocom >= 0.0.9",
        "pyyaml >= 5.1",
        "termcolor",
        "colorlog",
        "pycryptodomex",
        "packaging",
        "smpp.pdu @ git+https://github.com/hologram-io/smpp.pdu",
        "asn1tools",
        "smpp.twisted3 @ git+https://github.com/jookies/smpp.twisted",
        "pybind11",
        "klein",
        "service-identity",
        "pyopenssl",
        "requests",
    ],
    scripts=[
        'pySim-prog.py',
        'pySim-read.py',
        'pySim-shell.py',
        'pySim-trace.py',
        'pySim-smpp2sim.py',
    ],
    package_data={
        'pySim.esim':
            [
                'asn1/rsp/*.asn',
                'asn1/saip/*.asn',
            ],
    },
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    zip_safe=False,
    python_requires=">=3.6",
)
