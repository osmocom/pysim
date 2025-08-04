#!/usr/bin/env python3

# (C) 2025 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
#
# Author: Neels Hofmeyr
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import math
from importlib import resources
import unittest
from pySim.esim.saip import param_source

import xo
update_expected_output = False

class D:
    mandatory = set()
    optional = set()

    def __init__(self, **kwargs):
        if (set(kwargs.keys()) - set(self.optional)) != set(self.mandatory):
            raise RuntimeError(f'{self.__class__.__name__}.__init__():'
                               f' {set(kwargs.keys())=!r} - {self.optional=!r} != {self.mandatory=!r}')
        for k, v in kwargs.items():
            setattr(self, k, v)
        for k in self.optional:
            if not hasattr(self, k):
                setattr(self, k, None)

decimals = '0123456789'
hexadecimals = '0123456789abcdefABCDEF'

class FakeRandom:
    vals = b'\xab\xcfm\xf0\x98J_\xcf\x96\x87fp5l\xe7f\xd1\xd6\x97\xc1\xf9]\x8c\x86+\xdb\t^ke\xc1r'
    i = 0

    @classmethod
    def next(cls):
        cls.i = (cls.i + 1) % len(cls.vals)
        return cls.vals[cls.i]

    @staticmethod
    def randint(a, b):
        d = b - a
        n_bytes = math.ceil(math.log(d, 2))
        r = int.from_bytes( bytes(FakeRandom.next() for i in range(n_bytes)) )
        return a + (r % (b - a))

    @staticmethod
    def randbytes(n):
        return bytes(FakeRandom.next() for i in range(n))


class ParamSourceTest(unittest.TestCase):

    def test_param_source(self):

        class ParamSourceTest(D):
            mandatory = (
                    'param_source',
                    'n',
                    'expect',
                    )
            optional = (
                    'expect_arg',
                    'csv_rows',
                    )

        def expect_const(t, vals):
            return tuple(t.expect_arg) == tuple(vals)

        def expect_random(t, vals):
            chars = t.expect_arg.get('digits')
            repetitions = (t.n - len(set(vals)))
            if repetitions:
                raise RuntimeError(f'expect_random: there are {repetitions} repetitions in the returned values: {vals}')
            for val_i in range(len(vals)):
                v = vals[val_i]
                val_minlen = t.expect_arg.get('val_minlen')
                val_maxlen = t.expect_arg.get('val_maxlen')
                if len(v) < val_minlen or len(v) > val_maxlen:
                    raise RuntimeError(f'expect_random: invalid length {len(v)} for value [{val_i}]: {v!r}, expecting'
                                       f' {val_minlen}..{val_maxlen}')

                if chars is not None and not all(c in chars for c in v):
                    raise RuntimeError(f'expect_random: invalid char in value [{val_i}]: {v!r}')
            return True

        param_source_tests = [
            ParamSourceTest(param_source=param_source.ConstantSource.from_str('123'),
                            n=3,
                            expect=expect_const,
                            expect_arg=('123', '123', '123')
                           ),
            ParamSourceTest(param_source=param_source.RandomDigitSource.from_str('12345'),
                            n=3,
                            expect=expect_random,
                            expect_arg={'digits': decimals,
                                        'val_minlen': 5,
                                        'val_maxlen': 5,
                                        },
                           ),
            ParamSourceTest(param_source=param_source.RandomDigitSource.from_str('1..999'),
                            n=10,
                            expect=expect_random,
                            expect_arg={'digits': decimals,
                                        'val_minlen': 1,
                                        'val_maxlen': 3,
                                        },
                           ),
            ParamSourceTest(param_source=param_source.RandomDigitSource.from_str('001..999'),
                            n=10,
                            expect=expect_random,
                            expect_arg={'digits': decimals,
                                        'val_minlen': 3,
                                        'val_maxlen': 3,
                                        },
                           ),
            ParamSourceTest(param_source=param_source.RandomHexDigitSource.from_str('12345678'),
                            n=3,
                            expect=expect_random,
                            expect_arg={'digits': hexadecimals,
                                        'val_minlen': 8,
                                        'val_maxlen': 8,
                                       },
                           ),
            ParamSourceTest(param_source=param_source.RandomHexDigitSource.from_str('0*8'),
                            n=3,
                            expect=expect_random,
                            expect_arg={'digits': hexadecimals,
                                        'val_minlen': 8,
                                        'val_maxlen': 8,
                                       },
                           ),
            ParamSourceTest(param_source=param_source.RandomHexDigitSource.from_str('00*4'),
                            n=3,
                            expect=expect_random,
                            expect_arg={'digits': hexadecimals,
                                        'val_minlen': 8,
                                        'val_maxlen': 8,
                                       },
                           ),
            ParamSourceTest(param_source=param_source.IncDigitSource.from_str('10001'),
                            n=3,
                            expect=expect_const,
                            expect_arg=('10001', '10002', '10003')
                           ),
            ParamSourceTest(param_source=param_source.CsvSource('column_name'),
                            n=3,
                            expect=expect_const,
                            expect_arg=('first val', 'second val', 'third val'),
                            csv_rows=(
                                      {'column_name': 'first val',},
                                      {'column_name': 'second val',},
                                      {'column_name': 'third val',},
                                     )
                           ),
            ]

        outputs = []

        for t in param_source_tests:
            try:
                if hasattr(t.param_source, 'random_impl'):
                    t.param_source.random_impl = FakeRandom

                vals = []
                for i in range(t.n):
                    csv_row = None
                    if t.csv_rows is not None:
                        csv_row = t.csv_rows[i]
                    vals.append( t.param_source.get_next(csv_row=csv_row) )
                if not t.expect(t, vals):
                    raise RuntimeError(f'invalid values returned: returned {vals}')
                output = f'ok: {t.param_source.__class__.__name__} {vals=!r}'
                outputs.append(output)
                print(output)
            except RuntimeError as e:
                raise RuntimeError(f'{t.param_source.__class__.__name__} {t.n=} {t.expect.__name__}({t.expect_arg!r}): {e}') from e

        output = '\n'.join(outputs) + '\n'
        xo_name = 'test_param_src'
        if update_expected_output:
            with resources.path(xo, xo_name) as xo_path:
                with open(xo_path, 'w', encoding='utf-8') as f:
                    f.write(output)
        else:
            xo_str = resources.read_text(xo, xo_name)
            if xo_str != output:
                at = 0
                while at < len(output):
                    if output[at] == xo_str[at]:
                        at += 1
                        continue
                    break

                raise RuntimeError(f'output differs from expected output at position {at}: {xo_str[at:at+128]!r}')

if __name__ == "__main__":
    if '-u' in sys.argv:
        update_expected_output = True
        sys.argv.remove('-u')
    unittest.main()
