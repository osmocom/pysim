# Implementation of SimAlliance/TCA Interoperable Profile handling: parameter sources for batch personalization.
#
# (C) 2025 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
#
# Author: nhofmeyr@sysmocom.de
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import random
from pySim.utils import all_subclasses_of

class ParamSourceExn(Exception):
    pass

class ParamSourceExhaustedExn(ParamSourceExn):
    pass

class ParamSourceUndefinedExn(ParamSourceExn):
    pass

class ParamSource:
    'abstract parameter source'
    is_abstract = True

    # This name should be short but descriptive, useful for a user interface, like 'random decimal digits'.
    name = 'none'

    @classmethod
    def get_all_implementations(cls, blacklist=None):
        # return a set() so that multiple inheritance does not return dups
        return set(c
                   for c in all_subclasses_of(cls)
                   if (not c.is_abstract) and ((not blacklist) or (c not in blacklist))
                  )

    @classmethod
    def from_str(cls, s:str):
        '''if a parameter source defines some string input magic, override this function.
           For example, a RandomDigitSource derives the number of digits from the string length,
           so the user can enter '0000' to get a four digit random number.'''
        return cls(s)

    def get_next(self, csv_row:dict=None):
        '''return the next value from the parameter source.
           When there are no more values from the source, raise a ParamSourceExhaustedExn.'''
        raise ParamSourceExhaustedExn()


class ConstantSource(ParamSource):
    'one value for all'
    is_abstract = False
    name = 'constant'

    def __init__(self, val:str):
        self.val = val

    def get_next(self, csv_row:dict=None):
        return self.val

class RandomDigitSource(ParamSource):
    'return a different sequence of random decimal digits each'
    is_abstract = False
    name = 'random decimal digits'

    def __init__(self, num_digits, first_value, last_value):
        'see from_str()'
        num_digits = int(num_digits)
        first_value = int(first_value)
        last_value = int(last_value)
        assert num_digits > 0
        assert first_value <= last_value
        self.num_digits = num_digits
        self.val_first_last = (first_value, last_value)

    def get_next(self, csv_row:dict=None):
        val = random.randint(*self.val_first_last) # TODO secure random source?
        return self.val_to_digit(val)

    def val_to_digit(self, val:int):
        return '%0*d' % (self.num_digits, val)  # pylint: disable=consider-using-f-string

    @classmethod
    def from_str(cls, s:str):
        if '..' in s:
            first_str, last_str = s.split('..')
            first_str = first_str.strip()
            last_str = last_str.strip()
        else:
            first_str = s.strip()
            last_str = None

        first_value = int(first_str)
        last_value = int(last_str) if last_str is not None else '9' * len(first_str)
        return cls(num_digits=len(first_str), first_value=first_value, last_value=last_value)

class RandomHexDigitSource(ParamSource):
    'return a different sequence of random hexadecimal digits each'
    is_abstract = False
    name = 'random hexadecimal digits'

    def __init__(self, num_digits):
        'see from_str()'
        num_digits = int(num_digits)
        if num_digits < 1:
            raise ValueError('zero number of digits')
        # hex digits always come in two
        if (num_digits & 1) != 0:
            raise ValueError(f'hexadecimal value should have even number of digits, not {num_digits}')
        self.num_digits = num_digits

    def get_next(self, csv_row:dict=None):
        val = random.randbytes(self.num_digits // 2) # TODO secure random source?
        return val

    @classmethod
    def from_str(cls, s:str):
        return cls(num_digits=len(s.strip()))

class IncDigitSource(RandomDigitSource):
    'incrementing sequence of digits'
    is_abstract = False
    name = 'incrementing decimal digits'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.next_val = None
        self.reset()

    def reset(self):
        self.next_val = self.val_first_last[0]

    def get_next(self, csv_row:dict=None):
        val = self.next_val
        if val is None:
            raise ParamSourceExhaustedExn()

        returnval = self.val_to_digit(val)

        val += 1
        if val > self.val_first_last[1]:
            self.next_val = None
        else:
            self.next_val = val

        return returnval

class CsvSource(ParamSource):
    'apply a column from a CSV row, as passed in to ParamSource.get_next(csv_row)'
    is_abstract = False
    name = 'from CSV'

    def __init__(self, csv_column, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.csv_column = csv_column

    def get_next(self, csv_row:dict=None):
        val = None
        if csv_row:
            val = csv_row.get(self.csv_column)
        if not val:
            raise ParamSourceUndefinedExn(f'no value for CSV column {self.csv_column!r}')
        return val
