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

import secrets
import re
from pySim.utils import all_subclasses_of
from osmocom.utils import b2h

class ParamSourceExn(Exception):
    pass

class ParamSourceExhaustedExn(ParamSourceExn):
    pass

class ParamSourceUndefinedExn(ParamSourceExn):
    pass

class ParamSource:
    'abstract parameter source. For usage, see personalization.BatchPersonalization.'
    is_abstract = True

    # This name should be short but descriptive, useful for a user interface, like 'random decimal digits'.
    name = 'none'

    @classmethod
    def get_all_implementations(cls, blacklist=None):
        "return all subclasses of ParamSource that have is_abstract = False."
        # return a set() so that multiple inheritance does not return dups
        return set(c
                   for c in all_subclasses_of(cls)
                   if (not c.is_abstract) and ((not blacklist) or (c not in blacklist))
                  )

    @classmethod
    def from_str(cls, s:str):
        '''Subclasses implement this:
           if a parameter source defines some string input magic, override this function.
           For example, a RandomDigitSource derives the number of digits from the string length,
           so the user can enter '0000' to get a four digit random number.'''
        return cls(s)

    def get_next(self, csv_row:dict=None):
        '''Subclasses implement this: return the next value from the parameter source.
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

class InputExpandingParamSource(ParamSource):

    @classmethod
    def expand_str(cls, s:str):
        # user convenience syntax '0*32' becomes '00000000000000000000000000000000'
        if '*' not in s:
            return s
        tokens = re.split(r"([^ \t]+)[ \t]*\*[ \t]*([0-9]+)", s)
        if len(tokens) < 3:
            return s
        parts = []
        for unchanged, snippet, repeat_str in zip(tokens[0::3], tokens[1::3], tokens[2::3]):
            parts.append(unchanged)
            repeat = int(repeat_str)
            parts.append(snippet * repeat)
        return ''.join(parts)

    @classmethod
    def from_str(cls, s:str):
        return cls(cls.expand_str(s))

class RandomSourceMixin:
    random_impl = secrets.SystemRandom()

class RandomDigitSource(InputExpandingParamSource, RandomSourceMixin):
    'return a different sequence of random decimal digits each'
    is_abstract = False
    name = 'random decimal digits'

    def __init__(self, num_digits, first_value, last_value):
        """
        See also from_str().

        All arguments are integer values, and are converted to int if necessary, so a string of an integer is fine.
        num_digits: number of random digits (possibly with leading zeros) to generate.
        first_value, last_value: the decimal range in which to provide random digits.
        """
        num_digits = int(num_digits)
        first_value = int(first_value)
        last_value = int(last_value)
        assert num_digits > 0
        assert first_value <= last_value
        self.num_digits = num_digits
        self.val_first_last = (first_value, last_value)

    def get_next(self, csv_row:dict=None):
        val = self.random_impl.randint(*self.val_first_last)
        return self.val_to_digit(val)

    def val_to_digit(self, val:int):
        return '%0*d' % (self.num_digits, val)  # pylint: disable=consider-using-f-string

    @classmethod
    def from_str(cls, s:str):
        s = cls.expand_str(s)

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

class RandomHexDigitSource(InputExpandingParamSource, RandomSourceMixin):
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
        val = self.random_impl.randbytes(self.num_digits // 2)
        return b2h(val)

    @classmethod
    def from_str(cls, s:str):
        s = cls.expand_str(s)
        return cls(num_digits=len(s.strip()))

class IncDigitSource(RandomDigitSource):
    'incrementing sequence of digits'
    is_abstract = False
    name = 'incrementing decimal digits'

    def __init__(self, *args, **kwargs):
        "The arguments defining the number of digits and value range are identical to RandomDigitSource.__init__()."
        super().__init__(*args, **kwargs)
        self.next_val = None
        self.reset()

    def reset(self):
        "Restart from the first value of the defined range passed to __init__()."
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

    def __init__(self, csv_column):
        """
        csv_column: column name indicating the column to use for this parameter.
                    This name is used in get_next(): the caller passes the current CSV row to get_next(), from which
                    CsvSource picks the column with the name matching csv_column.
        """
        self.csv_column = csv_column

    def get_next(self, csv_row:dict=None):
        val = None
        if csv_row:
            val = csv_row.get(self.csv_column)
        if not val:
            raise ParamSourceUndefinedExn(f'no value for CSV column {self.csv_column!r}')
        return val
