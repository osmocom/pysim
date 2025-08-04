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
import re
from osmocom.utils import b2h

class ParamSourceExn(Exception):
    pass

class ParamSourceExhaustedExn(ParamSourceExn):
    pass

class ParamSourceUndefinedExn(ParamSourceExn):
    pass

class ParamSource:
    """abstract parameter source. For usage, see personalization.BatchPersonalization."""

    # This name should be short but descriptive, useful for a user interface, like 'random decimal digits'.
    name = "none"
    numeric_base = None # or 10 or 16

    def __init__(self, input_str:str):
        """Subclasses should call super().__init__(input_str) before evaluating self.input_str. Each subclass __init__()
        may in turn manipulate self.input_str to apply expansions or decodings."""
        self.input_str = input_str

    def get_next(self, csv_row:dict=None):
        """Subclasses implement this: return the next value from the parameter source.
           When there are no more values from the source, raise a ParamSourceExhaustedExn.
           This default implementation is an empty source."""
        raise ParamSourceExhaustedExn()

    @classmethod
    def from_str(cls, input_str:str):
        """compatibility with earlier version of ParamSource. Just use the constructor."""
        return cls(input_str)

class ConstantSource(ParamSource):
    """one value for all"""
    name = "constant"

    def get_next(self, csv_row:dict=None):
        return self.input_str

class InputExpandingParamSource(ParamSource):

    def __init__(self, input_str:str):
        super().__init__(input_str)
        self.input_str = self.expand_input_str(self.input_str)

    @classmethod
    def expand_input_str(cls, input_str:str):
        # user convenience syntax '0*32' becomes '00000000000000000000000000000000'
        if "*" not in input_str:
            return input_str
        # re:                "XX            *        123" with optional spaces
        tokens = re.split(r"([^ \t]+)[ \t]*\*[ \t]*([0-9]+)", input_str)
        if len(tokens) < 3:
            return input_str
        parts = []
        for unchanged, snippet, repeat_str in zip(tokens[0::3], tokens[1::3], tokens[2::3]):
            parts.append(unchanged)
            repeat = int(repeat_str)
            parts.append(snippet * repeat)

        return "".join(parts)

class DecimalRangeSource(InputExpandingParamSource):
    """abstract: decimal numbers with a value range"""

    numeric_base = 10

    def __init__(self, input_str:str=None, num_digits:int=None, first_value:int=None, last_value:int=None):
        """Constructor to set up values from a (user entered) string: DecimalRangeSource(input_str).
        Constructor to set up values directly: DecimalRangeSource(num_digits=3, first_value=123, last_value=456)

        num_digits produces leading zeros when first_value..last_value are shorter.
        """
        assert ((input_str is not None and (num_digits, first_value, last_value) == (None, None, None))
                or (input_str is None and None not in (num_digits, first_value, last_value)))

        if input_str is not None:
            super().__init__(input_str)

            input_str = self.input_str

            if ".." in input_str:
                first_str, last_str = input_str.split('..')
                first_str = first_str.strip()
                last_str = last_str.strip()
            else:
                first_str = input_str.strip()
                last_str = None

            num_digits = len(first_str)
            first_value = int(first_str)
            last_value = int(last_str if last_str is not None else "9" * num_digits)

        assert num_digits > 0
        assert first_value <= last_value
        self.num_digits = num_digits
        self.first_value = first_value
        self.last_value = last_value

    def val_to_digit(self, val:int):
        return "%0*d" % (self.num_digits, val)  # pylint: disable=consider-using-f-string

class RandomSourceMixin:
    random_impl = random.SystemRandom()

class RandomDigitSource(DecimalRangeSource, RandomSourceMixin):
    """return a different sequence of random decimal digits each"""
    name = "random decimal digits"

    def get_next(self, csv_row:dict=None):
        val = self.random_impl.randint(*self.val_first_last)
        return self.val_to_digit(val)

class RandomHexDigitSource(InputExpandingParamSource, RandomSourceMixin):
    """return a different sequence of random hexadecimal digits each"""
    name = "random hexadecimal digits"
    numeric_base = 16

    def __init__(self, input_str:str):
        super().__init__(input_str)
        input_str = self.input_str

        num_digits = len(input_str.strip())
        if num_digits < 1:
            raise ValueError("zero number of digits")
        # hex digits always come in two
        if (num_digits & 1) != 0:
            raise ValueError(f"hexadecimal value should have even number of digits, not {num_digits}")
        self.num_digits = num_digits

    def get_next(self, csv_row:dict=None):
        val = self.random_impl.randbytes(self.num_digits // 2)
        return b2h(val)

class IncDigitSource(DecimalRangeSource):
    """incrementing sequence of digits"""
    name = "incrementing decimal digits"

    def __init__(self, input_str:str=None, num_digits:int=None, first_value:int=None, last_value:int=None):
        """input_str: the first value to return, a string of an integer number with optional leading zero digits. The
        leading zero digits are preserved."""
        super().__init__(input_str, num_digits, first_value, last_value)
        self.next_val = None
        self.reset()

    def reset(self):
        """Restart from the first value of the defined range passed to __init__()."""
        self.next_val = self.first_value

    def get_next(self, csv_row:dict=None):
        val = self.next_val
        if val is None:
            raise ParamSourceExhaustedExn()

        returnval = self.val_to_digit(val)

        val += 1
        if val > self.last_value:
            self.next_val = None
        else:
            self.next_val = val

        return returnval

class CsvSource(ParamSource):
    """apply a column from a CSV row, as passed in to ParamSource.get_next(csv_row)"""
    name = "from CSV"

    def __init__(self, input_str:str):
        """self.csv_column = input_str:
        column name indicating the column to use for this parameter.
        This name is used in get_next(): the caller passes the current CSV row to get_next(), from which
        CsvSource picks the column with the name matching csv_column.
        """
        """Parse input_str into self.num_digits, self.first_value, self.last_value."""
        super().__init__(input_str)
        self.csv_column = self.input_str

    def get_next(self, csv_row:dict=None):
        val = None
        if csv_row:
            val = csv_row.get(self.csv_column)
        if not val:
            raise ParamSourceUndefinedExn(f"no value for CSV column {self.csv_column!r}")
        return val
