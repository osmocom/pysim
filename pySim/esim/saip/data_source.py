# Data sources: Provding data for profile personalization
#
# (C) 2024 by Harald Welte <laforge@osmocom.org>
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

import abc
import secrets

from Cryptodome.Random import get_random_bytes

class DataSource(abc.ABC):
    """Base class for something that can provide data during a personalization process."""

    @abc.abstractmethod
    def generate_one(self):
        pass


class DataSourceFixed(DataSource):
    """A data source that provides a fixed value (of any type).

    Parameters:
        fixed_value: The fixed value that shall be used during each data generation
    """
    def __init__(self, fixed_value, **kwargs):
        self.fixed_value = fixed_value
        super().__init__(**kwargs)

    def generate_one(self):
        return self.fixed_value


class DataSourceIncrementing(DataSource):
    """A data source that provides incrementing integer numbers.

    Parameters:
        base_value: The start value (value returned during first data generation)
        step_size: Increment step size (Default: 1)
    """
    def __init__(self, base_value: int, **kwargs):
        self.base_value = int(base_value)
        self.step_size = kwargs.pop('step_size', 1)
        self.i = 0
        super().__init__(**kwargs)

    def generate_one(self):
        val = self.base_value + self.i
        self.i += self.step_size
        return val


class DataSourceRandomBytes(DataSource):
    """A data source that provides a configurable number of random bytes.

    Parameters:
        size: Number of bytes to generate each turn
    """
    def __init__(self, size: int, **kwargs):
        self.size = size
        super().__init__(**kwargs)

    def generate_one(self):
        return get_random_bytes(self.size)


class DataSourceRandomUInt(DataSource):
    """A data source that provides a configurable unsigned integer value.

    Parameters:
        below: Number one greater than the maximum permitted random unsigned integer
    """
    def __init__(self, below: int, **kwargs):
        self.below = below
        super().__init__(**kwargs)

    def generate_one(self):
        return secrets.randbelow(self.below)

