"""Implementation of Personalization of eSIM profiles in SimAlliance/TCA Interoperable Profile:
   Run a batch of N personalizations"""

# (C) 2025-2026 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

import copy
from typing import Generator
from pySim.esim.saip.personalization import ConfigurableParameter
from pySim.esim.saip import param_source
from pySim.esim.saip import ProfileElementSequence, ProfileElementSD

class BatchPersonalization:
    """Produce a series of eSIM profiles from predefined parameters.
    Personalization parameters are derived from pysim.esim.saip.param_source.ParamSource.

    Usage example:

    der_input = some_file.open('rb').read()
    pes = ProfileElementSequence.from_der(der_input)
    p = pers.BatchPersonalization(
        n=10,
        src_pes=pes,
        csv_rows=get_csv_reader())

    p.add_param_and_src(
        personalization.Iccid(),
        param_source.IncDigitSource(
            num_digits=18,
            first_value=123456789012340001,
            last_value=123456789012340010))

    # add more parameters here, using ConfigurableParameter and ParamSource subclass instances to define the profile
    # ...

    # generate all 10 profiles (from n=10 above)
    for result_pes in p.generate_profiles():
        upp = result_pes.to_der()
        store_upp(upp)
    """

    class ParamAndSrc:
        'tie a ConfigurableParameter to a source of actual values'
        def __init__(self, param: ConfigurableParameter, src: param_source.ParamSource):
            self.param = param
            self.src = src

    def __init__(self,
                 n: int,
                 src_pes: ProfileElementSequence,
                 params: list[ParamAndSrc]=None,
                 csv_rows: Generator=None,
                ):
        """
        n: number of eSIM profiles to generate.
        src_pes: a decoded eSIM profile as ProfileElementSequence, to serve as template. This is not modified, only
                 copied.
        params: list of ParamAndSrc instances, defining a ConfigurableParameter and corresponding ParamSource to fill in
                profile values.
        csv_rows: A list or generator producing all CSV rows one at a time, starting with a row containing the column
                  headers. This is compatible with the python csv.reader. Each row gets passed to
                  ParamSource.get_next(), such that ParamSource implementations can access the row items.
                  See param_source.CsvSource.
        """
        self.n = n
        self.params = params or []
        self.src_pes = src_pes
        self.csv_rows = csv_rows

    def add_param_and_src(self, param:ConfigurableParameter, src:param_source.ParamSource):
        self.params.append(BatchPersonalization.ParamAndSrc(param=param, src=src))

    def generate_profiles(self):
        # get first row of CSV: column names
        csv_columns = None
        if self.csv_rows:
            try:
                csv_columns = next(self.csv_rows)
            except StopIteration as e:
                raise ValueError('the input CSV file appears to be empty') from e

        for i in range(self.n):
            csv_row = None
            if self.csv_rows and csv_columns:
                try:
                    csv_row_list = next(self.csv_rows)
                except StopIteration as e:
                    raise ValueError(f'not enough rows in the input CSV for eSIM nr {i+1} of {self.n}') from e

                csv_row = dict(zip(csv_columns, csv_row_list))

            pes = copy.deepcopy(self.src_pes)

            for p in self.params:
                try:
                    input_value = p.src.get_next(csv_row=csv_row)
                    assert input_value is not None
                    value = p.param.__class__.validate_val(input_value)
                    p.param.__class__.apply_val(pes, value)
                except Exception as e:
                    raise ValueError(f'{p.param.name} fed by {p.src.name}: {e}') from e

            yield pes
