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
import pprint
from typing import List, Generator
from pySim.esim.saip.personalization import ConfigurableParameter
from pySim.esim.saip import param_source
from pySim.esim.saip import ProfileElementSequence, ProfileElementSD
from pySim.global_platform import KeyUsageQualifier
from osmocom.utils import b2h

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


class UppAudit(dict):
    """
    Key-value pairs collected from a single UPP DER or PES.

    UppAudit itself is a dict, callers may use the standard python dict API to access key-value pairs read from the UPP.
    """

    @classmethod
    def from_der(cls, der: bytes, params: List, der_size=False, additional_sd_keys=False):
        '''return a dict of parameter name and set of selected parameter values found in a DER encoded profile. Note:
        some ConfigurableParameter implementations return more than one key-value pair, for example, Imsi returns
        both 'IMSI' and 'IMSI-ACC' parameters.

        e.g.
            UppAudit.from_der(my_der, [Imsi, ])
            --> {'IMSI': '001010000000023', 'IMSI-ACC': '5'}

        (where 'IMSI' == Imsi.name)

        Read all parameters listed in params. params is a list of either ConfigurableParameter classes or
        ConfigurableParameter class instances. This calls only classmethods, so each entry in params can either be the
        class itself, or a class-instance of, a (non-abstract) ConfigurableParameter subclass.
        For example, params = [Imsi, ] is equivalent to params = [Imsi(), ].

        For der_size=True, also include a {'der_size':12345} entry.

        For additional_sd_keys=True, output also all Security Domain KVN that there are *no* ConfigurableParameter
        subclasses for. For example, SCP80 has reserved kvn 0x01..0x0f, but we offer only Scp80Kvn01, Scp80Kvn02,
        Scp80Kvn03. So we would not show kvn 0x04..0x0f in an audit. additional_sd_keys=True includes audits of all SD
        key KVN there may be in the UPP. This helps to spot SD keys that may already be present in a UPP template, with
        unexpected / unusual kvn.
        '''

        # make an instance of this class
        upp_audit = cls()

        if der_size:
            upp_audit['der_size'] = set((len(der), ))

        pes = ProfileElementSequence.from_der(der)
        for param in params:
            try:
                for valdict in param.get_values_from_pes(pes):
                    upp_audit.add_values(valdict)
            except (TypeError, ValueError) as e:
                raise ValueError(f'Error during audit for parameter {param}: {e}') from e

        if not additional_sd_keys:
            return upp_audit

        # additional_sd_keys
        for pe in pes.pe_list:
            if pe.type != 'securityDomain':
                continue
            assert isinstance(pe, ProfileElementSD)

            for key in pe.keys:
                audit_key = f'SdKey_KVN{key.key_version_number:02x}_ID{key.key_identifier:02x}'
                kuq_bin = KeyUsageQualifier.build(key.key_usage_qualifier).hex()
                audit_val = f'{key.key_components=!r} key_usage_qualifier=0x{kuq_bin}={key.key_usage_qualifier!r}'
                upp_audit[audit_key] = set((audit_val, ))

        return upp_audit

    def get_single_val(self, key, validate=True, allow_absent=False, absent_val=None):
        """
        Return the audit's value for the given audit key (like 'IMSI' or 'IMSI-ACC').
        Any kind of value may occur multiple times in a profile. When all of these agree to the same unambiguous value,
        return that value. When they do not agree, raise a ValueError.
        """
        # key should be a string, but if someone passes a ConfigurableParameter, just use its default name
        if ConfigurableParameter.is_super_of(key):
            key = key.get_name()

        assert isinstance(key, str)
        v = self.get(key)
        if v is None and allow_absent:
            return absent_val
        if not isinstance(v, set):
            raise ValueError(f'audit value should be a set(), got {v!r}')
        if len(v) != 1:
            raise ValueError(f'expected a single value for {key}, got {v!r}')
        v = tuple(v)[0]
        return v

    @staticmethod
    def audit_val_to_str(v):
        """
        Usually, we want to see a single value in an audit. Still, to be able to collect multiple ambiguous values,
        audit values are always python sets. Turn it into a nice string representation: only the value when it is
        unambiguous, otherwise a list of the ambiguous values.
        A value may also be completely absent, then return 'not present'.
        """
        def try_single_val(w):
            'change single-entry sets to just the single value'
            if isinstance(w, set):
                if len(w) == 1:
                    return tuple(w)[0]
                if len(w) == 0:
                    return None
            return w

        v = try_single_val(v)
        if isinstance(v, bytes):
            v = bytes_to_hexstr(v)
        if v is None:
            return 'not present'
        return str(v)

    def get_val_str(self, key):
        """Return a string of the value stored for the given key"""
        return UppAudit.audit_val_to_str(self.get(key))

    def add_values(self, src:dict):
        """self and src are both a dict of sets.
        For example from
            self == { 'a': set((123,)) }
        and
            src == { 'a': set((456,)), 'b': set((789,)) }
        then after this function call:
            self == { 'a': set((123, 456,)), 'b': set((789,)) }
        """
        assert isinstance(src, dict)
        for key, srcvalset in src.items():
            dstvalset = self.get(key)
            if dstvalset is None:
                dstvalset = set()
                self[key] = dstvalset
            dstvalset.add(srcvalset)

    def __str__(self):
        return '\n'.join(f'{key}: {self.get_val_str(key)}' for key in sorted(self.keys()))

class BatchAudit(list):
    """
    Collect UppAudit instances for a batch of UPP, for example from a personalization.BatchPersonalization.
    Produce an output CSV.

    Usage example:

        ba = BatchAudit(params=(personalization.Iccid, ))
        for upp_der in upps:
            ba.add_audit(upp_der)
        print(ba.summarize())

        with open('output.csv', 'wb') as csv_data:
            csv_str = io.TextIOWrapper(csv_data, 'utf-8', newline='')
            csv.writer(csv_str).writerows( ba.to_csv_rows() )
            csv_str.flush()

    BatchAudit itself is a list, callers may use the standard python list API to access the UppAudit instances.
    """

    def __init__(self, params:List):
        assert params
        self.params = params

    def add_audit(self, upp_der:bytes):
        audit = UppAudit.from_der(upp_der, self.params)
        self.append(audit)
        return audit

    def summarize(self):
        batch_audit = UppAudit()

        audits = self

        if len(audits) > 2:
            val_sep = ', ..., '
        else:
            val_sep = ', '

        first_audit = None
        last_audit = None
        if len(audits) >= 1:
            first_audit = audits[0]
        if len(audits) >= 2:
            last_audit = audits[-1]

        if first_audit:
            if last_audit:
                for key in first_audit.keys():
                    first_val = first_audit.get_val_str(key)
                    last_val = last_audit.get_val_str(key)

                    if first_val == last_val:
                        val = first_val
                    else:
                        val_sep_with_newline = f"{val_sep.rstrip()}\n{' ' * (len(key) + 2)}"
                        val = val_sep_with_newline.join((first_val, last_val))
                    batch_audit[key] = val
            else:
                batch_audit.update(first_audit)

        return batch_audit

    def to_csv_rows(self, headers=True, sort_key=None):
        '''generator that yields all audits' values as rows, useful feed to a csv.writer.'''
        columns = set()
        for audit in self:
            columns.update(audit.keys())

        columns = tuple(sorted(columns, key=sort_key))

        if headers:
            yield columns

        for audit in self:
            yield (audit.get_single_val(col, allow_absent=True, absent_val="") for col in columns)

def bytes_to_hexstr(b:bytes, sep=''):
    return sep.join(f'{x:02x}' for x in b)

def esim_profile_introspect(upp):
    pes = ProfileElementSequence.from_der(upp.read())
    d = {}
    d['upp'] = repr(pes)

    def show_bytes_as_hexdump(item):
        if isinstance(item, bytes):
            return bytes_to_hexstr(item)
        if isinstance(item, list):
            return list(show_bytes_as_hexdump(i) for i in item)
        if isinstance(item, tuple):
            return tuple(show_bytes_as_hexdump(i) for i in item)
        if isinstance(item, dict):
            d = {}
            for k, v in item.items():
                d[k] = show_bytes_as_hexdump(v)
            return d
        return item

    l = list((pe.type, show_bytes_as_hexdump(pe.decoded)) for pe in pes)
    d['pp'] = pprint.pformat(l, width=120)
    return d
