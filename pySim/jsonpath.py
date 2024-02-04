"""JSONpath utility functions as needed within pysim.

As pySim-sell has the ability to represent SIM files as JSON strings,
adding JSONpath allows us to conveniently modify individual sub-fields
of a file or record in its JSON representation.
"""

import jsonpath_ng

# (C) 2021 by Harald Welte <laforge@osmocom.org>
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


def js_path_find(js_dict, js_path):
    """Find/Match a JSON path within a given JSON-serializable dict.
    Args:
        js_dict : JSON-serializable dict to operate on
        js_path : JSONpath string
    Returns: Result of the JSONpath expression
    """
    jsonpath_expr = jsonpath_ng.parse(js_path)
    return jsonpath_expr.find(js_dict)


def js_path_modify(js_dict, js_path, new_val):
    """Find/Match a JSON path within a given JSON-serializable dict.
    Args:
        js_dict : JSON-serializable dict to operate on
        js_path : JSONpath string
        new_val : New value for field in js_dict at js_path
    """
    jsonpath_expr = jsonpath_ng.parse(js_path)
    jsonpath_expr.find(js_dict)
    jsonpath_expr.update(js_dict, new_val)
