import pprint
from pprint import PrettyPrinter
from functools import singledispatch, wraps
from typing import get_type_hints

from pySim.utils import b2h

def common_container_checks(f):
    type_ = get_type_hints(f)['object']
    base_impl = type_.__repr__
    empty_repr = repr(type_())   # {}, [], ()
    too_deep_repr = f'{empty_repr[0]}...{empty_repr[-1]}'  # {...}, [...], (...)
    @wraps(f)
    def wrapper(object, context, maxlevels, level):
        if type(object).__repr__ is not base_impl:  # subclassed repr
            return repr(object)
        if not object:                              # empty, short-circuit
            return empty_repr
        if maxlevels and level >= maxlevels:        # exceeding the max depth
            return too_deep_repr
        oid = id(object)
        if oid in context:                          # self-reference
            return pprint._recursion(object)
        context[oid] = 1
        result = f(object, context, maxlevels, level)
        del context[oid]
        return result
    return wrapper

@singledispatch
def saferepr(object, context, maxlevels, level):
    return repr(object)

@saferepr.register
def _handle_bytes(object: bytes, *args):
    if len(object) <= 40:
        return '"%s"' % b2h(object)
    else:
        return '"%s...%s"' % (b2h(object[:20]), b2h(object[-20:]))

@saferepr.register
@common_container_checks
def _handle_dict(object: dict, context, maxlevels, level):
    level += 1
    contents = [
        f'{saferepr(k, context, maxlevels, level)}: '
        f'{saferepr(v, context, maxlevels, level)}'
        for k, v in sorted(object.items(), key=pprint._safe_tuple)
    ]
    return f'{{{", ".join(contents)}}}'

@saferepr.register
@common_container_checks
def _handle_list(object: list, context, maxlevels, level):
    level += 1
    contents = [
        f'{saferepr(v, context, maxlevels, level)}'
        for v in object
    ]
    return f'[{", ".join(contents)}]'

@saferepr.register
@common_container_checks
def _handle_tuple(object: tuple, context, maxlevels, level):
    level += 1
    if len(object) == 1:
        return f'({saferepr(object[0], context, maxlevels, level)},)'
    contents = [
        f'{saferepr(v, context, maxlevels, level)}'
        for v in object
    ]
    return f'({", ".join(contents)})'

class HexBytesPrettyPrinter(PrettyPrinter):
    def format(self, *args):
        # it doesn't matter what the boolean values are here
        return saferepr(*args), True, False
