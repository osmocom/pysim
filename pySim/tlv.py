"""object-oriented TLV parser/encoder library."""

# (C) 2021 by Harald Welte <laforge@osmocom.org>
# All Rights Reserved
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

import inspect
import abc
import re
from typing import List, Tuple, Optional

from pySim.utils import bertlv_encode_len, bertlv_parse_len, bertlv_encode_tag, bertlv_parse_tag
from pySim.utils import comprehensiontlv_encode_tag, comprehensiontlv_parse_tag
from pySim.utils import bertlv_parse_tag_raw, comprehensiontlv_parse_tag_raw
from pySim.utils import dgi_parse_tag_raw, dgi_parse_len, dgi_encode_tag, dgi_encode_len

from pySim.construct import build_construct, parse_construct


def camel_to_snake(name):
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()

class TlvMeta(abc.ABCMeta):
    """Metaclass which we use to set some class variables at the time of defining a subclass.
    This allows us to create subclasses for each TLV/IE type, where the class represents fixed
    parameters like the tag/type and instances of it represent the actual TLV data."""
    def __new__(mcs, name, bases, namespace, **kwargs):
        #print("TlvMeta_new_(mcs=%s, name=%s, bases=%s, namespace=%s, kwargs=%s)" % (mcs, name, bases, namespace, kwargs))
        x = super().__new__(mcs, name, bases, namespace)
        # this becomes a _class_ variable, not an instance variable
        x.tag = namespace.get('tag', kwargs.get('tag', None))
        x.desc = namespace.get('desc', kwargs.get('desc', None))
        nested = namespace.get('nested', kwargs.get('nested', None))
        if nested is None or inspect.isclass(nested) and issubclass(nested, TLV_IE_Collection):
            # caller has specified TLV_IE_Collection sub-class, we can directly reference it
            x.nested_collection_cls = nested
        else:
            # caller passed list of other TLV classes that might possibly appear within us,
            # build a dynamically-created TLV_IE_Collection sub-class and reference it
            name = 'auto_collection_%s' % (name)
            cls = type(name, (TLV_IE_Collection,), {'nested': nested})
            x.nested_collection_cls = cls
        return x


class TlvCollectionMeta(abc.ABCMeta):
    """Metaclass which we use to set some class variables at the time of defining a subclass.
    This allows us to create subclasses for each Collection type, where the class represents fixed
    parameters like the nested IE classes and instances of it represent the actual TLV data."""
    def __new__(mcs, name, bases, namespace, **kwargs):
        #print("TlvCollectionMeta_new_(mcs=%s, name=%s, bases=%s, namespace=%s, kwargs=%s)" % (mcs, name, bases, namespace, kwargs))
        x = super().__new__(mcs, name, bases, namespace)
        # this becomes a _class_ variable, not an instance variable
        x.possible_nested = namespace.get('nested', kwargs.get('nested', None))
        return x


class Transcodable(abc.ABC):
    _construct = None
    """Base class for something that can be encoded + encoded.  Decoding and Encoding happens either
     * via a 'construct' object stored in a derived class' _construct variable, or
     * via a 'construct' object stored in an instance _construct variable, or
     * via a derived class' _{to,from}_bytes() methods."""

    def __init__(self):
        self.encoded = None
        self.decoded = None
        self._construct = None

    def to_bytes(self, context: dict = {}) -> bytes:
        """Convert from internal representation to binary bytes.  Store the binary result
        in the internal state and return it."""
        if self.decoded is None:
            do = b''
        elif self._construct:
            do = build_construct(self._construct, self.decoded, context)
        elif self.__class__._construct:
            do = build_construct(self.__class__._construct, self.decoded, context)
        else:
            do = self._to_bytes()
        self.encoded = do
        return do

    # not an abstractmethod, as it is only required if no _construct exists
    def _to_bytes(self):
        raise NotImplementedError('%s._to_bytes' % type(self).__name__)

    def from_bytes(self, do: bytes, context: dict = {}):
        """Convert from binary bytes to internal representation. Store the decoded result
        in the internal state and return it."""
        self.encoded = do
        if self.encoded == b'':
            self.decoded = None
        elif self._construct:
            self.decoded = parse_construct(self._construct, do, context=context)
        elif self.__class__._construct:
            self.decoded = parse_construct(self.__class__._construct, do, context=context)
        else:
            self.decoded = self._from_bytes(do)
        return self.decoded

    # not an abstractmethod, as it is only required if no _construct exists
    def _from_bytes(self, do: bytes):
        raise NotImplementedError('%s._from_bytes' % type(self).__name__)


class IE(Transcodable, metaclass=TlvMeta):
    # we specify the metaclass so any downstream subclasses will automatically use it
    """Base class for various Information Elements. We understand the notion of a hierarchy
    of IEs on top of the Transcodable class."""
    # this is overridden by the TlvMeta metaclass, if it is used to create subclasses
    nested_collection_cls = None
    tag = None

    def __init__(self, **kwargs):
        super().__init__()
        self.nested_collection = None
        if self.nested_collection_cls:
            self.nested_collection = self.nested_collection_cls()
        # if we are a constructed IE, [ordered] list of actual child-IE instances
        self.children = kwargs.get('children', [])
        self.decoded = kwargs.get('decoded', None)

    def __repr__(self):
        """Return a string representing the [nested] IE data (for print)."""
        if len(self.children):
            member_strs = [repr(x) for x in self.children]
            return '%s(%s)' % (type(self).__name__, ','.join(member_strs))
        else:
            return '%s(%s)' % (type(self).__name__, self.decoded)

    def to_dict(self):
        """Return a JSON-serializable dict representing the [nested] IE data."""
        if len(self.children):
            v = [x.to_dict() for x in self.children]
        else:
            v = self.decoded
        return {camel_to_snake(type(self).__name__): v}

    def from_dict(self, decoded: dict):
        """Set the IE internal decoded representation to data from the argument.
        If this is a nested IE, the child IE instance list is re-created."""
        expected_key_name = camel_to_snake(type(self).__name__)
        if not expected_key_name in decoded:
            raise ValueError("Dict %s doesn't contain expected key %s" % (decoded, expected_key_name))
        if self.nested_collection:
            self.children = self.nested_collection.from_dict(decoded[expected_key_name])
        else:
            self.children = []
            self.decoded = decoded[expected_key_name]

    def is_constructed(self):
        """Is this IE constructed by further nested IEs?"""
        return bool(len(self.children) > 0)

    @abc.abstractmethod
    def to_ie(self, context: dict = {}) -> bytes:
        """Convert the internal representation to entire IE including IE header."""

    def to_bytes(self, context: dict = {}) -> bytes:
        """Convert the internal representation *of the value part* to binary bytes."""
        if self.is_constructed():
            # concatenate the encoded IE of all children to form the value part
            out = b''
            for c in self.children:
                out += c.to_ie(context=context)
            return out
        else:
            return super().to_bytes(context=context)

    def from_bytes(self, do: bytes, context: dict = {}):
        """Parse *the value part* from binary bytes to internal representation."""
        if self.nested_collection:
            self.children = self.nested_collection.from_bytes(do, context=context)
        else:
            self.children = []
            return super().from_bytes(do, context=context)

    def child_by_name(self, name: str) -> Optional['IE']:
        """Return a child IE instance of given snake-case/json type name. This only works in case
        there is no more than one child IE of the given type."""
        children = list(filter(lambda c: camel_to_snake(type(c).__name__) == name, self.children))
        if len(children) > 1:
            raise KeyError('There are multiple children of class %s' % name)
        elif len(children) == 1:
            return children[0]

    def child_by_type(self, cls) -> Optional['IE']:
        """Return a child IE instance of given type (class). This only works in case
        there is no more than one child IE of the given type."""
        children = list(filter(lambda c: isinstance(c, cls), self.children))
        if len(children) > 1:
            raise KeyError('There are multiple children of class %s' % cls)
        elif len(children) == 1:
            return children[0]


class TLV_IE(IE):
    """Abstract base class for various TLV type Information Elements."""

    def _compute_tag(self) -> int:
        """Compute the tag (sometimes the tag encodes part of the value)."""
        return self.tag

    @classmethod
    @abc.abstractmethod
    def _parse_tag_raw(cls, do: bytes) -> Tuple[int, bytes]:
        """Obtain the raw TAG at the start of the bytes provided by the user."""

    @classmethod
    @abc.abstractmethod
    def _parse_len(cls, do: bytes) -> Tuple[int, bytes]:
        """Obtain the length encoded at the start of the bytes provided by the user."""

    @abc.abstractmethod
    def _encode_tag(self) -> bytes:
        """Encode the tag part. Must be provided by derived (TLV format specific) class."""

    @abc.abstractmethod
    def _encode_len(self, val: bytes) -> bytes:
        """Encode the length part assuming a certain binary value. Must be provided by
        derived (TLV format specific) class."""

    def to_ie(self, context: dict = {}):
        return self.to_tlv(context=context)

    def to_tlv(self, context: dict = {}):
        """Convert the internal representation to binary TLV bytes."""
        val = self.to_bytes(context=context)
        return self._encode_tag() + self._encode_len(val) + val

    def is_tag_compatible(self, rawtag) -> bool:
        """Is the given rawtag compatible with this class?"""
        return rawtag == self._compute_tag()

    def from_tlv(self, do: bytes, context: dict = {}):
        if len(do) == 0:
            return {}, b''
        (rawtag, remainder) = self.__class__._parse_tag_raw(do)
        if rawtag:
            if not self.is_tag_compatible(rawtag):
                raise ValueError("%s: Encountered tag %s doesn't match our supported tag %s" %
                                 (self, rawtag, self.tag))
            (length, remainder) = self.__class__._parse_len(remainder)
            value = remainder[:length]
            remainder = remainder[length:]
        else:
            value = do
            remainder = b''
        dec = self.from_bytes(value, context=context)
        return dec, remainder


class COMPACT_TLV_IE(TLV_IE):
    """TLV_IE formatted as COMPACT-TLV described in ISO 7816"""

    @classmethod
    def _parse_tag_raw(cls, do: bytes) -> Tuple[int, bytes]:
        return do[0] >> 4, do

    @classmethod
    def _decode_tag(cls, do: bytes) -> Tuple[dict, bytes]:
        rawtag, remainder = cls._parse_tag_raw(do)
        return {'tag': rawtag}, remainder

    @classmethod
    def _parse_len(cls, do: bytes) -> Tuple[int, bytes]:
        return do[0] & 0xf, do[1:]

    def _encode_tag(self) -> bytes:
        """Not needed as we override the to_tlv() method to encode tag+length into one byte."""
        raise NotImplementedError

    def _encode_len(self):
        """Not needed as we override the to_tlv() method to encode tag+length into one byte."""
        raise NotImplementedError

    def to_tlv(self, context: dict = {}):
        val = self.to_bytes(context=context)
        return bytes([(self.tag << 4) | (len(val) & 0xF)]) + val


class BER_TLV_IE(TLV_IE):
    """TLV_IE formatted as ASN.1 BER described in ITU-T X.690 8.1.2."""

    @classmethod
    def _decode_tag(cls, do: bytes) -> Tuple[dict, bytes]:
        return bertlv_parse_tag(do)

    @classmethod
    def _parse_tag_raw(cls, do: bytes) -> Tuple[int, bytes]:
        return bertlv_parse_tag_raw(do)

    @classmethod
    def _parse_len(cls, do: bytes) -> Tuple[int, bytes]:
        return bertlv_parse_len(do)

    def _encode_tag(self) -> bytes:
        return bertlv_encode_tag(self._compute_tag())

    def _encode_len(self, val: bytes) -> bytes:
        return bertlv_encode_len(len(val))


class ComprTlvMeta(TlvMeta):
    def __new__(mcs, name, bases, namespace, **kwargs):
        x = super().__new__(mcs, name, bases, namespace, **kwargs)
        if x.tag:
            # we currently assume that the tag values always have the comprehension bit set;
            # let's fix it up if a derived class has forgotten about that
            if x.tag > 0xff and x.tag & 0x8000 == 0:
                print("Fixing up COMPR_TLV_IE class %s: tag=0x%x has no comprehension bit" % (name, x.tag))
                x.tag = x.tag | 0x8000
            elif x.tag & 0x80 == 0:
                print("Fixing up COMPR_TLV_IE class %s: tag=0x%x has no comprehension bit" % (name, x.tag))
                x.tag = x.tag | 0x80
        return x

class COMPR_TLV_IE(TLV_IE, metaclass=ComprTlvMeta):
    """TLV_IE formated as COMPREHENSION-TLV as described in ETSI TS 101 220."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.comprehension = False

    @classmethod
    def _decode_tag(cls, do: bytes) -> Tuple[dict, bytes]:
        return comprehensiontlv_parse_tag(do)

    @classmethod
    def _parse_tag_raw(cls, do: bytes) -> Tuple[int, bytes]:
        return comprehensiontlv_parse_tag_raw(do)

    @classmethod
    def _parse_len(cls, do: bytes) -> Tuple[int, bytes]:
        return bertlv_parse_len(do)

    def is_tag_compatible(self, rawtag: int) -> bool:
        """Override is_tag_compatible as we need to mask out the
        comprehension bit when doing compares."""
        ctag = self._compute_tag()
        if ctag > 0xff:
            return ctag & 0x7fff == rawtag & 0x7fff
        else:
            return ctag & 0x7f == rawtag & 0x7f

    def _encode_tag(self) -> bytes:
        return comprehensiontlv_encode_tag(self._compute_tag())

    def _encode_len(self, val: bytes) -> bytes:
        return bertlv_encode_len(len(val))


class DGI_TLV_IE(TLV_IE):
    """TLV_IE formated as  GlobalPlatform Systems Scripting Language Specification v1.1.0 Annex B."""

    @classmethod
    def _parse_tag_raw(cls, do: bytes) -> Tuple[int, bytes]:
        return dgi_parse_tag_raw(do)

    @classmethod
    def _parse_len(cls, do: bytes) -> Tuple[int, bytes]:
        return dgi_parse_len(do)

    def _encode_tag(self) -> bytes:
        return dgi_encode_tag(self._compute_tag())

    def _encode_len(self, val: bytes) -> bytes:
        return dgi_encode_len(len(val))


class TLV_IE_Collection(metaclass=TlvCollectionMeta):
    # we specify the metaclass so any downstream subclasses will automatically use it
    """A TLV_IE_Collection consists of multiple TLV_IE classes identified by their tags.
    A given encoded DO may contain any of them in any order, and may contain multiple instances
    of each DO."""
    # this is overridden by the TlvCollectionMeta metaclass, if it is used to create subclasses
    possible_nested = []

    def __init__(self, desc=None, **kwargs):
        self.desc = desc
        #print("possible_nested: ", self.possible_nested)
        self.members = kwargs.get('nested', self.possible_nested)
        self.members_by_tag = {}
        self.members_by_name = {}
        self.members_by_tag = {m.tag: m for m in self.members}
        self.members_by_name = {camel_to_snake(m.__name__): m for m in self.members}
        # if we are a constructed IE, [ordered] list of actual child-IE instances
        self.children = kwargs.get('children', [])
        self.encoded = None

    def __str__(self):
        member_strs = [str(x) for x in self.members]
        return '%s(%s)' % (type(self).__name__, ','.join(member_strs))

    def __repr__(self):
        member_strs = [repr(x) for x in self.members]
        return '%s(%s)' % (self.__class__, ','.join(member_strs))

    def __add__(self, other):
        """Extending TLV_IE_Collections with other TLV_IE_Collections or TLV_IEs."""
        if isinstance(other, TLV_IE_Collection):
            # adding one collection to another
            members = self.members + other.members
            return TLV_IE_Collection(self.desc, nested=members)
        elif inspect.isclass(other) and issubclass(other, TLV_IE):
            # adding a member to a collection
            return TLV_IE_Collection(self.desc, nested=self.members + [other])
        else:
            raise TypeError

    def from_bytes(self, binary: bytes, context: dict = {}) -> List[TLV_IE]:
        """Create a list of TLV_IEs from the collection based on binary input data.
        Args:
            binary : binary bytes of encoded data
        Returns:
            list of instances of TLV_IE sub-classes containing parsed data
        """
        self.encoded = binary
        # list of instances of TLV_IE collection member classes appearing in the data
        res = []
        remainder = binary
        first = next(iter(self.members_by_tag.values()))
        # iterate until no binary trailer is left
        while len(remainder):
            context['siblings'] = res
            # obtain the tag at the start of the remainder
            tag, _r = first._parse_tag_raw(remainder)
            if tag is None:
                break
            if issubclass(first, COMPR_TLV_IE):
                tag = tag | 0x80 # HACK: always assume comprehension
            if tag in self.members_by_tag:
                cls = self.members_by_tag[tag]
                # create an instance and parse accordingly
                inst = cls()
                _dec, remainder = inst.from_tlv(remainder, context=context)
                res.append(inst)
            else:
                # unknown tag; create the related class on-the-fly using the same base class
                name = 'unknown_%s_%X' % (first.__base__.__name__, tag)
                cls = type(name, (first.__base__,), {'tag': tag, 'possible_nested': [],
                                                     'nested_collection_cls': None})
                cls._from_bytes = lambda s, a: {'raw': a.hex()}
                cls._to_bytes = lambda s: bytes.fromhex(s.decoded['raw'])
                # create an instance and parse accordingly
                inst = cls()
                _dec, remainder = inst.from_tlv(remainder, context=context)
                res.append(inst)
        self.children = res
        return res

    def from_dict(self, decoded: List[dict]) -> List[TLV_IE]:
        """Create a list of TLV_IE instances from the collection based on an array
        of dicts, where they key indicates the name of the TLV_IE subclass to use."""
        # list of instances of TLV_IE collection member classes appearing in the data
        res = []
        # iterate over members of the list passed into "decoded"
        for i in decoded:
            # iterate over all the keys (typically one!) within the current list item dict
            for k in i.keys():
                # check if we have a member identified by the dict key
                if k in self.members_by_name:
                    # resolve the class for that name; create an instance of it
                    cls = self.members_by_name[k]
                    inst = cls()
                    if cls.nested_collection_cls:
                        # in case of collections, we want to pass the raw "value" portion to from_dict,
                        # as to_dict() below intentionally omits the collection-class-name as key
                        inst.from_dict(i[k])
                    else:
                        inst.from_dict({k: i[k]})
                    res.append(inst)
                else:
                    raise ValueError('%s: Unknown TLV Class %s in %s; expected %s' %
                                     (self, k, decoded, self.members_by_name.keys()))
        self.children = res
        return res

    def to_dict(self):
        # we intentionally return not a dict, but a list of dicts.  We could prefix by
        # self.__class__.__name__, but that is usually some meaningless auto-generated  collection name.
        return [x.to_dict() for x in self.children]

    def to_bytes(self, context: dict = {}):
        out = b''
        context['siblings'] = self.children
        for c in self.children:
            out += c.to_tlv(context=context)
        return out

    def from_tlv(self, do, context: dict = {}):
        return self.from_bytes(do, context=context)

    def to_tlv(self, context: dict = {}):
        return self.to_bytes(context=context)


def flatten_dict_lists(inp):
    """hierarchically flatten each list-of-dicts into a single dict. This is useful to
       make the output of hierarchical TLV decoder structures flatter and more easy to read."""
    def are_all_elements_dict(l):
        for e in l:
            if not isinstance(e, dict):
                return False
        return True

    def are_elements_unique(lod):
        set_of_keys = {list(x.keys())[0] for x in lod}
        return len(lod) == len(set_of_keys)

    if isinstance(inp, list):
        if are_all_elements_dict(inp) and are_elements_unique(inp):
            # flatten into one shared dict
            newdict = {}
            for e in inp:
                key = list(e.keys())[0]
                newdict[key] = e[key]
            inp = newdict
            # process result as any native dict
            return {k:flatten_dict_lists(v) for k,v in inp.items()}
        else:
            return [flatten_dict_lists(x) for x in inp]
    elif isinstance(inp, dict):
        return {k:flatten_dict_lists(v) for k,v in inp.items()}
    else:
        return inp
