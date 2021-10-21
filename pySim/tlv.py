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


from typing import Optional, List, Dict, Any, Tuple
from bidict import bidict
from construct import *

from pySim.utils import bertlv_encode_len, bertlv_parse_len, bertlv_encode_tag, bertlv_parse_tag
from pySim.utils import comprehensiontlv_encode_tag, comprehensiontlv_parse_tag
from pySim.utils import bertlv_parse_one, comprehensiontlv_parse_one
from pySim.utils import bertlv_parse_tag_raw, comprehensiontlv_parse_tag_raw

from pySim.construct import parse_construct, LV, HexAdapter, BcdAdapter, BitsRFU, GsmStringAdapter
from pySim.exceptions import *

import inspect
import abc

class TlvMeta(abc.ABCMeta):
    """Metaclass which we use to set some class variables at the time of defining a subclass.
    This allows us to create subclasses for each TLV/IE type, where the class represents fixed
    parameters like the tag/type and instances of it represent the actual TLV data."""
    def __new__(metacls, name, bases, namespace, **kwargs):
        #print("TlvMeta_new_(metacls=%s, name=%s, bases=%s, namespace=%s, kwargs=%s)" % (metacls, name, bases, namespace, kwargs))
        x = super().__new__(metacls, name, bases, namespace)
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
    def __new__(metacls, name, bases, namespace, **kwargs):
        #print("TlvCollectionMeta_new_(metacls=%s, name=%s, bases=%s, namespace=%s, kwargs=%s)" % (metacls, name, bases, namespace, kwargs))
        x = super().__new__(metacls, name, bases, namespace)
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

    def to_bytes(self) -> bytes:
        """Convert from internal representation to binary bytes.  Store the binary result
        in the internal state and return it."""
        if not self.decoded:
            do = b''
        elif self._construct:
            do = self._construct.build(self.decoded, total_len=None)
        elif self.__class__._construct:
            do = self.__class__._construct.build(self.decoded, total_len=None)
        else:
            do = self._to_bytes()
        self.encoded = do
        return do

    # not an abstractmethod, as it is only required if no _construct exists
    def _to_bytes(self):
        raise NotImplementedError

    def from_bytes(self, do:bytes):
        """Convert from binary bytes to internal representation. Store the decoded result
        in the internal state and return it."""
        self.encoded = do
        if self.encoded == b'':
            self.decoded = None
        elif self._construct:
            self.decoded = parse_construct(self._construct, do)
        elif self.__class__._construct:
            self.decoded = parse_construct(self.__class__._construct, do)
        else:
            self.decoded = self._from_bytes(do)
        return self.decoded

    # not an abstractmethod, as it is only required if no _construct exists
    def _from_bytes(self, do:bytes):
        raise NotImplementedError

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
        return {type(self).__name__: v}

    def from_dict(self, decoded:dict):
        """Set the IE internal decoded representation to data from the argument.
        If this is a nested IE, the child IE instance list is re-created."""
        if self.nested_collection:
            self.children = self.nested_collection.from_dict(decoded)
        else:
            self.children = []
            self.decoded = decoded

    def is_constructed(self):
        """Is this IE constructed by further nested IEs?"""
        if len(self.children):
            return True
        else:
            return False

    @abc.abstractmethod
    def to_ie(self) -> bytes:
        """Convert the internal representation to entire IE including IE header."""

    def to_bytes(self) -> bytes:
        """Convert the internal representation _of the value part_ to binary bytes."""
        if self.is_constructed():
            # concatenate the encoded IE of all children to form the value part
            out = b''
            for c in self.children:
                out += c.to_ie()
            return out
        else:
            return super().to_bytes()

    def from_bytes(self, do:bytes):
        """Parse _the value part_ from binary bytes to internal representation."""
        if self.nested_collection:
            self.children = self.nested_collection.from_bytes(do)
        else:
            self.children = []
            return super().from_bytes(do)


class TLV_IE(IE):
    """Abstract base class for various TLV type Information Elements."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _compute_tag(self) -> int:
        """Compute the tag (sometimes the tag encodes part of the value)."""
        return self.tag

    @classmethod
    @abc.abstractmethod
    def _parse_tag_raw(cls, do:bytes) -> Tuple[int, bytes]:
        """Obtain the raw TAG at the start of the bytes provided by the user."""

    @classmethod
    @abc.abstractmethod
    def _parse_len(cls, do:bytes) -> Tuple[int, bytes]:
        """Obtain the length encoded at the start of the bytes provided by the user."""

    @abc.abstractmethod
    def _encode_tag(self) -> bytes:
        """Encode the tag part. Must be provided by derived (TLV format specific) class."""

    @abc.abstractmethod
    def _encode_len(self, val:bytes) -> bytes:
        """Encode the length part assuming a certain binary value. Must be provided by
        derived (TLV format specific) class."""

    def to_ie(self):
        return self.to_tlv()

    def to_tlv(self):
        """Convert the internal representation to binary TLV bytes."""
        val = self.to_bytes()
        return self._encode_tag() + self._encode_len(val) + val

    def from_tlv(self, do:bytes):
        (rawtag, remainder) = self.__class__._parse_tag_raw(do)
        if rawtag:
            if rawtag != self.tag:
                raise ValueError("%s: Encountered tag %s doesn't match our supported tag %s" %
                                 (self, rawtag, self.tag))
            (length, remainder) = self.__class__._parse_len(remainder)
            value = remainder[:length]
            remainder = remainder[length:]
        else:
            value = do
            remainder = b''
        dec = self.from_bytes(value)
        return dec, remainder


class BER_TLV_IE(TLV_IE):
    """TLV_IE formatted as ASN.1 BER described in ITU-T X.690 8.1.2."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @classmethod
    def _decode_tag(cls, do:bytes) -> Tuple[dict, bytes]:
        return bertlv_parse_tag(do)

    @classmethod
    def _parse_tag_raw(cls, do:bytes) -> Tuple[int, bytes]:
        return bertlv_parse_tag_raw(do)

    @classmethod
    def _parse_len(cls, do:bytes) -> Tuple[int, bytes]:
        return bertlv_parse_len(do)

    def _encode_tag(self) -> bytes:
        return bertlv_encode_tag(self._compute_tag())

    def _encode_len(self, val:bytes) -> bytes:
        return bertlv_encode_len(len(val))


class COMPR_TLV_IE(TLV_IE):
    """TLV_IE formated as COMPREHENSION-TLV as described in ETSI TS 101 220."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.comprehension = False

    @classmethod
    def _decode_tag(cls, do:bytes) -> Tuple[dict, bytes]:
        return comprehensiontlv_parse_tag(do)

    @classmethod
    def _parse_tag_raw(cls, do:bytes) -> Tuple[int, bytes]:
        return comprehensiontlv_parse_tag_raw(do)

    @classmethod
    def _parse_len(cls, do:bytes) -> Tuple[int, bytes]:
        return bertlv_parse_len(do)

    def _encode_tag(self) -> bytes:
        return comprehensiontlv_encode_tag(self._compute_tag())

    def _encode_len(self, val:bytes) -> bytes:
        return bertlv_encode_len(len(val))


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
        self.members_by_tag = { m.tag:m for m in self.members }
        self.members_by_name = { m.__name__:m for m in self.members }
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
            return TLV_IE_Collection(self.desc, nested = self.members + [other])
        else:
            raise TypeError

    def from_bytes(self, binary:bytes) -> List[TLV_IE]:
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
            # obtain the tag at the start of the remainder
            tag, r = first._parse_tag_raw(remainder)
            if tag == None:
                return res
            if tag in self.members_by_tag:
                cls = self.members_by_tag[tag]
                # create an instance and parse accordingly
                inst = cls()
                dec, remainder = inst.from_tlv(remainder)
                res.append(inst)
            else:
                # unknown tag; create the related class on-the-fly using the same base class
                name = 'unknown_%s_%X' % (first.__base__.__name__, tag)
                cls = type(name, (first.__base__,), {'tag':tag, 'possible_nested':[],
                    'nested_collection_cls':None})
                cls._from_bytes = lambda s, a : {'raw': a.hex()}
                cls._to_bytes = lambda s: bytes.fromhex(s.decoded['raw'])
                # create an instance and parse accordingly
                inst = cls()
                dec, remainder = inst.from_tlv(remainder)
                res.append(inst)
        self.children = res
        return res

    def from_dict(self, decoded:List[dict]) -> List[TLV_IE]:
        """Create a list of TLV_IE instances from the collection based on an array
        of dicts, where they key indicates the name of the TLV_IE subclass to use."""
        # list of instances of TLV_IE collection member classes appearing in the data
        res = []
        for i in decoded:
            for k in i.keys():
                if k in self.members_by_name:
                    cls = self.members_by_name[k]
                    inst = cls()
                    inst.from_dict(i[k])
                    res.append(inst)
                else:
                    raise ValueError('%s: Unknown TLV Class %s in %s; expected %s' %
                                     (self, i[0], decoded, self.members_by_name.keys()))
        self.children = res
        return res

    def to_dict(self):
        return [x.to_dict() for x in self.children]

    def to_bytes(self):
        out = b''
        for c in self.children:
            out += c.to_tlv()
        return out

    def from_tlv(self, do):
        return self.from_bytes(do)

    def to_tlv(self):
        return self.to_bytes()
