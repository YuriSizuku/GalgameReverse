#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""
"""

__version__ = '0.1.0'
__date__    = '2021-05-03'
__author__  = 'Robert Jordan'

__all__ = ['Field', 'Status', 'Typedef']

#######################################################################################

import abc, csv, enum, io, os, statistics, string
from collections import namedtuple, Counter, OrderedDict
from datetime import datetime
from itertools import chain
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, NoReturn, Tuple, Union

from .._util import Fore as F, Style as S
from ..flags import MjoType, MjoTypeMask, MjoScope
from ..crypt import hash32

from ..mjs.identifiers import GROUP_SYSCALL, GROUP_LOCAL, GROUP_DEFAULT, Identifier, SyscallSig, FunctionSig, VariableSig, ArgumentSig, LocalSig
from .googlesheets import GoogleSheet
# from .sheetinfo import Status, Typedef, TYPEDEFS, TYPEDEF_LOOKUP

#######################################################################################


#region ## SHEET HELPER ENUMS ##

class Field(enum.Enum):
    HASH       = 'Hash'       # hex hash value taken from the engine.
                              #  syscalls: validate with hash32(f'${name}@MAJIRO_INTER')
                              #    groups: validate with hash32(f'$main@{name}')
    ADDRESS    = 'Address'    # hex syscall function address in ClosedGAME Majiro engine (expect "inline" values)
    SOURCE     = 'Source'     # files declaring funcs/vars with group name
    INVOKED_BY = 'Invoked by' # Same as SOURCE, but for Callbacks
    SCOPE      = 'Scope'      # scope of variable (uses aliases: local, thread, save, persist)
    RETURN     = 'Return'     # return value, uses type aliases for ints when necessary (expect other names like any/void, etc.)
    TYPE       = 'Type'       # type of variable, uses type aliases for ints when necessary
    NAME       = 'Name'       # syscall name (sometimes ends with '?' for unsure names)
    GROUP      = 'Group'      # group name for Functions and Variables
    ARGUMENTS  = 'Arguments'  # function arguments, there is a syntax to these, but at the moment they're not used
    STATUS     = 'Status'     # name status, is this name confirmed to be correct? (see Status enum below)
    NOTES      = 'Notes'      # other notes, only included for unexpected or strange behavior

class Status(enum.Enum):
    NONE      = ''          # no status, not even inspected yet
    UNHASHED  = 'unhashed'  # name has been confirmed AND unhashed name matches hash value
    COLLISION = 'collision' # name is unhashed, but possibly only a collision, and not the original name
    PARTIAL   = 'partial'   # partial name has been unhashed through XOR proofs (either prefix or postfix)
    INCORRECT = 'incorrect' # guessed/likely name did not match hash value
    CONFIRMED = 'confirmed' #DEPRECATED: name is confirmed through inspection of .mjs soruce scripts
    LIKELY    = 'likely'    # name is likely, by going off of log/error messages found in asm
    GUESSED   = 'guessed'   # name is purely guessed (and may only be used to describe function)

#endregion

#region ## RETURN TYPE ALIASES ##

EMPTY:str = '-'  # used to denote field is filled in, but there is nothing to show

#void,any,any/void,int,int?,bool,file*,page*,sprite*,float,string,int[],float[],string[],

TYPEDEFS:Dict[MjoType,List[str]] = OrderedDict([
    (MjoType.UNKNOWN, ['']),
    (Ellipsis,        ['void','any','any/void']),
    (MjoType.INT,     ['int','int?','bool','file*','page*','sprite*']),
    (MjoType.FLOAT,   ['float']),
    (MjoType.STRING,  ['string']),
    (MjoType.INT_ARRAY,    ['int[]']),
    (MjoType.FLOAT_ARRAY,  ['float[]']),
    (MjoType.STRING_ARRAY, ['string[]']),
])
TYPEDEF_LOOKUP:Dict[str,MjoType] = OrderedDict(chain(*[[(k,t) for k in keys] for t,keys in TYPEDEFS.items()]))

#endregion

#######################################################################################

#region ## HELPER FUNCTIONS ##

class Typedef(enum.Enum):
    UNKNOWN  = ''         # type not documented/known
    #NONE     = ''         # alias for UNKNOWN
    
    VOID     = 'void'     # Return types only
    ANY      = 'any'
    ANY_VOID = 'any/void' # Return types only

    INT_UNK  = 'int?'     # type: int (usage unknown)
    INT      = 'int'      # type: int (usage known)
    BOOL     = 'bool'     # type: int (0 or 1)
    FILE     = 'file*'    # type: int (ptr to FILE)
    PAGE     = 'page*'    # type: int (ptr to PAGE)
    SPRITE   = 'sprite*'  # type: int (ptr to SPRITE)

    FLOAT    = 'float'
    STRING   = 'string'
    INT_ARRAY    = 'int[]'
    FLOAT_ARRAY  = 'float[]'
    STRING_ARRAY = 'string[]'

#endregion

#######################################################################################

class _ColBase(abc.ABC):
    def __init__(self, col_name:str, python_name:str=...):
        self.col_name:str = col_name
        self.python_name:str = col_name.lower() if python_name is Ellipsis else python_name
    @abc.abstractmethod
    def from_col(self, col:str) -> Any:
        raise NotImplementedError(f'{self.__class__.__name__}.from_col')
    @abc.abstractmethod
    def to_col(self, value:Any, *, preserve:bool=False) -> str:
        raise NotImplementedError(f'{self.__class__.__name__}.to_col')
    @classmethod
    def _presstr(self, preserve:bool) -> str:
        return '\''

class _RowBase:
    def __init_subclass__(cls, cols:List[_ColBase], **kwargs):
        cls.COLS = cols
    def __init__(self, *args, **kwargs):
        for col in self.COLS:
            setattr(self, col.python_name, col.from_col(''))
    @classmethod
    def is_row_empty(cls, row:OrderedDict) -> bool:
        return row and any(c.strip() for c in row.values()) # safety strip, any non-empty strings
    @classmethod
    def from_row(cls, row:OrderedDict) -> '_RowBase':
        rowcls = cls()
        for col in cls.COLS:
            setattr(rowcls, col.python_name, col.from_col(row[col.col_name].strip())) # safety strip
        return rowcls
    def to_row(self, *, preserve:bool=False) -> OrderedDict:
        odict = OrderedDict()
        for col in self.COLS:
            odict[col.col_name] = col.to_col(getattr(self, col.python_name), preserve=preserve)
        return odict
    def verify(self) -> bool:
        return True # default implementation, no verification

class _RowHashBase(_RowBase, cols=()): #TODO: better way to handle base class?
    def __init__(self, *args, **kwargs):
        self.hash:Optional[int] = 0
        self.name:Optional[str] = ''
        self.status:Status = Status.NONE
        self.notes:str = ''
        super().__init__(*args, **kwargs)
    @property
    def identifier(self) -> Identifier:
        raise NotImplementedError(f'{self.__class__.__name__}.identifier')
    @property
    def fullname(self) -> str:
        raise NotImplementedError(f'{self.__class__.__name__}.fullname')
    @property
    def confirmed(self) -> bool:
        return self.status in (Status.UNHASHED, Status.COLLISION, Status.CONFIRMED)
    @property
    def unhashed(self) -> bool: # no collisions
        return self.status in (Status.UNHASHED, Status.CONFIRMED)
    def verify(self) -> bool:
        return not self.confirmed or (hash32(self.fullname) == self.hash)

#######################################################################################

class ColHash(_ColBase):
    def from_col(self, col:str) -> Optional[int]:
        return None if not col else int(col.lstrip('\''), 16)
    def to_col(self, value:Optional[int], *, preserve:bool=False) -> str:
        return '' if value is None else f'{self._presstr(preserve)}{value:08x}' # \' to preserve numeric formatting

class ColScope(_ColBase):
    def from_col(self, col:str) -> MjoScope:
        return MjoScope.UNKNOWN if not col else MjoScope.fromname(col)
    def to_col(self, value:Typedef, *, preserve:bool=False) -> str:
        if value is MjoScope.UNKNOWN: return ''
        # full name for local (BUT THIS SHOULD'T BE PRESENT IN VARIABES TABLE)
        elif value is MjoScope.LOCAL: return MjoScope.mnemonic
        else:                         return value.alias

class ColType(_ColBase):
    def from_col(self, col:str) -> Typedef:
        return Typedef(col)
    def to_col(self, value:Typedef, *, preserve:bool=False) -> str:
        return value.value

class ColStatus(_ColBase):
    def from_col(self, col:str) -> Status:
        return Status(col)
    def to_col(self, value:Status, *, preserve:bool=False) -> str:
        return value.value

class ColAddress(_ColBase):
    def from_col(self, col:str) -> Optional[Union[int,str]]:
        if not col:        return None
        try:               return int(col.lstrip('\''), 16)
        except ValueError: return col
    def to_col(self, value:Optional[Union[int,str]], *, preserve:bool=False) -> str:
        if value is None:          return ''
        if isinstance(value, int): return f'{self._presstr(preserve)}{value:08x}'
        if isinstance(value, str): return value
        raise TypeError(value.__class__.__name__)

# class ColArgs(_ColBase):
#     def from_col(self, col:str) -> Optional[str]:
#         if not col:      return None
#         if col == EMPTY: return ''
#         else:            return col
#     def to_col(self, value:Optional[str], *, preserve:bool=False) -> str:
#         if value is None:  return ''
#         elif value == '':  return EMPTY
#         else:              return value

class ColText(_ColBase):
    def from_col(self, col:str) -> Optional[str]:
        if not col:      return None
        if col == EMPTY: return ''
        else:            return col
    def to_col(self, value:Optional[str], *, preserve:bool=False) -> str:
        if value is None:  return ''
        elif value == '':  return EMPTY
        else:              return value

class ColPrefix(ColText):
    def __init__(self, prefix:str, col_name:str, python_name:str=...):
        super().__init__(col_name, python_name)
        self.prefix = prefix
    def from_col(self, col:str) -> Optional[str]:
        col = super().from_col(col)
        if col and col.startswith(self.prefix):
            raise ValueError(f'{self.__class__.__name__}.from_col() column {self.col_name!r} must not have prefix {self.prefix!r}, got {col}')
        return f'{self.prefix}{col}' if col else col
    def to_col(self, value:Optional[str], *, preserve:bool=False) -> str:
        if value and not value[0].startswith(self.prefix):
            raise ValueError(f'{self.__class__.__name__}.to_col() value {self.col_name!r} expects prefix {self.prefix!r}, got {value}')
        return value[len(self.prefix):] if value else value

class ColDate(_ColBase):
    def from_col(self, col:str) -> Optional[datetime]:
        if not col:      return None
        else:            return datetime.strptime(col, '%Y-%m-%d')
    def to_col(self, value:datetime, *, preserve:bool=False) -> str:
        if value is None:  return ''
        else:              return value.strftime('%Y-%m-%d')

class ColDateTime(_ColBase):
    def from_col(self, col:str) -> Optional[datetime]:
        if not col:      return None
        else:            return datetime.strptime(col, '%Y-%m-%d %H:%M:%S')
    def to_col(self, value:datetime, *, preserve:bool=False) -> str:
        if value is None:  return ''
        else:              return value.strftime('%Y-%m-%d %H:%M:%S')

#######################################################################################

class RowSyscall(_RowHashBase,cols=(ColHash('Hash'), ColAddress('Address','source'), ColType('Return','type'),
                                    ColPrefix('$','Name'), ColText('Arguments'), ColStatus('Status'), ColText('Notes'))):
    __slots__ = ('hash', 'source', 'type', 'name', 'arguments', 'status', 'notes')
    def __init__(self, *args, **kwargs):
        self.hash:Optional[int] = 0
        self.source:Optional[Union[int,str]] = 0
        # self.address:Optional[int] = 0
        # self.source:Optional[str] = '' # for non-hex addresses
        self.type:Typedef = Typedef.UNKNOWN
        self.name:Optional[str] = ''
        self.arguments:Optional[str] = ''
        self.status:Status = Status.NONE
        self.notes:str = ''
        super().__init__(*args, **kwargs)
    @property
    def scope(self) -> MjoScope:
        return MjoScope.FUNCTION
    @property
    def group(self) -> str:
        return GROUP_SYSCALL
    @property
    def identifier(self) -> SyscallSig:
        return SyscallSig(self.name or '', is_void=self.type is Typedef.VOID, doc=self.notes)
    @property
    def fullname(self) -> str:
        return f'{self.name or ""}@{self.group}'

class RowFunction(_RowHashBase,cols=(ColHash('Hash'), ColText('Source'), ColType('Return','type'), ColPrefix('$','Name'),
                                     ColText('Group'), ColText('Arguments'), ColStatus('Status'), ColText('Notes'))):
    __slots__ = ('hash', 'source', 'type', 'name', 'group', 'arguments', 'status', 'notes')
    def __init__(self, *args, **kwargs):
        self.hash:Optional[int] = 0
        self.source:Optional[str] = ''
        self.type:Typedef = Typedef.UNKNOWN
        self.name:Optional[str] = ''
        self.group:Optional[str] = ''
        self.arguments:Optional[str] = ''
        self.status:Status = Status.NONE
        self.notes:str = ''
        super().__init__(*args, **kwargs)
    @property
    def scope(self) -> MjoScope:
        return MjoScope.FUNCTION
    @property
    def identifier(self) -> FunctionSig:
        return FunctionSig(self.name or '', self.arguments if self.arguments is not None else (), is_void=self.type is Typedef.VOID, group=self.group or '', doc=self.notes)
    @property
    def fullname(self) -> str:
        return f'{self.name or ""}@{self.group}'

class RowVariable(_RowHashBase,cols=(ColHash('Hash'), ColText('Source'), ColScope('Scope'), ColType('Type'),
                                     ColText('Name'), ColText('Group'), ColStatus('Status'), ColText('Notes'))):
    __slots__ = ('hash', 'source', 'scope', 'type', 'name', 'group', 'status', 'notes')
    def __init__(self, *args, **kwargs):
        self.hash:Optional[int] = 0
        self.source:Optional[str] = ''
        self.scope:MjoScope = MjoScope.UNKNOWN
        self.type:Typedef = Typedef.UNKNOWN
        self.name:Optional[str] = ''
        self.group:Optional[str] = ''
        self.status:Status = Status.NONE
        self.notes:str = ''
        super().__init__(*args, **kwargs)
    # @property
    # def group(self) -> str:
    #     return GROUP_LOCAL
    @property
    def identifier(self) -> VariableSig:
        return VariableSig(self.name or '', group=self.group or '', doc=self.notes)
    @property
    def fullname(self) -> str:
        return f'{self.name or ""}@{self.group or ""}'

class RowLocal(_RowHashBase,cols=(ColHash('Hash'), ColType('Type'), ColText('Name'),
                                  ColStatus('Status'), ColText('Notes'))):
    __slots__ = ('hash', 'type', 'name', 'status', 'notes')
    def __init__(self, *args, **kwargs):
        self.hash:Optional[int] = 0
        self.type:Typedef = Typedef.UNKNOWN
        self.name:Optional[str] = ''
        self.status:Status = Status.NONE
        self.notes:str = ''
        super().__init__(*args, **kwargs)
    @property
    def scope(self) -> MjoScope:
        return MjoScope.LOCAL
    @property
    def group(self) -> str:
        return GROUP_LOCAL
    @property
    def identifier(self) -> LocalSig:
        return LocalSig(self.name or '', doc=self.notes)
    @property
    def fullname(self) -> str:
        return f'{self.name or ""}@{self.group}'

class RowGroup(_RowHashBase,cols=(ColHash('Hash'), ColText('Source'), ColText('Name'),#, 'group'),
                                  ColStatus('Status'), ColText('Notes'))):
    __slots__ = ('hash', 'source', 'name', 'status', 'notes')
    def __init__(self, *args, **kwargs):
        self.hash:Optional[int] = 0
        self.source:Optional[str] = ''
        self.name:Optional[str] = ''
        # self.group:Optional[str] = ''
        self.status:Status = Status.NONE
        self.notes:str = ''
        super().__init__(*args, **kwargs)
    @property
    def scope(self) -> MjoScope:
        return MjoScope.FUNCTION
    @property
    def group(self) -> str:
        return self.name
    @property
    def identifier(self) -> FunctionSig:
        return FunctionSig('$main', group=self.group or '', doc=self.notes)
    @property
    def fullname(self) -> str:
        return f'$main@{self.group or ""}'

class RowCallback(_RowHashBase,cols=(ColHash('Hash'), ColText('Invoked by','source'),
                                     ColText('Name'), ColStatus('Status'), ColText('Notes'))):
    __slots__ = ('hash', 'source', 'name', 'status', 'notes')
    def __init__(self, *args, **kwargs):
        self.hash:Optional[int] = 0
        self.source:Optional[str] = ''
        self.name:Optional[str] = ''
        self.status:Status = Status.NONE
        self.notes:str = ''
        super().__init__(*args, **kwargs)
    @property
    def scope(self) -> MjoScope:
        return MjoScope.UNKNOWN
    @property
    def identifier(self) -> Identifier:
        return Identifier(self.name or '', doc=self.notes)
    @property
    def fullname(self) -> str:
        return self.name or ''

_DATE_HINT_ = datetime.utcnow() # used for pylint type hinting in __init__ for RowGame

class RowGame(_RowBase,cols=(ColDate('Release'), ColText('Developer'), ColText('Name'),
                             ColDateTime('Engine Build Date','build'), ColText('Notes'))):
    __slots__ = ('release', 'developer', 'name', 'build', 'notes')
    def __init__(self, *args, **kwargs):
        self.release:Optional[datetime] = _DATE_HINT_
        self.developer:Optional[str] = ''
        self.name:Optional[str] = ''
        self.build:Optional[datetime] = _DATE_HINT_
        self.notes:str = ''
        super().__init__(*args, **kwargs)
