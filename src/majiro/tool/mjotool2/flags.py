#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script opcode flags and enums (mostly for variables)
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'
__credits__ = '''Based off Meta Language implementation by Haeleth - 2005
Converted to Python script with extended syntax by Robert Jordan - 2021
'''

__all__ = ['MjoType', 'MjoScope', 'MjoInvert', 'MjoModifier', 'MjoDimension', 'MjoFlags']

#######################################################################################

import enum
from collections import OrderedDict
from itertools import chain
from typing import Dict, Optional, Union

#region ## MAJIRO FLAGS ##

#NOTE: The #MjIL assembler language names and properties# are the most unpythonic thing I've ever seen... but it is Pythonic?
#      all flag MjIL names are defined in ## FLAG NAME DICTIONARIES ##
#      and flag functions are defined in ## FLAG NAME FUNCTIONS ##

class MjoType(enum.IntEnum):
    """Type (variable) flags for ld*, ldelem*, st*, and stelem* opcodes (same as internal IDs)
    """
    UNKNOWN      = -1 # ('?' postfix used internally to specify the name is unknown)
    #
    INT          = 0  #   '' postfix (int,         [i])  (also used for handles/function pointers)
    FLOAT        = 1  #  '%' postfix (float,       [r])  (observed as '!' for syscall: $46b18379 "$rand!@MAJIRO_INTER")
    STRING       = 2  #  '$' postfix (string,      [s])
    INT_ARRAY    = 3  #  '#' postfix (intarray,    [iarr])
    FLOAT_ARRAY  = 4  # '%#' postfix (floatarray,  [rarr])
    STRING_ARRAY = 5  # '$#' postfix (stringarray, [sarr])
    #
    #NOTE: WHAT THE HELL!??  (also possibly "any")
    INTERNAL     = 8  #  '~' postfix (observed for var: $11f91fd3 "%Op_internalCase~@MAJIRO_INTER", may be a collision)
    #                 #              (it's possible this is actually a post-postfix used to keep things internal, or it prevents access by MajiroCompile.exe)
    #
    def __bool__(self) -> bool: return self is not MjoType.UNKNOWN
    #
    #region # MjIL assembler language names and properties:
    @property
    def mnemonic(self) -> Optional[str]:                  return _flagname(self)
    @property
    def alias(self)    -> Optional[str]:                  return _flagname(self, True)
    #
    def getname(self, alias:bool=False) -> Optional[str]: return _flagname(self, alias)
    @classmethod
    def fromname(cls, name:str, default=...) -> 'MjoType': return _fromflagname(cls, name, default)
    #
    @property
    def postfix(self) -> str:
        if self is MjoType.INTERNAL:
            return self._POSTFIXES_ALT[self]  # INTERNAL only has an alt type since we still don't really understand it
        return self._POSTFIXES[self]
    @classmethod
    def frompostfix(cls, postfix:str, default=..., *, allow_unk:bool=False, allow_alt:bool=False) -> 'MjoType':
        if not allow_unk and postfix == MjoType.UNKNOWN.postfix:
            if default is not Ellipsis:
                return default
            raise KeyError(postfix)
        name = None
        if allow_alt:
            name = cls._POSTFIX_ALT_LOOKUP.get(postfix)
        # do name checks here to "cleanly" handle default values
        if default is not Ellipsis:
            return name if name is not None else cls._POSTFIX_LOOKUP.get(postfix, default)
        else:
            return name if name is not None else cls._POSTFIX_LOOKUP[postfix]
    @classmethod
    def frompostfix_name(cls, name:str, default=..., *, allow_unk:bool=False, allow_alt:bool=False) -> 'MjoType':
        postfix = cls.getpostfix_fromname(name)
        return cls.frompostfix(postfix, default, allow_unk=allow_unk, allow_alt=allow_alt)
    @classmethod
    def getpostfix_fromname(cls, name:str) -> str:
        # from name lookup behavior has to be hardcoded :(
        # trim group name, if included
        #NOTE: realistically identifiers should have at least two chars before group
        at_idx = name.find('@', 1)
        if at_idx != -1: name = name[:at_idx]
        # keep consistent parsing with '' postfix (which doesn't care if there's no room for an actual name)
        postfix = '' if len(name) > 0 else None
        for i in range(len(name) - 1, -1, -1): # (i=len(name)-1; i >= 0; i--)
            # consume as many postfix characters as possible to check invalid character usage
            #                            normal        doc   MAJIRO_INTER
            if i == 0 or name[i] not in ('%','$','#',  '?',  '!','~'): #cls._POSTFIX_LOOKUP:
                postfix = name[i+1:]
                break
        return postfix
    #
    @property
    def python_type(self) -> type: return self._PYTHON_TYPES[self]
    @property
    def is_native(self) -> bool: return (MjoType.INT <= self <= MjoType.FLOAT)
    @property
    def is_reference(self) -> bool: return (MjoType.STRING <= self <= MjoType.STRING_ARRAY)
    @property
    def is_primitive(self) -> bool: return (MjoType.INT <= self <= MjoType.STRING)
    @property
    def is_array(self) -> bool: return (MjoType.INT_ARRAY <= self <= MjoType.STRING_ARRAY)
    @property
    def element(self) -> 'MjoType':
        return MjoType(self.value & 0x3) if self.is_array else self
    @property
    def array(self) -> 'MjoType':
        if self is MjoType.UNKNOWN:
            return None
        return MjoType(self.value | 0x4) if self.is_primitive else self
    #endregion

class MjoTypeMask(enum.IntFlag):
    """Mask for MjoType used exclusively during Opcodes definitions
    """
    VOID         = 0
    #
    INT          = 1 << MjoType.INT.value
    FLOAT        = 1 << MjoType.FLOAT.value
    STRING       = 1 << MjoType.STRING.value
    INT_ARRAY    = 1 << MjoType.INT_ARRAY.value
    FLOAT_ARRAY  = 1 << MjoType.FLOAT_ARRAY.value
    STRING_ARRAY = 1 << MjoType.STRING_ARRAY.value
    # combinations:
    NUMERIC   = INT | FLOAT
    PRIMITIVE = INT | FLOAT | STRING
    ARRAY     = INT_ARRAY | FLOAT_ARRAY | STRING_ARRAY
    ALL       = INT | FLOAT | STRING | INT_ARRAY | FLOAT_ARRAY | STRING_ARRAY


class MjoScope(enum.IntEnum):
    """Scope (location) flags for ld*, ldelem*, st*, and stelem* opcodes
    """
    UNKNOWN    = -1
    #
    PERSISTENT = 0  # '#' prefix (persistent, [persist])
    SAVEFILE   = 1  # '@' prefix (savefile,   [save])
    THREAD     = 2  # '%' prefix (thread)
    LOCAL      = 3  # '_' prefix (local,      [loc])
    #NOTE: not a real scope flag <INTERNAL USE ONLY>
    FUNCTION   = 8  # '$' prefix (func,       [void])
    #
    def __bool__(self) -> bool: return self is not MjoScope.UNKNOWN
    #
    #region # MjIL assembler language names and properties:
    @property
    def mnemonic(self) -> Optional[str]:                  return _flagname(self)
    @property
    def alias(self)    -> Optional[str]:                  return _flagname(self, True)
    #
    def getname(self, alias:bool=False) -> Optional[str]: return _flagname(self, alias)
    @classmethod
    def fromname(cls, name:str, default=...) -> 'MjoScope': return _fromflagname(cls, name, default)
    #
    @property
    def prefix(self) -> str: return self._PREFIXES[self]
    @classmethod
    def fromprefix(cls, prefix:str, default=..., allow_unk:bool=False) -> 'MjoScope':
        if not allow_unk and prefix == MjoScope.UNKNOWN.prefix:
            if default is not Ellipsis:
                return default
            raise KeyError(prefix)
        if default is not Ellipsis:
            return cls._PREFIX_LOOKUP.get(prefix, default)
        return cls._PREFIX_LOOKUP[prefix]
    @classmethod
    def fromprefix_name(cls, name:str, default=..., allow_unk:bool=False) -> 'MjoScope':
        if allow_unk and name[:1] not in cls._PREFIX_LOOKUP:
            name = ''
        return cls.fromprefix(name[:1], default, allow_unk=allow_unk)
    #
    @property
    def is_var(self) -> bool: return (MjoScope.PERSISTENT <= self <= MjoScope.LOCAL)
    @property
    def is_func(self) -> bool: return (self is MjoScope.FUNCTION)
    #endregion


class MjoInvert(enum.IntEnum):
    """Invert (-/!/~) flags for ld* and ldelem* opcodes
    """
    NONE    = 0
    NUMERIC = 1  # -x (neg)
    BOOLEAN = 2  # !x (notl)
    BITWISE = 3  # ~x (not)
    #
    #region # MjIL assembler language names and properties:
    @property
    def mnemonic(self) -> Optional[str]:                  return _flagname(self)
    @property
    def alias(self)    -> Optional[str]:                  return _flagname(self, True)
    #
    def getname(self, alias:bool=False) -> Optional[str]: return _flagname(self, alias)
    @classmethod
    def fromname(cls, name:str, default=...) -> 'MjoInvert': return _fromflagname(cls, name, default)
    #
    @property
    def operator(self) -> str: return self._OPERATORS[self]
    #
    @property
    def supports(self) -> MjoTypeMask:
        if self is MjoInvert.NONE:
            return MjoTypeMask.ALL
        return MjoTypeMask.NUMERIC if (self is MjoInvert.NUMERIC) else MjoTypeMask.INT
    #endregion


class MjoModifier(enum.IntEnum):
    """Modifier (++/--) flags for ld* and ldelem* opcodes
    """
    NONE          = 0
    PREINCREMENT  = 1  # ++x (preinc,  [inc.x])
    PREDECREMENT  = 2  # --x (predec,  [dec.x])
    POSTINCREMENT = 3  # x++ (postinc, [x.inc])
    POSTDECREMENT = 4  # x-- (postdec, [x.dec])
    #
    #region # MjIL assembler language names and properties:
    @property
    def mnemonic(self) -> Optional[str]:                  return _flagname(self)
    @property
    def alias(self)    -> Optional[str]:                  return _flagname(self, True)
    #
    def getname(self, alias:bool=False) -> Optional[str]: return _flagname(self, alias)
    @classmethod
    def fromname(cls, name:str, default=...) -> 'MjoModifier': return _fromflagname(cls, name, default)
    #
    @property
    def operator(self) -> str: return self._OPERATORS[self]
    @property
    def is_pre(self) -> bool: return (MjoModifier.PREINCREMENT <= self <= MjoModifier.PREDECREMENT)
    @property
    def is_post(self) -> bool: return (MjoModifier.POSTINCREMENT <= self <= MjoModifier.POSTDECREMENT)
    #
    @property
    def supports(self) -> MjoTypeMask:
        return MjoTypeMask.ALL if (self is MjoModifier.NONE) else MjoTypeMask.INT
    #endregion


class MjoDimension(enum.IntEnum):
    """Dimension [,,] flags for ldelem* and stelem* opcodes
    """
    NONE          = 0  # [dim0]
    DIMENSION_1   = 1  # (dim1)
    DIMENSION_2   = 2  # (dim2)
    DIMENSION_3   = 3  # (dim3)
    #
    #region # MjIL assembler language names and properties:
    @property
    def mnemonic(self) -> Optional[str]:                  return _flagname(self)
    @property
    def alias(self)    -> Optional[str]:                  return _flagname(self, True)
    #
    def getname(self, alias:bool=False) -> Optional[str]: return _flagname(self, alias)
    @classmethod
    def fromname(cls, name:str, default=...) -> 'MjoDimension': return _fromflagname(cls, name, default)
    #
    @property
    def supports(self) -> MjoTypeMask:
        return MjoTypeMask.ALL if (self is MjoDimension.NONE) else MjoTypeMask.ARRAY
    #endregion

#endregion

#region ## MAJIRO FLAGS INT WRAPPER ##

class MjoFlags(int):
    """immutable int wrapper with accessor properties for Majiro variable bitmask flags
    """
    # Dim      = 0b00011000_00000000,
    # Type     = 0b00000111_00000000,
    # Scope    = 0b00000000_11100000,
    # Invert   = 0b00000000_00011000,
    # Modifier = 0b00000000_00000111,
    def __new__(cls, *args, **kwargs):
        return  super().__new__(cls, *args, **kwargs)
    @classmethod
    def fromflags(cls, scope:MjoScope, type:MjoType, dimension:int=0, modifier:MjoModifier=MjoModifier.NONE, invert:MjoInvert=MjoInvert.NONE) -> 'MjoFlags':
        """Return a new MjoFlags object with the specified bitmask flags
        """
        flags = 0
        flags |= ((modifier.value & 0x7))#<< 0)
        flags |= ((invert.value   & 0x3) <<  3)
        flags |= ((scope.value    & 0x7) <<  5)
        flags |= ((type.value     & 0x7) <<  8)
        #FIXME: Stop handling MjoDimension as int entirely??
        flags |= ((int(dimension) & 0x3) << 11)
        return cls(flags)
    def _replace(self, scope:MjoScope=..., type:MjoType=..., dimension:MjoDimension=..., modifier:MjoModifier=..., invert:MjoInvert=...) -> 'MjoFlags':
        """Return a new MjoFlags object replacing specified bitmask flags with new values
        """
        if scope     is Ellipsis: scope     = self.scope
        if type      is Ellipsis: type      = self.type
        if dimension is Ellipsis: dimension = self.dimension
        if modifier  is Ellipsis: modifier  = self.modifier
        if invert    is Ellipsis: invert    = self.invert
        return self.fromflags(scope=scope, type=type, dimension=dimension, modifier=modifier, invert=invert)
    @property
    def modifier(self) -> MjoModifier:
        return MjoModifier(self & 0x7)
    @property
    def invert(self) -> MjoInvert:
        return MjoInvert((self >> 3) & 0x3)
    @property
    def scope(self) -> MjoScope:
        return MjoScope((self >> 5) & 0x7)
    @property
    def type(self) -> MjoType:
        return MjoType((self >> 8) & 0x7)
    @property
    def dimension(self) -> MjoDimension:
        return MjoDimension((self >> 11) & 0x3)

#endregion

#region ## FLAG NAME DICTIONARIES ##

#TODO: is there really any need to be using OrderedDict's here?

# MjoType:
MjoType._NAMES:Dict[MjoType,str] = OrderedDict({
    MjoType.INT:          'int',
    MjoType.FLOAT:        'float',
    MjoType.STRING:       'string',
    MjoType.INT_ARRAY:    'intarray',
    MjoType.FLOAT_ARRAY:  'floatarray',
    MjoType.STRING_ARRAY: 'stringarray',
})
MjoType._ALIASES:Dict[MjoType,str] = OrderedDict({
    MjoType.INT:          'i',
    MjoType.FLOAT:        'r',
    MjoType.STRING:       's',
    MjoType.INT_ARRAY:    'iarr',
    MjoType.FLOAT_ARRAY:  'rarr',
    MjoType.STRING_ARRAY: 'sarr',
})
MjoType._LOOKUP:Dict[str,MjoType] = OrderedDict((v,k) for k,v in chain(MjoType._NAMES.items(), MjoType._ALIASES.items()))

MjoType._POSTFIXES:Dict[MjoType,str] = OrderedDict({
    #NOTE: not a real type flag <INTERNAL USE ONLY>
    MjoType.UNKNOWN:      '?',
    #
    MjoType.INT:          '',
    MjoType.FLOAT:        '%',
    MjoType.STRING:       '$',
    MjoType.INT_ARRAY:    '#',
    MjoType.FLOAT_ARRAY:  '%#',
    MjoType.STRING_ARRAY: '$#',
})
MjoType._POSTFIXES_ALT:Dict[MjoType,str] = OrderedDict({
    #NOTE: WHAT THE HELL!??
    #      observed for syscall: $46b18379 "$rand!@MAJIRO_INTER", which returns a float between 0 and 1 (DOUBLE??)
    MjoType.FLOAT:        '!',
    #MjoType.FLOAT_ARRAY:  '!#',
    #
    #NOTE: WHAT THE HELL!??
    #      observed for var: $11f91fd3 "%Op_internalCase~@MAJIRO_INTER", may be a collision.
    #      it's possible this is actually a post-postfix used to keep things internal, or it prevents access by MajiroCompile.exe.
    MjoType.INTERNAL:     '~',
})
MjoType._POSTFIX_LOOKUP:Dict[str,MjoType] = OrderedDict((v,k) for k,v in MjoType._POSTFIXES.items())
MjoType._POSTFIX_ALT_LOOKUP:Dict[str,MjoType] = OrderedDict((v,k) for k,v in MjoType._POSTFIXES_ALT.items())

MjoType._PYTHON_TYPES:Dict[MjoType,type] = OrderedDict({
    #NOTE: not a real type flag <INTERNAL USE ONLY>
    MjoType.UNKNOWN:      object,  # any type
    #
    MjoType.INT:          int,
    MjoType.FLOAT:        float,
    MjoType.STRING:       str,
    MjoType.INT_ARRAY:    list,
    MjoType.FLOAT_ARRAY:  list,
    MjoType.STRING_ARRAY: list,
})

# MjoScope:
MjoScope._NAMES:Dict[MjoScope,str] = OrderedDict({
    MjoScope.PERSISTENT: 'persistent',
    MjoScope.SAVEFILE:   'savefile',
    MjoScope.THREAD:     'thread',
    MjoScope.LOCAL:      'local',
    #NOTE: not a real scope flag <INTERNAL USE ONLY, EXCLUDED FROM _LOOKUP>
    MjoScope.FUNCTION:   'func',
})
MjoScope._ALIASES:Dict[MjoScope,str] = OrderedDict({
    MjoScope.PERSISTENT: 'persist',
    MjoScope.SAVEFILE:   'save',
    # (no thread alias, already short enough for its infrequent usage)
    MjoScope.LOCAL:      'loc',
})
MjoScope._LOOKUP:Dict[str,MjoScope] = OrderedDict((v,k) for k,v in chain(MjoScope._NAMES.items(), MjoScope._ALIASES.items()) if k is not MjoScope.FUNCTION)

MjoScope._PREFIXES:Dict[MjoScope,str] = OrderedDict({
    #NOTE: not a real scope flag <INTERNAL USE ONLY>
    MjoScope.UNKNOWN:    '',
    #
    MjoScope.PERSISTENT: '#',
    MjoScope.SAVEFILE:   '@',
    MjoScope.THREAD:     '%',
    MjoScope.LOCAL:      '_',
    #NOTE: not a real scope flag <INTERNAL USE ONLY>
    MjoScope.FUNCTION:   '$',
})
MjoScope._PREFIX_LOOKUP:Dict[str,MjoScope] = OrderedDict((v,k) for k,v in MjoScope._PREFIXES.items())

# MjoInvert:
MjoInvert._NAMES:Dict[MjoInvert,str] = OrderedDict({
    #NOTE: these names will conflict with "notl" and "not" opcode mnemonics, be prepared when parsing MjIL
    MjoInvert.NUMERIC: 'neg',
    MjoInvert.BOOLEAN: 'notl',
    MjoInvert.BITWISE: 'not',
})
MjoInvert._LOOKUP:Dict[str,MjoInvert] = OrderedDict((v,k) for k,v in MjoInvert._NAMES.items())

MjoInvert._OPERATORS:Dict[MjoInvert,str] = OrderedDict({
    MjoInvert.NONE:    None,
    MjoInvert.NUMERIC: '-',
    MjoInvert.BOOLEAN: '!',
    MjoInvert.BITWISE: '~',
})

# MjoModifier:
MjoModifier._NAMES:Dict[MjoModifier,str] = OrderedDict({
    MjoModifier.PREINCREMENT:  'preinc',
    MjoModifier.PREDECREMENT:  'predec',
    MjoModifier.POSTINCREMENT: 'postinc',
    MjoModifier.POSTDECREMENT: 'postdec',
})
MjoModifier._ALIASES:Dict[MjoModifier,str] = OrderedDict({
    MjoModifier.PREINCREMENT:  'inc.x',
    MjoModifier.PREDECREMENT:  'dec.x',
    MjoModifier.POSTINCREMENT: 'x.inc',
    MjoModifier.POSTDECREMENT: 'x.dec',
})
MjoModifier._LOOKUP:Dict[str,MjoModifier] = OrderedDict((v,k) for k,v in chain(MjoModifier._NAMES.items(), MjoModifier._ALIASES.items()))

MjoModifier._OPERATORS:Dict[MjoModifier,str] = OrderedDict({
    MjoModifier.NONE:          None,
    MjoModifier.PREINCREMENT:  '++',
    MjoModifier.PREDECREMENT:  '--',
    MjoModifier.POSTINCREMENT: '++',
    MjoModifier.POSTDECREMENT: '--',
})

# MjoDimension:
MjoDimension._NAMES:Dict[MjoDimension,str] = OrderedDict({
    #MjoDimension.NONE:        'dim0', # useless alias, not required
    MjoDimension.DIMENSION_1: 'dim1',
    MjoDimension.DIMENSION_2: 'dim2',
    MjoDimension.DIMENSION_3: 'dim3',
})
MjoDimension._ALIASES:Dict[MjoDimension,str] = OrderedDict({
    MjoDimension.NONE:        'dim0', # useless alias, not required
})
MjoDimension._LOOKUP:Dict[str,MjoDimension] = OrderedDict((v,k) for k,v in chain(MjoDimension._NAMES.items(), MjoDimension._ALIASES.items()))

#endregion

#region ## FLAG NAME FUNCTIONS ##

def _flagname(flag:Union[MjoScope,MjoType,MjoModifier,MjoInvert,MjoDimension,int], alias:bool=False) -> Optional[str]:
    """Return the name or alias/mnemonic for the given Majiro bitmask flag

    returns `None` for *.NONE flags, unless there is an alias and `alias` is True (MjoDimension only)
    """
    name = None
    #FIXME: Stop handling MjoDimension as int entirely??
    if not isinstance(flag, enum.Enum) and isinstance(flag, int):
        flag = MjoDimension(flag)
    if isinstance(flag, (MjoScope, MjoType, MjoModifier, MjoInvert, MjoDimension)):
        name = None
        if alias and hasattr(flag.__class__, '_ALIASES'):
            name = flag.__class__._ALIASES.get(flag) # optional alias
        if not flag:
            return name or flag.__class__._NAMES.get(flag) # return None for flags with NONE value
        else:
            return name or flag.__class__._NAMES[flag] # requried lookup
    else:
        raise TypeError(f'argument must be Mjo-Scope/Type/Modifier/Invert/Dimension or int object, not {flag.__class__.__name__}')

def _fromflagname(cls, name:str, default=...) -> enum.Enum:
    """Returns the flag enum from the the specified name
    
    when `default` argument is defined:
        returns `default` on invalid name
    otherwise:
        raises `KeyError` on invalid name
    """
    if default is not Ellipsis:
        return cls._LOOKUP.get(name, default)
    return cls._LOOKUP[name]

#endregion

# print('MjoDimension._NAMES   :', ', '.join(MjoDimension._NAMES.values()))
# print('MjoDimension._ALIASES :', ', '.join(MjoDimension._ALIASES.values()))
# print('MjoType._NAMES        :', ', '.join(MjoType._NAMES.values()))
# print('MjoType._ALIASES      :', ', '.join(MjoType._ALIASES.values()))
# print('MjoScope._NAMES       :', ', '.join(MjoScope._NAMES.values()))
# print('MjoScope._ALIASES     :', ', '.join(MjoScope._ALIASES.values()))
# print('MjoModifier._NAMES    :', ', '.join(MjoModifier._NAMES.values()))
# print('MjoModifier._ALIASES  :', ', '.join(MjoModifier._ALIASES.values()))
# print('MjoInvert._NAMES      :', ', '.join(MjoInvert._NAMES.values()))


del chain, OrderedDict, Dict, Optional, Union  # cleanup declaration-only imports
