#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script identifier signatures
"""

__version__ = '0.1.0'
__date__    = '2021-05-03'
__author__  = 'Robert Jordan'

__all__ = ['GROUP_SYSCALL', 'GROUP_DEFAULT', 'GROUP_LOCAL', 'Identifier', 'VariableSig', 'LocalSig', 'ArgumentSig', 'FunctionSig', 'SyscallSig']#, 'FunctionReturn'

#######################################################################################

## the code in this file is not fit for humans. or robots. or anyone. ##
## viewer discretion is advised, please look away                     ##

#######################################################################################

import enum, re
# from collections import namedtuple, OrderedDict
from typing import List, Optional, Pattern, Tuple, Union

from ..crypt import hash32
from ..flags import MjoType, MjoFlags, MjoScope


#######################################################################################

GROUP_SYSCALL:str = 'MAJIRO_INTER'
GROUP_DEFAULT:str = 'GLOBAL'
GROUP_LOCAL:str   = ''

# # this'll probably be removed at some point... like right now
# class FunctionReturn(enum.IntEnum):
#     UNKNOWN = -1
#     VOID = enum.auto()
#     FUNC = enum.auto()

#######################################################################################

class Identifier:
    """Identifier(name:str, *, group:str=None, doc:str=None)

    if name contains a '@' after the first character, group will be ignored
    """
    __slots__ = ('name', 'group', 'scope', 'type', 'doc')
    # group will be resolved from name if found
    def __init__(self, name:str, *, group:str=None, doc:str=None):
        self.name:str = name
        self.group:str = group
        self.scope:MjoScope = MjoScope.UNKNOWN
        self.type:MjoType = MjoType.UNKNOWN
        self.doc:str = doc

        if group and group[0] == '@':
            raise ValueError(f'group must not contain \'@\' prefix, got {group}')

        # realistically identifiers should have at least two chars before group
        at_idx = name.find('@', 1)
        if at_idx != -1: # group override from default
            self.group = name[at_idx+1:]
            self.name  = name[:at_idx]

        # get scope / function:
        self.scope = MjoScope.fromprefix_name(self.name, allow_unk=True)
        # get type / return type:
        self.type = MjoType.frompostfix_name(self.name, allow_unk=True, allow_alt=True)

    @property
    def fullname(self) -> str:
        return self.name if self.group is None else f'{self.name}@{self.group}'
    @property
    def prefix(self) -> str:
        return self.scope.prefix
    @property
    def postfix(self) -> str:
        # dumb hack to handle '!' float alias postfix
        return self.name[-len(self.type.postfix):]  # return self.type.postfix
    @property
    def basename(self) -> str:
        return self.name[len(self.scope.prefix):-len(self.type.postfix)]
    @property
    def basename_noscope(self) -> str:
        return self.name[len(self.scope.prefix):]
    @property
    def basename_notype(self) -> str:
        return self.name[:-len(self.type.postfix)]
    @property
    def is_func(self) -> bool:
        return self.scope.is_func #(self.scope is MjoScope.FUNCTION)
    @property
    def is_var(self) -> bool:
        return self.scope.is_var #(MjoScope.PERSISTENT <= self.scope <= MjoScope.LOCAL)
    @property
    def is_array(self) -> bool:
        return self.type.is_array #(MjoType.INT_ARRAY <= self.type <= MjoType.STRING_ARRAY)
    @property
    def hash(self) -> int:
        return hash32(self.fullname)
    @property
    def hashstr(self) -> str:
        return f'${self.hash:08x}'
    @property
    def definition_keyword(self) -> str:
        return ''

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.fullname!r})'
    def __str__(self) -> str:
        return self.fullname

#######################################################################################

class VariableSig(Identifier):
    __slots__ = Identifier.__slots__
    def __init__(self, name:str, *, group:str=None, doc:str=None):
        super().__init__(name, group=group, doc=doc)

    @property
    def definition_keyword(self) -> str:
        return 'var'
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.fullname!r})'
    def __str__(self) -> str:
        return f'{self.definition_keyword} {self.fullname}'

class LocalSig(VariableSig):
    __slots__ = VariableSig.__slots__
    def __init__(self, name:str, *, doc:str=None):
        super().__init__(name, group=GROUP_LOCAL, doc=doc) # local group
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.fullname!r})'
    def __str__(self) -> str:
        return f'{self.definition_keyword} {self.name}'

#######################################################################################

class ArgumentSig(LocalSig):
    __slots__ = LocalSig.__slots__ + ('optional', 'variadic', 'default', 'tuple_last')
    def __init__(self, name:str, *, optional:bool=False, variadic:bool=False, default:str=None, tuple_last:bool=False, doc:str=None):
        super().__init__(name, doc=doc) # local group
        self.optional:bool = optional
        self.variadic:bool = variadic
        self.default:str = default
        self.tuple_last:bool = tuple_last
    @property
    def definition_keyword(self) -> str:
        return ''  # set back to empty
    @property
    def is_optional(self) -> bool: # alias to conform with naming
        return self.optional
    @property
    def is_variadic(self) -> bool: # alias to conform with naming
        return self.variadic
    @property
    def is_tuple_last(self) -> bool: # alias to conform with naming
        return self.tuple_last
    @property
    def has_default(self) -> bool:
        return self.default is not None
    @property
    def default_repr(self) -> str:
        return '' if self.default is None else f' = {self.default}'
    @property
    def va_name(self) -> str:
        return f'...{self.name}' if self.variadic else self.name
    @property
    def default_name(self) -> str:
        return self.name if self.default is None else f'{self.name} = {self.default}'
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.fullname!r}, optional={self.optional!r}, variadic={self.variadic!r}, default={self.default!r}, tuple_last={self.tuple_last!r})'
    def __str__(self) -> str:
        return f'[{self.va_name}]' if self.is_optional else self.va_name



class FunctionSig(Identifier):
    __slots__ = Identifier.__slots__ + ('is_void', '_arguments')
    _RE_EOL         = re.compile(r"^(\s*)$")
    _RE_WHITESPACE  = re.compile(r"^(\s+)")
    _RE_VARIADIC    = re.compile(r"^(\.\.\.)")
    _RE_PUNCTUATION = re.compile(r"^([(){}\[\],])")
    _RE_DEFAULT     = re.compile(r"^=\s*(\"(?:\\.|[^\"])*\"|[_@#$%!?~.\-+'A-Za-z_0-9]+\*?(?:\([^)]*\))?)")
    _RE_ARGUMENT    = re.compile(r"^([_@#$%!?~A-Za-z_][_@#$%!?~A-Za-z_0-9]*\*?)")
    _RE_SET = ( _RE_EOL,
                _RE_WHITESPACE,
                _RE_VARIADIC,
                _RE_PUNCTUATION,
                _RE_DEFAULT,
                _RE_ARGUMENT )
    _ARG_TYPE = ArgumentSig

    def __init__(self, name:str, arguments:Union[List[ArgumentSig],str]=(), *, is_void:Optional[bool]=None, group:str=None, doc:str=None):
        super().__init__(name, group=group, doc=doc)
        self.is_void:Optional[bool] = is_void
        self._arguments:Union[List[ArgumentSig],str] = []
        if arguments is None:
            pass
        elif isinstance(arguments, str):
            self._arguments = arguments  # lazy parsing once requested
        else:
            self._arguments = list(arguments)

    @property
    def arguments(self) -> List[ArgumentSig]:
        # handle lazy exanding (parsing) of arguments
        if self._arguments is None:
            return None
        elif isinstance(self._arguments, str):
            self._arguments = self.parse_arguments(self._arguments)
            return 
        else:
            return self._arguments

    def add_argument(self, arg:Union[str,ArgumentSig], *, optional:bool=..., variadic:bool=..., default:str=..., doc:str=...):
        if isinstance(arg, self._ARG_TYPE):
            if optional is Ellipsis: optional = arg.is_optional
            if variadic is Ellipsis: variadic = arg.is_variadic
            if default is Ellipsis:  default = arg.default
            if doc is Ellipsis:      doc = arg.doc
        else:
            if optional is Ellipsis:
                optional = self._arguments[-1].is_optional if self._arguments else False
            if variadic is Ellipsis:
                variadic = self._arguments[-1].is_variadic if self._arguments else False
            if default is Ellipsis:  default = None
            if doc is Ellipsis:      doc = None

        if isinstance(arg, Identifier):
            self._arguments.append(self._ARG_TYPE(arg.name, optional=optional, variadic=variadic, default=default, doc=doc))
        else:
            self._arguments.append(self._ARG_TYPE(arg, optional=optional, variadic=variadic, default=default, doc=doc))
    def end_argument_tuple(self):
        if self._arguments:
            self._arguments[-1].tuple_last = True

    # @property
    # def return_type(self) -> FunctionReturn:
    #     if self.is_void is None:
    #         return FunctionReturn.UNKNOWN
    #     return FunctionReturn.FUNC if self.is_void else FunctionReturn.VOID
    @property
    def has_optionals(self) -> bool:
        if self._arguments is None: return None
        any(a.is_optional for a in self.arguments)  # expand lazy arguments
    @property
    def has_variadics(self) -> bool:
        if self._arguments is None: return None
        any(a.is_variadic for a in self.arguments)  # expand lazy arguments
    @property
    def has_defaults(self) -> bool:
        if self._arguments is None: return None
        any(a.has_default for a in self.arguments)  # expand lazy arguments
    @property
    def has_arguments(self) -> bool:
        if self._arguments is None:
            return None
        elif isinstance(self._arguments, str):
            if self._arguments.strip().startswith('?'):
                return None  # unknown
            return self._arguments.strip() not in ('', 'void')
        else:
            return bool(self._arguments)
    @property
    def definition_keyword(self) -> str:
        # only use void when confirmed(?)
        return 'void' if self.is_void is False else 'func'

    @property
    def args_str(self) -> str:
        if self._arguments is None:
            return '???'
        if isinstance(self._arguments, str):
            return self._arguments
        if not self._arguments:
            return 'void'
        arg_spans:List[Tuple[bool, str, list]] = []  # optional, variadic ('...' or ''), *args:List[str]
        optional = self._arguments[0].is_optional
        variadic = self._arguments[0].is_variadic
        arg_spans.append( (optional, '...' if variadic else '', []) )
        last_arg = None
        for arg in self._arguments:
            if (last_arg and getattr(last_arg, 'tuple_last', False)) or arg.is_optional != optional or arg.is_variadic != variadic:
                arg_spans.append( (arg.is_optional, '...' if arg.is_variadic else '', []) )
                optional = arg.is_optional
                variadic = arg.is_variadic
            arg_spans[-1][-1].append(getattr(arg, 'default_name', arg.name))
            last_arg = arg
        return ', '.join(('[{}{}]' if opt else '{}{}').format(var, ', '.join(args)) for opt,var,args in arg_spans)

    @property
    def args_repr(self) -> str:
        if self._arguments is None:
            return None
        elif isinstance(self._arguments, str):
            return self._arguments
        else:
            return self.args_str

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.fullname!r}, {self.args_repr!r}, is_void={self.is_void!r})'
    def __str__(self) -> str:
        return f'{self.definition_keyword} {self.fullname}({self.args_str})'

    def parse_arguments(self, text:str) -> List[ArgumentSig]:
        self._arguments = []
        if text is None or text.strip() in ('', 'void'):
            return  # no arguments :)

        last_s:str = None
        last_p:Pattern = None
        optional      = variadic      = False
        next_optional = next_variadic = False
        next_arg      = next_default  = None

        def commit_arg():
            self.add_argument(next_arg, optional=next_optional, variadic=next_variadic, default=next_default)
            if not optional:
                self.end_argument_tuple()

        eol:bool = False
        pos:int = 0
        while not eol:
            m = None
            for p in self._RE_SET:
                m = p.search(text[pos:])
                if not m:
                    continue
                s = m[1]
                if p is self._RE_EOL:
                    pos += m.end()
                    if last_s is not None and last_s in (',', '...', '['):
                        raise ValueError(f'Unexpected <EOL> after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
                    elif optional:
                        raise ValueError(f'Unexpected unclosing optional \'[\' in function arguments {text!r} at char {(pos+2)}')
                    eol = True
                    variadic = False
                    #region ## COMMIT ARG ##
                    if last_p in (self._RE_ARGUMENT, self._RE_DEFAULT):
                        commit_arg()
                        next_optional = next_variadic = False
                        next_arg = next_default = None
                    #endregion
                    break
                elif p is self._RE_WHITESPACE:
                    pos += m.end() # completely ignore
                    break
                elif p is self._RE_ARGUMENT:
                    if last_s is not None and last_s not in (',', '[', '...'):
                        raise ValueError(f'Unexpected argument {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
                    next_arg = s
                    next_optional = optional
                    next_variadic = next_variadic or variadic
                elif p is self._RE_DEFAULT:
                    if last_p is not self._RE_ARGUMENT:
                        raise ValueError(f'Unexpected default value {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
                    next_default = s
                #else: #if p is RE_PUNCTUATION:
                elif s == '...':
                    if last_s is not None and last_s not in (',', '['):
                        raise ValueError(f'Unexpected variadic {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
                    next_variadic = True
                    variadic = True
                elif s == '[':
                    if optional:
                        raise ValueError(f'Unexpected nested {s!r} in function arguments {text!r} at char {(pos+2)}')
                    elif last_s is not None and last_s not in (','):
                        raise ValueError(f'Unexpected punctuation {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
                    optional = True
                    variadic = False
                    if last_s is not None:
                        self.end_argument_tuple()
                elif s == ']':
                    if not optional:
                        raise ValueError(f'Unexpected unmatched closing {s!r} in function arguments {text!r} at char {(pos+2)}')
                    elif last_s is None or last_p not in (self._RE_ARGUMENT, self._RE_DEFAULT):
                        raise ValueError(f'Unexpected closing {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
                    optional = variadic = False  # variadic continues inside [] tuples
                    #region ## COMMIT ARG ##
                    if last_p in (self._RE_ARGUMENT, self._RE_DEFAULT):
                        commit_arg()
                        next_optional = next_variadic = False
                        next_arg = next_default = None
                    #endregion
                elif s == ',':
                    if last_s is None or last_s in (',', '[', '...'):
                        raise ValueError(f'Unexpected closing {s!r} after token {last_s!r} in function arguments {text!r} at char {(pos+2)}')
                    variadic = variadic and optional  # variadic continues inside [] tuples
                    #region ## COMMIT ARG ##
                    if last_p in (self._RE_ARGUMENT, self._RE_DEFAULT):
                        commit_arg()
                        next_optional = next_variadic = False
                        next_arg = next_default = None
                    #endregion
                else:
                    raise ValueError(f'Unexpected punctuation {s!r} in function arguments {text!r} at char {(pos+2)}')
                    
                pos += m.end()
                last_s = s
                last_p = p
                break
            if m is None:
                raise ValueError(f'Failed to match function arguments {text!r} at char {(pos+2)}')

        return self._arguments

#######################################################################################

class SyscallArgumentSig(ArgumentSig):
    __slots__ = ArgumentSig.__slots__ + ('any', 'orig_name')
    def __init__(self, name:str, *, optional:bool=False, variadic:bool=False, default:str=None, tuple_last:bool=False, doc:str=None):
        self.any:bool = name[-1] == '*' if name else False
        self.orig_name:str = name
        name = f'_{(name[:-1] if self.any else name)}'
        super().__init__(name, optional=optional, variadic=variadic, default=default, tuple_last=tuple_last, doc=doc) # local group

    @property
    def is_any(self) -> bool: # alias to conform with naming
        return self.any
    @property
    def default_name(self) -> str:
        return self.orig_name if self.default is None else f'{self.orig_name} = {self.default}'
    @property
    def va_name(self) -> str:
        return f'...{self.orig_name}' if self.variadic else self.orig_name

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.orig_name!r}, optional={self.optional!r}, variadic={self.variadic!r}, default={self.default!r}, tuple_last={self.tuple_last!r})'
    def __str__(self) -> str:
        return f'[{self.va_name}{self.default_repr}]' if self.is_optional else f'{self.va_name}{self.default_repr}'

class SyscallSig(FunctionSig):
    __slots__ = FunctionSig.__slots__
    _ARG_TYPE = SyscallArgumentSig
    def __init__(self, name:str, arguments:Union[List[SyscallArgumentSig],str]=(), *, is_void:Optional[bool]=None, doc:str=None):
        self._arguments:Union[List[SyscallArgumentSig],str] = []
        super().__init__(name, arguments, is_void=is_void, group=GROUP_SYSCALL, doc=doc)

    @property
    def definition_keyword(self) -> str:
        return f'inter {super().definition_keyword}'

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.name!r}, {self.args_repr!r}, is_void={self.is_void!r})'
    def __str__(self) -> str:
        return f'{self.definition_keyword} {self.name}({self.args_str})'#full_args_repr})'

#######################################################################################


