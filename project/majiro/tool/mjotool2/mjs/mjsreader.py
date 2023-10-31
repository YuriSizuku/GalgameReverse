#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Script to read and parse .mjh files and collect hashes for variable names and function signatures.
"""

__version__ = '0.1.0'
__date__    = '2021-05-03'
__author__  = 'Robert Jordan'

#######################################################################################

## the code in this file is not fit for humans. or robots. or anyone. ##
## viewer discretion is advised, please look away                     ##

#######################################################################################

import enum, io, json, os, re, struct
from enum import auto
from collections import namedtuple, OrderedDict
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union


from .._util import DummyColors, Colors
from .._util import Fore as F, Style as S
from ..flags import MjoType
from ..crypt import hash32
# from ..script import KNOWN_SYSCALLS, SPECIAL_VARIABLES
# from ..script import MjoScript
# from ..analysis import ControlFlowGraph
from .identifiers import *

MjsKnownFile = namedtuple('MjsKnownFile', ('includename', 'filename', 'encoding'))
MjsInclude = namedtuple('MjsInclude', ('filename', 'included'))

#######################################################################################

#region ## OLD IDENTIFIERS

# class IdentifierType(enum.IntEnum):
#     UNKNOWN = -1
#     INT          = 0  #   '' postfix  (also used for handles/function pointers)
#     FLOAT        = 1  #  '%' postfix
#     STRING       = 2  #  '$' postfix
#     INT_ARRAY    = 3  #  '#' postfix
#     FLOAT_ARRAY  = 4  # '%#' postfix
#     STRING_ARRAY = 5  # '$#' postfix

# class IdentifierScope(enum.IntEnum):
#     UNKNOWN = -1
#     PERSISTENT = 0  # '#' prefix
#     SAVEFILE   = 1  # '@' prefix
#     THREAD     = 2  # '%' prefix
#     LOCAL      = 3  # '_' prefix
#     FUNCTION   = auto() # '$' prefix

# class FunctionReturn(enum.IntEnum):
#     UNKNOWN = -1
#     VOID = auto()
#     FUNC = auto()

# class Identifier:
#     # group will be resolved from name if found
#     def __init__(self, name:str, *, group:str=None):
#         self.name:str = name
#         self.group:str = group
#         self.scope:IdentifierScope = IdentifierScope.UNKNOWN
#         self.type:IdentifierType = IdentifierType.UNKNOWN
#         #
#         # realistically identifiers should have at least two chars before group
#         at_idx = name.find('@', 1)
#         if at_idx != -1: # group override from default
#             self.group = name[at_idx+1:]
#             self.name  = name[:at_idx]
#         #
#         # get scope / function
#         if   self.name[0] == '_':
#             self.scope = IdentifierScope.LOCAL
#         elif self.name[0] == '%':
#             self.scope = IdentifierScope.THREAD
#         elif self.name[0] == '@':
#             self.scope = IdentifierScope.SAVEFILE
#         elif self.name[0] == '#':
#             self.scope = IdentifierScope.PERSISTENT
#         elif self.name[0] == '$':
#             self.scope = IdentifierScope.FUNCTION
#         else:
#             self.scope = IdentifierScope.UNKNOWN
#         # get type / return type
#         if   self.name[-2:]=='$#':
#             self.type = IdentifierType.STRING_ARRAY
#         elif self.name[-2:]=='%#':
#             self.type = IdentifierType.FLOAT_ARRAY
#         elif self.name[-1] =='#':
#             self.type = IdentifierType.INT_ARRAY
#         elif self.name[-1] =='$':
#             self.type = IdentifierType.STRING
#         elif self.name[-1] =='%':
#             self.type = IdentifierType.FLOAT
#         else:
#             self.type = IdentifierType.INT
#     @property
#     def fullname(self) -> str:
#         if self.group is not None:
#             return '{0.name}@{0.group}'.format(self)
#         return self.name
#     @property
#     def is_func(self) -> bool:
#         return (self.scope == IdentifierScope.FUNCTION)
#     @property
#     def is_var(self) -> bool:
#         return (IdentifierScope.PERSISTENT <= self.scope <= IdentifierScope.LOCAL)
#     @property
#     def is_array(self) -> bool:
#         return (IdentifierType.INT_ARRAY <= self.type <= IdentifierType.STRING_ARRAY)
#     @property
#     def hash(self) -> int:
#         # from zlib import crc32
#         # return crc32(self.fullname.encode('cp932'))
#         #from ..crypt import hash32
#         return hash32(self.fullname)
#     @property
#     def hash_string(self) -> str:
#         return '${.hash:08x}'.format(self)
#     @property
#     def definition_keyword(self) -> str:
#         return ''
#     def __repr__(self) -> str:
#         return '{0.__class__.__name__}({0.fullname!r})'.format(self)
#     def __str__(self) -> str:
#         return self.fullname

# class ArgumentSig(Identifier):
#     def __init__(self, name:str, *, optional:bool=False):
#         super().__init__(name, group='') # local group
#         self.optional:bool = optional
#     @property
#     def is_optional(self) -> bool: # alias to conform with naming
#         return self.optional
#     def __repr__(self) -> str:
#         # if not self.is_optional:
#         #     return '{0.__class__.__name__}({0.fullname!r})'.format(self)
#         return '{0.__class__.__name__}({0.fullname!r}, optional={0.optional!r})'.format(self)
#     def __str__(self) -> str:
#         if self.is_optional:
#             return '[{0.name}]'.format(self)
#         return self.name



# class FunctionSig(Identifier):
#     def __init__(self, name:str, arguments:List[ArgumentSig]=(), *, has_return:Optional[bool]=True, group:str=None):
#         super().__init__(name, group=group)
#         self.has_return:bool = has_return
#         self.arguments:List[ArgumentSig] = list(arguments)
#     #
#     def add_argument(self, arg:Union[str, Identifier], *, optional:bool=...):
#         if isinstance(arg, ArgumentSig):
#             if optional is Ellipsis:
#                 self.arguments.append(arg) # append as-is
#                 return
#         #
#         if optional is Ellipsis:
#             optional = self.arguments[-1].optional if self.arguments else False
#         #
#         if isinstance(arg, Identifier):
#             self.arguments.append(ArgumentSig(arg.name, optional=optional))
#         else:
#             self.arguments.append(ArgumentSig(arg, optional=optional))
#     #
#     @property
#     def return_type(self) -> FunctionReturn:
#         if self.has_return is None:
#             return FunctionReturn.UNKNOWN
#         return FunctionReturn.FUNC if self.has_return else FunctionReturn.VOID
#     @property
#     def has_optionals(self) -> bool:
#         for arg in self.arguments:
#             if arg.is_optional:
#                 return True
#         return False
#     @property
#     def has_arguments(self) -> bool:
#         return bool(self.arguments)
#     @property
#     def definition_keyword(self) -> str:
#         if self.has_return is False:
#             return 'void'
#         return 'func' # only use void when confirmed(?)
#     def __repr__(self) -> str:
#         return '{0.__class__.__name__}({0.fullname!r}, {0.arguments!r}, has_return={0.has_return!r})'.format(self)
#     @property
#     def args_repr(self) -> str:
#         if not self.arguments:
#             return 'void'
#         arg_spans:List[Tuple[bool, list]] = []
#         optional = self.arguments[0].optional
#         arg_spans.append( (optional, []) )
#         for arg in self.arguments:
#             if arg.optional != optional:
#                 arg_spans.append( (arg.optional, []) )
#                 optional = arg.optional
#             arg_spans[-1][1].append(arg.name)
#         return ', '.join(('[{!s}]' if opt else '{!s}').format(', '.join(args)) for opt,args in arg_spans)
#     def __str__(self) -> str:
#         # args:str = 'void' # void when no args, like in C
#         # if self.has_arguments:
#         #     # get optional spans (realistically this should be: not-optional, [optional]) and done
            
#         #     args = ', '.join(str(a) for a in self.arguments)
#         # return '{0.definition_keyword!s} {0.fullname!s}({1})'.format(self, args)
#         return '{0.definition_keyword!s} {0.fullname!s}({0.args_repr!s})'.format(self)

# class VariableSig(Identifier):
#     def __init__(self, name:str, *, group:str=None):
#         super().__init__(name, group=group)
#     @property
#     def definition_keyword(self) -> str:
#         return 'var'
#     def __repr__(self) -> str:
#         return '{0.__class__.__name__}({0.fullname!r})'.format(self)
#     def __str__(self) -> str:
#         return '{0.definition_keyword!s} {0.fullname!s}'.format(self)

#endregion

#######################################################################################

class TokenType(enum.IntEnum):
    UNKNOWN = auto()
    #
    EOL = auto()  # EOL '\n'
    WHITESPACE = auto()  # ' ', '\t'
    COMMENT = auto()  # // line comment
    SHIFTJIS = auto()
    #
    PREPROCESSOR = auto()
    KEYWORD = auto()
    IDENTIFIER = auto()
    CTRL = auto()  # \x, \w, etc. (doesn't capture ()'s, but will allow it)
    #
    LITERAL_STRING = auto()
    LITERAL_FLOAT = auto()
    LITERAL_INT = auto()
    #
    SYMBOL = auto()
    OPERATOR = auto()
    UNEXPECTED_SYMBOL = auto()
    #UNKNOWN_SYMBOL = auto()

#######################################################################################

# auto-strips whitespace before a comment
RE_COMMENT = re.compile(r"^\s*//\s*(?P<comment>.*)$")

RE_WHITESPACE = re.compile(r"^[ \t]+") # ALT(?): r"\s+"

# we don't really NEED regex for this
RE_EOF = re.compile(r"^$")

# NOTE: unconfirmed keywords: continue
RE_KEYWORD = re.compile(r"^(?:void|func|var|if|else\s+if|else|switch|case|default|break|unbreak|continue|return|goto|do|while|for|setskip|constructor|destructor)\b")

# # includes private use, which are made-use of in defines, terrifying right?
# RE_IDENTIFIER = re.compile(r"^(?:(?P<prefix>[_%@#$\uE000-\uF8FF]*)(?P<name>[A-Za-z][0-9A-Za-z_]*)(?P<postfix>[%#$]*)(?P<group>@[0-9A-Za-z_]*)?)")

# allows invalid prefixes and postfixes because of DEFINES allowing them, at least as prefixes. example: #define @@RBY 12
RE_IDENTIFIER = re.compile(r"^(?:(?P<prefix>[_%@#$]*)(?P<name>[A-Za-z][0-9A-Za-z_]*)(?P<postfix>[%#$]*)(?P<group>@[0-9A-Za-z_]*)?)")

# NOTE: unconfirmed processors: #elif
RE_PREPROCESSOR = re.compile(r"^#(?P<name>define|include|if|elif|else|endif|group|force[cg]r|forcewipeonblank|subst|use_readflg)\b")

RE_SYMBOL = re.compile(r"^[{}()\[\],;?:]")
# includes unexpected symbols, like failed string matches with '"'
RE_UNEXPECTED_SYMBOL = re.compile(r"^[`'.\"_%@#$]")

# RE_UNEXPECTED_SYMBOL = re.compile(r"^[\"]")

# catch all for any letters (even though one letter is the only type)
RE_CTRL = re.compile(r"^\\[A-Za-z_]+")

# FIXME: lazy hack to assume all non-ascii is Shift_JIS
# skip private use block(?)
RE_SHIFTJIS = re.compile(r"^[\u0080-\uDFFF\uF900-\uFFFF].*$") # message text
#RE_SHIFTJIS = re.compile(r"^[\u0080-\uFFFF].*$") # message text

RE_LITERAL_STRING = re.compile(r"^(?:\"(?P<value>(?:\\.|[^\"])*)\")")
RE_LITERAL_FLOAT = re.compile(r"^(?:[0-9]*\.[0-9]+)\b")
# attempt float literal first to avoid '.' decimal
RE_LITERAL_INT = re.compile(r"^(?:(?P<hex>0[Xx][0-9A-Fa-f]+)|(?P<dec>[0-9]+))\b")

RE_OPERATOR = re.compile(r"^(?:<<?=?|>>?=?|&[&=]?|\|[|=]?|[+\-*/%^=]=?|=|~)")
# RE_BINARY_OPERATOR = re.compile(r"^(?P<assign>(?P<compound>[+\-*/%&|<<|>>^]")

# RE_BINARY_OPERATOR = re.compile(r"^(?P<assign>(?P<compound>[+\-*/%&|^]")

MATCHING = [
    (TokenType.EOL, RE_EOF),
    (TokenType.WHITESPACE, RE_WHITESPACE),
    (TokenType.COMMENT, RE_COMMENT),
    (TokenType.SHIFTJIS, RE_SHIFTJIS),

    (TokenType.PREPROCESSOR, RE_PREPROCESSOR),
    (TokenType.KEYWORD, RE_KEYWORD),
    (TokenType.IDENTIFIER, RE_IDENTIFIER),
    (TokenType.CTRL, RE_CTRL),

    (TokenType.LITERAL_STRING, RE_LITERAL_STRING),
    (TokenType.LITERAL_FLOAT, RE_LITERAL_FLOAT),
    (TokenType.LITERAL_INT, RE_LITERAL_INT),

    (TokenType.OPERATOR, RE_OPERATOR),
    (TokenType.SYMBOL, RE_SYMBOL)#,
    # (TokenType.UNEXPECTED_SYMBOL, RE_UNEXPECTED_SYMBOL)
]

class ParseToken:
    def __init__(self, type:TokenType, text:str, line:str, start:int, stop:int):
        self.type:TokenType = type
        self.text:str = text
        self.line:str = line
        self.start:int = start
        self.stop:int = stop
    # @property
    # def pos(self) -> int: # alias for matching usage in parse_token*
    #     return self.start
    def __len__(self) -> int:
        return self.stop - self.start
    def __repr__(self) -> str:
        return '<Token: {0.type.name!s} {0.text!r} [{0.start}:{0.stop}]>'.format(self)

PreToken = namedtuple('PreToken', ('condition', 'name'))

#######################################################################################

class MjsReader:
    def __init__(self, filename:str, *, encoding:str='cp932', debug_mode:bool=False, pre_greedy:bool=False):
        self.group_names:set = {"", "GLOBAL"} # already-known groups
        self.func_hashes:Dict[int, str] = {}
        self.var_hashes:Dict[int, str] = {}
        self.filename:str = filename
        self.encoding:str = encoding
        # lookup names are converted to lowercase
        self.known_files:Dict[str, MjsKnownFile] = {}
        # #define preprocessors: word replacement
        self.defines:Dict[str,str] = {}
        # #subst preprocessors: <REGEX>
        # sadly we can't just simply convert any regex to valid Python regex, I guess it could be attempted though
        self.substs:Dict[str,str] = {}
        # #group preprocessors: "NAME", push, pop
        self.groupstack:List[str] = ['GLOBAL'] #FIXME: Is this right?
        #self.group:str = '' # is GLOBAL default?
        # #include preprocessors: "path\file.mjh|txt"
        # note, these are skipped if not found, because nobody has all of the include files
        self.includes:List[MjsInclude] = [] # true if file was able to be read
        #self.includes:Dict[str, bool] = OrderedDict() # true if file was able to be read
        self.filestack:list = []
        self.file = None
        self.line:str = None
        self.pos:int = 0
        self.line_number:int = 0
        self.scope:int = 0
        self.block_level:int = 0
        self.functions:Dict[str, FunctionSig] = OrderedDict()
        self.variables:Dict[str, VariableSig] = OrderedDict()
        self.local_variables:Dict[str, VariableSig] = OrderedDict()
        self.local_arguments:Dict[str, ArgumentSig] = OrderedDict()
        self.local_functions:Dict[str, FunctionSig] = OrderedDict()
        self.current_function:FunctionSig = None
        self.use_readflg:bool = False
        self.forcewipeonblank:bool = False
        self.forcecr:bool = False
        self.forcegr:tuple = (None, None)
        self.pre_ifstack:List[PreToken] = []
        self.debug_mode:bool = debug_mode
        self.pre_greedy:bool = pre_greedy
        #self.pre_ignore:bool = False
    def add_known_file(self, includename:str, filename:str, *, encoding:str='cp932'):
        """Add known file that can be read and picked up by #include preprocessors
        """
        self.known_files[includename.lower()] = MjsKnownFile(includename, filename, encoding)
    def open(self, filename:str, *, encoding='cp932'):
        """Open a new file, and push the current file into the stack (if reading one)
        """
        reader = open(filename, 'rt', encoding=encoding)
        #with open(filename, 'rt', encoding=encoding) as reader:
        if self.file is not None:
            self.filestack.append(self.file)
        self.file = reader
    def close(self):
        """Close the current file being read, and return to previous file, if one exists.
        """
        if self.file is not None:
            self.file.close()
            self.file = None
            if self.filestack:
                self.file = self.filestack.pop()
    @property
    def pre_ignore(self) -> bool:
        for cond,_ in self.pre_ifstack:
            if not cond:
                return True
        return False
    @property
    def current_group(self) -> str:
        if self.current_function is not None:
            return ''
        elif self.groupstack:
            return self.groupstack[-1]
        else:
            return 'GLOBAL' # group default???
    # def parse_define(self):
    #
    def parse_preprocessor_if(self, pre_token:ParseToken):
        name:str = pre_token.text
        if name in ('#if', '#elif'):
            token = self.parse_token_skipws()
            if token.type is TokenType.LITERAL_INT:
                condition = int(token.text, 0)
            elif token.text in self.defines:
                condition = int(self.defines[token.text], 0)
            else:
                raise Exception('unexpected token {!r} after {} preprocessor on line {}'.format(token, name, self.line_number))
            #
            if name == '#if':
                self.pre_ifstack.append(PreToken(condition, name))
                if self.debug_mode: print('#if {}'.format(condition))
            elif name == '#elif': # assumed
                if not self.pre_ifstack:
                    raise Exception('unexpected preprocessor {} without #if on line {}'.format(name, self.line_number))
                if self.pre_ifstack[-1].name == '#else':
                    raise Exception('unexpected preprocessor {} after #else on line {}'.format(name, self.line_number))
                self.pre_ifstack[-1] = PreToken(condition, name)
                if self.debug_mode: print('#elif {}'.format(condition))
        elif name == '#else':
            if not self.pre_ifstack:
                raise Exception('unexpected preprocessor {} without #if on line {}'.format(name, self.line_number))
            if self.pre_ifstack[-1].name == '#else':
                raise Exception('unexpected preprocessor {} after #else on line {}'.format(name, self.line_number))
            self.pre_ifstack[-1] = PreToken(not self.pre_ifstack[-1].condition, name)
            # self.pre_ignore = self.pre_ifstack[-1]
            if self.debug_mode: print('#else // {}'.format(int(not self.pre_ignore)))
        elif name == '#endif':
            if not self.pre_ifstack:
                raise Exception('unexpected preprocessor {} without #if on line {}'.format(name, self.line_number))
            self.pre_ifstack.pop()
        else:
            raise Exception('program error: unexpected preprocessor {} without when looking for #ifs on line {}'.format(name, self.line_number))
    #
    def skipws(self, *, pos:int=..., peek:bool=False):
        if pos is Ellipsis: pos = self.pos
        token = self.parse_token(pos=pos, peek=True)
        while token.type is TokenType.WHITESPACE:
            pos = token.stop
            if not peek:
                self.pos = pos
            token = self.parse_token(pos=pos, peek=True)
        return token.stop
    def parse_preprocessor(self, pre_token:ParseToken):
        name:str = pre_token.text
        if name in ('#if', '#elif', '#else', '#endif'):
            self.parse_preprocessor_if(pre_token)
        elif self.pre_ignore:
            return
        if name == '#define':
            # token = self.read_token_until(TokenType.WHITESPACE)
            # if token.type in (TokenType.COMMENT, TokenType.EOL, TokenType.SYMBOL, TokenType.UNEXPECTED_SYMBOL):
            #     raise Exception('unexpected token {!r} after {} preprocessor on line {}'.format(token, name, self.line_number))
            self.skipws()
            define_name = self.read_token_until(TokenType.WHITESPACE)
            define_value = self.read_token_until(TokenType.WHITESPACE, TokenType.EOL, TokenType.COMMENT)
            self.defines[define_name] = define_value
            if self.debug_mode: print('#define {} {}'.format(define_name, define_value))
        elif name == '#include':
            token = self.parse_token_skipws()
            if token.type is not TokenType.LITERAL_STRING:
                raise Exception('unexpected token {!r} after {} preprocessor on line {}'.format(token, name, self.line_number))
            #FIXME: bad hack until string value resolution is added
            # I don't trust myself to have implemented this properly in a single day,
            #  functionality turned off
            # self.include(token.text[1:-1], encoding=self.encoding)
            # if self.debug_mode: print('#include {}'.format(token.text))
        elif name == '#group':
            token = self.parse_token_skipws()
            if token.type is TokenType.IDENTIFIER:
                if token.text == 'push':
                    self.groupstack.append('GLOBAL') # default group????
                    if self.debug_mode: print('#group push')
                elif token.text == 'pop':
                    self.groupstack.pop()
                    if self.debug_mode: print('#group pop')
                else:
                    raise Exception('unexpected keyword {!r} after {} preprocessor on line {}'.format(token.text, name, self.line_number))
            elif token.type is TokenType.LITERAL_STRING:
                #FIXME: bad hack until string value resolution is added
                self.groupstack[-1] = token.text[1:-1]
                self.add_group_name(self.groupstack[-1])
                if self.debug_mode: print('#group {}'.format(token.text))
            else:
                raise Exception('unexpected token {!r} after {} preprocessor on line {}'.format(token, name, self.line_number))
        else:
            pass # ignore other preprocessors for now
            
    #
    def add_group_name(self, group:str):
        self.group_names.add(group)
    def add_var_hash(self, varsig:VariableSig):
        if self.debug_mode: print(str(varsig))
        self.var_hashes[varsig.hash] = varsig
        if varsig.group:
            self.add_group_name(varsig.group)
    def add_arg_hash(self, argsig:ArgumentSig):
        # if self.debug_mode: print(str(varsig))
        self.var_hashes[argsig.hash] = argsig
    def add_func_hash(self, funcsig:FunctionSig):
        if self.debug_mode: print(str(funcsig))
        self.func_hashes[funcsig.hash] = funcsig
        if funcsig.group:
            self.add_group_name(funcsig.group)
    #
    def parse_varsig(self, var_token:ParseToken):
        token:ParseToken = self.parse_token_skipws()
        if token.type is not TokenType.IDENTIFIER:
            raise Exception('unexpected token {!r} after {} variable declaration on line {}'.format(var_token.text, token.text, self.line_number))
        variable = VariableSig(self.defines.get(token.text, token.text), group=self.current_group)
        if variable.name[0] == '_': # hack solution to force local variable groups
            variable.group = ''
        self.add_var_hash(variable)
        self.variables[variable.fullname] = variable
        token = self.parse_token_skipws()
        while token.text != ';':
            if token.text == ',':
                if variable is None:
                    raise Exception('Unexpected token {!r} in var declarations (no variable declared) on line {}'.format(token, self.line_number))
                variable = None
            elif token.type == TokenType.IDENTIFIER:
                if variable is not None:
                    raise Exception('Unexpected token {!r} in ar declarations (no comma after variable) on line {}'.format(token, self.line_number))
                variable = VariableSig(self.defines.get(token.text, token.text), group=self.current_group)
                if variable.name[0] == '_': # hack solution to force local variable groups
                    variable.group = ''
                self.add_var_hash(variable)
                self.variables[variable.fullname] = variable
            token = self.parse_token_skipws()
    #
    def parse_funcsig(self, func_token:ParseToken):
        is_void:bool = func_token.text == 'void'
        token = self.parse_token_skipws()
        if token.type is not TokenType.IDENTIFIER:
            raise Exception('unexpected token {!r} after {} function declaration on line {}'.format(token.text, token.text, self.line_number))
        function = FunctionSig(self.defines.get(token.text, token.text), is_void=is_void, group=self.current_group)
        token = self.parse_token_skipws(multiline=True)
        if token.text != '(':
            raise Exception('Unexpected token {!r}, expected function arguments open parenthesis on line {}'.format(token, self.line_number))
        token = self.parse_token_skipws(multiline=True)
        if token.text == 'void':
            token = self.parse_token_skipws(multiline=True)
            if token.text != ')':
                raise Exception('Unexpected token {!r} after void function arguments on line {}'.format(token, self.line_number))
        elif token.text == ')':
            # we'll also accept an absense of void
            pass
        else:
            optional:int = 0 # allow nesting
            #
            # last_token = None #token
            #token = self.parse_token_skipws(multiline=True)
            argsig = None
            while token.text != ')':
                if token.text == '[':
                    optional += 1
                elif token.text == ']':
                    if optional == 0:
                        raise Exception('Unexpected token {!r} in function arguments (no matching \'[\') on line {}'.format(token, self.line_number))
                    optional -= 1
                elif token.text == ',':
                    if argsig is None:
                        raise Exception('Unexpected token {!r} in function arguments (no arg declared) on line {}'.format(token, self.line_number))
                    argsig = None
                elif token.type is TokenType.IDENTIFIER:
                    if argsig is not None:
                        raise Exception('Unexpected token {!r} in function arguments (no comma after arg) on line {}'.format(token, self.line_number))
                    argsig = ArgumentSig(self.defines.get(token.text, token.text), optional=bool(optional))
                    function.add_argument(argsig)
                    self.add_arg_hash(argsig)
                else:
                    raise Exception('Unexpected token {!r} in function arguments on line {}'.format(token, self.line_number))
                token = self.parse_token_skipws(multiline=True)
        #
        token = self.parse_token_skipws(multiline=True)
        if token.text == ';':
            # just a declaration
            if self.current_function:
                self.local_functions[function.fullname] = function
            self.add_func_hash(function)
            return False
        elif token.text == '{':
            # begin new block
            #TODO: don't do this stuff right now
            # if self.current_function:
            #     raise Exception('Unexpected start of function inside another function on line'.format(self.line_number))
            # self.current_function = function
            self.functions[function.fullname] = function
            self.add_func_hash(function)
            return True
        else:
            raise Exception('Unexpected token {!r} after signature "{!s}" on line {}'.format(token, function, self.line_number))
    #
    def parse_line(self):
        if not self.next_line():
            return False
        token:ParseToken = self.parse_token_skipws()
        if token.type in (TokenType.EOL, TokenType.COMMENT):
            return True
        if token.type is TokenType.WHITESPACE:
            pass # shouldn't happen
        elif token.type is TokenType.PREPROCESSOR:
            self.parse_preprocessor(token)
        #FIXME: screw it, we'll parse function signatures and variables regardless, WE WANT THOSE HASHES!
        elif not self.pre_greedy and self.pre_ignore:
            return True
        elif token.type is TokenType.KEYWORD:
            if token.text in ('void', 'func'):
                self.parse_funcsig(token)
            elif token.text == 'var':
                self.parse_varsig(token)
        #FIXME: Moved below function/variable parsing for ALL THE HASHES!
        elif self.pre_greedy and self.pre_ignore:
            return True
        else:
            pass # do fuck-all about everything else
        
        return True
    #
    def parse_token(self, *, pos:int=..., peek:bool=False) -> ParseToken:
        if pos is Ellipsis: pos = self.pos
        #
        token:ParseToken = None
        for token_type,pattern in MATCHING:
            m = pattern.search(self.line[pos:]) #, pos)
            if m:
                token = ParseToken(token_type, m[0], self.line, pos, pos + len(m[0]))
                break
                #self.pos = token.stop
        # if token not found
        if pos >= len(self.line):
            token = ParseToken(TokenType.EOL, '', self.line, pos, pos)
        elif token is None:
            # invalid character
            token = ParseToken(TokenType.UNKNOWN, self.line[pos], self.line, pos, pos+1)
        #
        if not peek:
            self.pos = token.stop
        return token
    #
    def read_token_until(self, *token_types:TokenType, pos:int=..., peek:bool=False, multiline:bool=False) -> str:
        return ''.join(t.text for t in self.parse_token_until(*token_types, pos=pos, peek=peek, multiline=multiline))
    #
    def parse_token_skipws(self, *, pos:int=..., peek:bool=False, multiline:bool=False) -> ParseToken:
        token:ParseToken = self.parse_token(pos=pos, peek=peek)
        while token.type in (TokenType.WHITESPACE, TokenType.COMMENT) or token.type is TokenType.EOL:
            if token.type is TokenType.EOL:
                if not multiline or not self.next_line():
                    break
                pos = 0
            else:
                pos = token.stop
            token = self.parse_token(pos=pos, peek=peek)
        return token
    #
    def next_line(self) -> bool:
        self.line = self.file.readline()
        if not self.line:
            return False
        self.line = self.line.rstrip('\r\n').rstrip() # do rstrip?
        self.line_number += 1
        self.pos = 0
        return True

    def parse_token_until(self, *token_types:TokenType, pos:int=..., peek:bool=False, multiline:bool=False) -> List[ParseToken]:
        # if pos is Ellipsis: pos = self.pos
        #
        tokens:List[ParseToken] = []
        token:ParseToken = self.parse_token(pos=pos, peek=peek)
        while token.type not in token_types:
            tokens.append(token)
            if token.type is TokenType.EOL:
                if not multiline or not self.next_line():
                    break
                pos = 0
            else:
                pos = token.stop
            token = self.parse_token(pos=pos, peek=peek)
        return tokens
    #
    def include(self, includename:str, filename:str=None, *, encoding:str='cp932') -> bool:
        # if filename is not None:
        #     self.open(filename, encoding=encoding)
        #     self.includes.append(MjsInclude(includename, True))
        #     return True
        # #
        # include = self.known_files.get(includename.lower(), None)
        # if include:
        #     self.open(include.filename. encoding=include.encoding)
        #     self.includes.append(MjsInclude(includename, True))
        #     # self.read_file
        #     return True
        # #
        # if os.path.isfile(includename):
        #     self.open(includename, encoding=encoding)
        #     self.includes.append(MjsInclude(includename, True))
        #     return True
        #
        return False
    def read(self):
        self.open(self.filename, encoding=self.encoding)
        # this is stuuupiiiiiiiid
        while self.parse_line():
            pass
        self.close()


#######################################################################################


def select_hashes(hash_dict:Dict[int,str], *prefixes:str, sort:bool=True) -> List[Tuple[int,str]]:
    if not prefixes: # use all items
        hash_list = list(hash_dict.items())
    else:
        hash_list = []
        for prefix in prefixes:
            hash_list.extend((h,sig) for h,sig in hash_dict.items() if sig[0] == prefix)
    
    if sort:
        hash_list.sort(key=lambda v: v[1]) #.fullname)
    return hash_list

def select_groups(group_list:List[str], sort:bool=True) -> List[str]:
    group_list = list(group_list)
    if sort:
        group_list.sort()
    return group_list

def write_hashes_dict(writer:io.TextIOBase, hash_list:List[Tuple[int,str]], *, readable:bool=False, python:bool=False, tab:str='\t', singlequotes:bool=True):
    writer.write('{')

    for i,(h,sig) in enumerate(hash_list):
        # comma-separate after first item
        if i:        writer.write(',')
        # newline and indent
        if readable: writer.write('\n' + tab)
        
        if python: # we don't have to use butt-ugly string hex values
            writer.write('0x{:08X}:'.format(h)) 
        else:      # bleh, JSON doesn't support hex OR numeric keys
            writer.write('"{:08X}":'.format(h))
        
        # visual space between key and value
        if readable: writer.write(' ')

        if python and singlequotes: # just use normal-repr single-quotes
            # also a bad hack, because repr does not guarantee one quote or the other
            #  in CPython we trust
            writer.write(repr(sig)) #.fullname))
        else:
            #FIXME: bad hack for double-quotes
            writer.write('"{}"'.format(repr(sig)[1:-1])) #.fullname)[1:-1]))
        writer.flush()

    # newline before closing brace
    if readable: writer.write('\n')
    writer.write('}')
    # extra newline after end of dict (for cleanliness)
    #if python:   writer.write('\n')

def write_groups_list(writer:io.TextIOBase, group_list:List[str], *, readable:bool=False, python:bool=False, tab:str='\t', singlequotes:bool=True):
    writer.write('[')

    for i,group in enumerate(group_list):
        # comma-separate after first item
        if i:        writer.write(',')
        # newline and indent
        if readable: writer.write('\n' + tab)

        if python and singlequotes: # just use normal-repr single-quotes
            # also a bad hack, because repr does not guarantee one quote or the other
            #  in CPython we trust
            writer.write(repr(group)) #.fullname))
        else:
            #FIXME: bad hack for double-quotes
            writer.write('"{}"'.format(repr(group)[1:-1])) #.fullname)[1:-1]))
        writer.flush()

    # newline before closing brace
    if readable: writer.write('\n')
    writer.write(']')
    # extra newline after end of dict (for cleanliness)
    # if python:   writer.write('\n')

HashSelection = namedtuple('HashSelection', ('name', 'varname', 'hashes', 'prefixes'))
GroupSelection = namedtuple('GroupSelection', ('name', 'varname', 'groups'))

def write_python_file(writer:io.TextIOBase, hash_items:List[HashSelection], group_items:List[GroupSelection], *, readable:bool=True, sort:bool=True):
    all_names = []
    writer.write('#!/usr/bin/env python3\n')
    writer.write('#-*- coding: utf-8 -*-\n')
    writer.write('"""Known hashes and groups for Majiro  (this file was auto-generated)\n')
    writer.write('\n')
    writer.write('Contains:\n')
    hash_lists = []
    group_lists = []
    for i,item in enumerate(hash_items):
        hash_lists.append(select_hashes(item.hashes, *item.prefixes, sort=sort))
        writer.write('{:d} {} hashes\n'.format(len(hash_lists[-1]), item.name))
        all_names.append(item.varname)
    for i,item in enumerate(group_items):
        group_lists.append(select_groups(item.groups, sort=sort))
        writer.write('{:d} {} names\n'.format(len(group_lists[-1]), item.name))
        all_names.append(item.varname)
    writer.write('"""\n')
    writer.write('\n')
    writer.write('__date__    = {!r}\n'.format(__date__))
    writer.write('__author__  = {!r}\n'.format(__author__))
    writer.write('\n')
    writer.write('__all__ = {!r}\n'.format(all_names))
    writer.write('\n')
    writer.write('#######################################################################################\n')
    writer.write('\n')
    writer.write('from typing import Dict, Set\n')

    if hash_items:
        writer.write('\n')
    for i,item in enumerate(hash_items):
        hash_list = hash_lists[i]
        writer.write('\n{}:Dict[int,str] = '.format(item.varname))
        write_hashes_dict(writer, hash_list, readable=False, python=True)
        writer.write('\n')
    
    if group_items:
        writer.write('\n')
    for i,item in enumerate(group_items):
        group_list = group_lists[i]
        writer.write('\n{}:Set[str] = '.format(item.varname))
        write_groups_list(writer, group_list, readable=False, python=True)
        writer.write('\n')

    writer.write('\n\n')
    writer.write('del Dict, Set  # cleanup declaration-only imports\n')

def write_json_file(writer:io.TextIOBase, hash_items:List[HashSelection], group_items:List[GroupSelection], *, tab:str='\t', readable:bool=True, sort:bool=True):
    writer.write('{')
    first_item = True

    for item in hash_items:
        # comma-separate after first item
        if first_item:
            first_item = False
            # newline and indent
            if readable:   writer.write('\n' + tab)
        else:
            writer.write(',')
            # double-newline and indent
            if readable:   writer.write('\n\n' + tab)

        writer.write('"{}":'.format(item.varname))
        
        # visual space between key and value
        if readable:   writer.write(' ')

        hash_list = select_hashes(item.hashes, *item.prefixes, sort=sort)
        write_hashes_dict(writer, hash_list, readable=False, python=False)

    if readable and hash_items and group_items:
        writer.write(',\n\n') # visual separation between hashes and groups
        first_item = True   # set first item again because we already placed comma
    
    for item in group_items:
        # comma-separate after first item
        if first_item:
            first_item = False
            # newline and indent
            if readable:   writer.write('\n' + tab)
        else:
            writer.write(',')
            # double-newline and indent
            if readable:   writer.write('\n\n' + tab)

        writer.write('"{}":'.format(item.varname))
        
        # visual space between key and value
        if readable:   writer.write(' ')

        group_list = select_groups(item.groups, sort=sort)
        write_groups_list(writer, group_list, readable=False, python=False)

    # newline before closing brace
    if readable: writer.write('\n')
    writer.write('}')


def load_mjs_hashes(filename:str, var_hashes:Dict[int,str], func_hashes:Dict[int,str], group_names:Set[str], *, debug_mode:bool=True, pre_greedy:bool=True):
    mjsreader = MjsReader(filename, encoding='utf-8', debug_mode=debug_mode, pre_greedy=pre_greedy)
    mjsreader.read()
    # only parse, what you need - Liberty Mutable
    if var_hashes is not None:
        var_hashes.update((h,sig.fullname) for h,sig in mjsreader.var_hashes.items())
    if func_hashes is not None:
        func_hashes.update((h,sig.fullname) for h,sig in mjsreader.func_hashes.items())
    if group_names is not None:
        group_names.update(mjsreader.group_names)

def parse_json_hashes(data:dict) -> Iterable[Tuple[int,str]]:
    # expects: {"HEXHASH": "IDENTIFIERNAME@GROUP", ...}
    # hex prefixes: "", "$", "0x", "0X"
    def parse_hash(key:str) -> int:
        if key[0] == '$':
            key = key[1:]
        elif key[:2] in ('0x', '0X'):
            key = key[2:]
        return int(key, 16)

    return ((parse_hash(k), v) for k,v in data.items())

def parse_json_groups(data:list) -> Iterable[str]:
    # expects: ["name1", "name2", ...]
    # strips "@" before name if present
    def parse_group(key:str) -> int:
        if key[0] == '@':
            return key[1:]
        return key

    return (parse_group(k) for k in data)

def load_json_hashes(filename:str, hash_dict:Dict[int,str]):
    with open(filename, 'rt', encoding='utf-8') as reader:
        data = json.load(reader) # expects: {"HEXHASH": "IDENTIFIERNAME@GROUP", ...}
                                 # hex prefixes: "", "$", "0x", "0X"
        hash_dict.update(parse_json_hashes(data))

def load_json_groups(filename:str, group_names:Set[str]):
    with open(filename, 'rt', encoding='utf-8') as reader:
        data = json.load(reader) # expects: ["name1", "name2", ...]
                                 # strips "@" before name if present
        group_names.update(parse_json_groups(data))

def load_json_all(filename:str, var_hashes:Dict[int,str], func_hashes:Dict[int,str], sys_hashes:Dict[int,str], group_names:Set[str]):
    with open(filename, 'rt', encoding='utf-8') as reader:
        data = json.load(reader)

        if var_hashes and "variables" in data:
            var_hashes.update(parse_json_hashes(data["variables"]))
        if var_hashes and "local_vars" in data:
            var_hashes.update(parse_json_hashes(data["local_vars"]))
        if var_hashes and "thread_vars" in data:
            var_hashes.update(parse_json_hashes(data["thread_vars"]))
        if var_hashes and "savefile_vars" in data:
            var_hashes.update(parse_json_hashes(data["savefile_vars"]))
        if var_hashes and "persistent_vars" in data:
            var_hashes.update(parse_json_hashes(data["persistent_vars"]))

        if func_hashes and "functions" in data:
            func_hashes.update(parse_json_hashes(data["functions"]))
        if func_hashes and "usercalls" in data:
            func_hashes.update(parse_json_hashes(data["usercalls"]))

        if sys_hashes and "syscalls" in data:
            sys_hashes.update(parse_json_hashes(data["syscalls"]))
        if group_names and "groups" in data:
            group_names.update(parse_json_groups(data["groups"]))


#######################################################################################


## MAIN FUNCTION ##

def main(argv:list=None) -> int:
    ## PARSER SETUP ##

    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input', dest='inputs', metavar='MJSFILE', nargs='+', default=[], required=False, help='parse hashes and groups from mjs/mjh files')
    parser.add_argument('-H', '--hashes', metavar='JSONFILE', nargs='+', default=[], required=False, help='parse user-defined hashes from json files')
    parser.add_argument('-s', '--syscalls', metavar='JSONFILE', nargs='+', default=[], required=False, help='parse syscall hashes from json files')
    parser.add_argument('-g', '--groups', metavar='JSONFILE', nargs='+', default=[], required=False, help='parse groups from json files')
    parser.add_argument('-a', '--all', metavar='JSONFILE', nargs='+', default=[], required=False, help='parse "syscalls", "functions", "variables", and "groups" from json files')

    args = parser.parse_args(argv)

    print('Work work...')

    ## VARIABLE SETUP ##

    group_names:Set[str] = set()
    var_hashes:Dict[int,str] = {}
    func_hashes:Dict[int,str] = {}
    sys_hashes:Dict[int,str] = {}

    # predefined known hashes that won't show up as declarations
    EXTRA_VAR_HASHES = {0xA704BDBD:"__SYS__NumParams@"}
    EXTRA_FUNC_HASHES = {}
    EXTRA_SYS_HASHES = {} # nothing yet

    var_hashes.update(EXTRA_VAR_HASHES)
    func_hashes.update(EXTRA_FUNC_HASHES)
    sys_hashes.update(EXTRA_SYS_HASHES)


    ## DEFAULT BEHAVIOR ##

    debug_mode:bool = True
    pre_greedy:bool = True
    if not args.inputs + args.hashes + args.syscalls + args.groups + args.all:
        load_mjs_hashes('../data/mjs/adv.mjh.bak', var_hashes, func_hashes, group_names, debug_mode=debug_mode, pre_greedy=pre_greedy)

    ## LOAD FILES ##

    for scriptfile in args.inputs:
        load_mjs_hashes(scriptfile, var_hashes, func_hashes, group_names, debug_mode=debug_mode, pre_greedy=pre_greedy)
    
    for jsonfile in args.hashes:
        # combination of all user-defined hashes (these can be seperated later by the prefix)
        user_hashes:Dict[int,str] = {}
        load_json_hashes(jsonfile, user_hashes)
        for k,v in user_hashes.items():
            if v.fullname == '$':
                func_hashes[k] = v
            else:
                var_hashes[k] = v
        del user_hashes

    for jsonfile in args.syscalls:
        load_json_hashes(jsonfile, sys_hashes)

    for jsonfile in args.groups:
        load_json_groups(jsonfile, group_names)

    for jsonfile in args.all:
        load_json_all(jsonfile, var_hashes, func_hashes, sys_hashes, group_names)

    # add main function hashes for all known groups (even if they aren't used)
    for group in group_names:
        funcsig = Identifier('$main', group=group)
        func_hashes[funcsig.hash] = funcsig.fullname


    # datasets to initialize with list comprehension
    PY_HASHES = (
        ('local_vars', var_hashes, ('_',)),
        ('thread_vars', var_hashes, ('%',)),
        ('savefile_vars', var_hashes, ('@',)),
        ('persistent_vars', var_hashes, ('#',)),
        #('variables', var_hashes, ()),
        ('usercalls', func_hashes, ()),
        ('syscalls', sys_hashes, ()),
    )
    
    JSON_HASHES = (
        ('variables', var_hashes, ()),
        ('usercalls', func_hashes, ()),
        ('syscalls', sys_hashes, ()),
    )
    GROUPS = (
        ('groups', group_names),
    )

    # write python for our library
    hash_items = [HashSelection(n.replace('_', ' ').rstrip('s'), n.upper(), d, p) for n,d,p in PY_HASHES]
    group_items = [GroupSelection(n.replace('_', ' ').rstrip('s'), n.upper(), l) for n,l, in GROUPS]
    with open('../src/mjotool/known_hashes/_hashes.py', 'wt+', encoding='utf-8') as writer:
        write_python_file(writer, hash_items, group_items, readable=False, sort=True)
        writer.flush()

    # write compact af json for non-humans
    hash_items = [HashSelection(n, n, d, p) for n,d,p in JSON_HASHES]
    group_items = [GroupSelection(n, n, l) for n,l, in GROUPS]
    with open('../data/known_hashes_compact.json', 'wt+', encoding='utf-8') as writer:
        write_json_file(writer, hash_items, group_items, tab='\t', readable=False, sort=True)
        writer.flush()
    # write """readable""" json for everybody else
    with open('../data/known_hashes_readable.json', 'wt+', encoding='utf-8') as writer:
        write_json_file(writer, hash_items, group_items, tab='\t', readable=True, sort=True)
        writer.flush()

    print('Job done!')
    return 0


## MAIN CONDITION ##

if __name__ == '__main__':
    exit(main())

