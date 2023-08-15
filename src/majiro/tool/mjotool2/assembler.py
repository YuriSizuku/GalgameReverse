#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro IL script assembler
"""

__version__ = '0.0.1'
__date__    = '2021-04-16'
__author__  = 'Robert Jordan'

__all__ = ['MjILAssembler']

#######################################################################################

import csv, enum, io, math, os, re, struct  # math used for isnan()
from abc import abstractproperty
from collections import namedtuple, OrderedDict
from typing import Any, Callable, Dict, Iterable, Iterator, List, NoReturn, Optional, Set, Tuple, Union  # for hinting in declarations
#source: <https://stackoverflow.com/a/38935153/7517185>
from typing import Match, Pattern  # for regex type hinting
from enum import auto
from struct import calcsize

from ._util import StructIO, DummyColors, Colors, signed_i, unsigned_I, doublequote, sub_escapes, strip_ansi, len_ansi, repl_tabs, len_tabs, escape_ignorequotes, unescape
from .flags import MjoType, MjoScope, MjoInvert, MjoModifier, MjoDimension, MjoFlags
from .opcodes import Opcode
from . import crypt
# from . import known_hasheshinting in declarations
from . import known_hashes

from .script import Instruction, FunctionEntry, MjoScript, BasicBlock, Function
from .analysis import ControlFlowGraph


#region ## PARSER EXCEPTIONS ##

class TokenError(Exception):
    """Error raised by known token during parsing
    """
    pass

class ContextError(Exception):
    """Error raised by unexpected tokens during a specific context
    """
    pass

#endregion

#region ## TOKEN ENUMS ##

class TokenKind(enum.IntEnum):
    UNKNOWN    = -1

    # EOL:
    EOF            = auto()  # unused?
    EOL            = auto()
    # WHITESPACE:
    WHITESPACE     = auto()
    COMMENT        = auto()
    # TARGET/LABEL:
    OFFSET         = auto()
    ADDRESS        = auto()
    LABEL          = auto()
    # LINE_NUMBER:
    LINE_NUMBER    = auto()
    # KEYWORD:
    FUNC           = auto()  # func|void
    DIRECTIVE      = auto()
    DIRECTIVE_ARG  = auto()
    SCOPE          = auto()
    TYPE           = auto()
    DIMENSION      = auto()
    MODIFIER       = auto()
    OPCODE_INVERT  = auto()  # not, notl
    INVERT         = auto()
    OPCODE         = auto()  # op.103, nop.103, stelem...
    OPCODE_INVALID = auto()  # special handling of op.XXX and nop.XXX
    # STRING:
    LITERAL_STRING = auto()
    # FLOAT:
    LITERAL_FLOAT  = auto()  # fixed, exponential
    SPECIAL_FLOAT  = auto()  # NaN, [+-]Inf[inity] ~~(this will be typed as a keyword if there's no [+-] prefix)~~
    # INT:
    LITERAL_INT    = auto()  # decimal or hex, this is a legal float operand (assuming int is not also a potential operand)
    # HASH:
    LITERAL_HASH   = auto()
    INLINE_HASH    = auto()
    INLINE_RESOURCE= auto()
    # PUNCTUATION:
    PUNCTUATION    = auto()  # nothing special, check by character

class TokenType(enum.IntEnum):
    UNKNOWN    = -1
    # reader:
    # EOF          = auto()
    EOL          = auto()
    WHITESPACE   = auto()
    # everything else:
    TARGET       = auto()
    LABEL        = auto()
    LINE_NUMBER  = auto()
    KEYWORD      = auto() # Aa.dy887_  [A-Za-z]
    STRING       = auto() # "string"
    FLOAT        = auto() # [+-].0, [+-]0.0, 
    INT          = auto() # [+-]0, [+-]0x0  (all ranges outside )
    HASH         = auto() # $XXXXXXXX, $_hashname%, ${anotherhashname}
    RESOURCE     = auto() # %L543, %{anythinggoes}
    PUNCTUATION  = auto() # ()[]{}, etc. for function/array syntax etc.


#endregion

#region ## TOKEN STRUCTURE ##

class ParseToken:
    def __init__(self, type:TokenType, match:Union[Match,str], line:str, line_num:int, start:int, end:int):
        self.type:TokenType = type
        self.kind:Optional[TokenKind] = None
        self.match:Optional[Match] = match if not isinstance(match, str) else None
        self.text:str = match if isinstance(match, str) else match[0]
        self.value:Optional[Any] = None # contained value
        self.line:str = line
        self.line_num:int = line_num
        self.start:int = start
        self.end:int = end
        # print(repr(self))
    @property
    def span(self) -> Tuple[int, int]:
        return (self.start, self.end)
    def __len__(self) -> int:
        return self.end - self.start
    def __repr__(self) -> str:
        return '<{0.__class__.__name__}: {0.type.name!s} {0.text!r} [{0.start}:{0.end}]>'.format(self)


#endregion

#region ## KEYWORDS LOOKUP ##

# some of these contain redundant/useless values, that's fine for now

FUNC_KEYWORDS:Dict[str,str] = OrderedDict({
    'func': 'func',
    # aliases:
    'void': 'func',
})

DIRECTIVE_KEYWORDS:Dict[str,str] = OrderedDict({
    'readmark':   'readmark',
    'entrypoint': 'entrypoint',
    'group':      'group',
    'resfile':    'resfile',
})

DIRECTIVE_ARG_KEYWORDS:Dict[str,bool] = OrderedDict({
    'disable': False,
    'enable':  True,
    'none':    None,
    # # aliases:
    # 'off':     False,
    # 'on':      True,
})

# map of types/enums that implement: fromname(name, default=...)
FROMNAME_KIND_MAP:Dict[TokenKind,type] = OrderedDict({
    TokenKind.SCOPE:     MjoScope,
    TokenKind.TYPE:      MjoType,
    TokenKind.DIMENSION: MjoDimension,
    TokenKind.MODIFIER:  MjoModifier,
    TokenKind.INVERT:    MjoInvert,
    TokenKind.OPCODE:    Opcode,
})
# map of names to valid keyword names/values, many are redundant
KEYWORD_KIND_MAP:Dict[TokenKind,dict] = OrderedDict({
    #TokenKind.OPCODE: Opcode.ALIASES,  # this includes all op.xxx patterns
    TokenKind.FUNC:          FUNC_KEYWORDS,
    TokenKind.DIRECTIVE:     DIRECTIVE_KEYWORDS,
    TokenKind.DIRECTIVE_ARG: DIRECTIVE_ARG_KEYWORDS,
})

#endregion

#region ## TOKEN REGEX ##

RE_EOL = re.compile(r"^\s*((?:\/\/|;).*)?$")

RE_WHITESPACE = re.compile(r"^[ \t]+") #ALT?: r"\s+"

# label, (address | name)
RE_LABEL       = re.compile(r"^((?P<address>[0-9A-Fa-f]+)|(?P<name>[0-9A-Za-z_]+)):")
# target, (offset no '~' | address | name)
RE_TARGET      = re.compile(r"^@(~(?P<offset>[-+]?[0-9A-Fa-f]+)|(?P<address>[0-9A-Fa-f]+)|(?P<name>[0-9A-Za-z_]+))\b")
# number
RE_LINE_NUMBER = re.compile(r"^#([0-9]+)\b")

#NOTE: allow uppercase, but no keyword accepts it, used to throw errors
# keyword
RE_KEYWORD = re.compile(r"^([A-Za-z_](?:[0-9A-Za-z_.]*[0-9A-Za-z_])?)\b")

# quoted, (unquoted)
RE_LITERAL_STRING = re.compile(r"^(\"(?P<value>(?:\\.|[^\"])*)\")")
#FIXME: [DISCUSSION] decided on specification for legal NAN/INF, currently all case-mixing is legal
#NOTE: regex case-insensitivity (?i:) is Python 3.6+
# value, (fixed | exponent | (+-)inf | nan)
RE_LITERAL_FLOAT = re.compile(r"^(([+-]?[0-9]*\.[0-9]+)|([+-]?\d*\.\d+[Ee][+-]?\d+)|([+-]?(?i:INF)(?i:INITY)?)|(?i:NaN))\b")
#FIXME: [DISCUSSION] should [+-]0xHEX be allowed? should unsigned decimal integers be allowed?
# value, (prefixed hex | dec)
RE_LITERAL_INT = re.compile(r"^((?P<hex>[+-]?0[Xx][0-9A-Fa-f]+)|(?P<dec>[+-]?[0-9]+))\b(?!\.)")

# no-$-prefix hash, (hex | implicit name | explicit name w/o {})
RE_ANY_HASH = re.compile(r'^\$(([0-9A-Fa-f]{8})|([_%@#$0-9A-Za-z]+)|\{([^}]+)\})(?=$|\s|[\/;(){}\[\],])')
# RE_LITERAL_HASH = re.compile(r'^\$(?P<value>[0-9A-Fa-f]{8})\b')
# # name
# RE_INLINE_HASH_IMPLICIT = re.compile(r'^\$(?P<name>[_%@#$0-9A-Za-z]+)(?=$|\s|[\/;(){}\[\],])')
# # name
# RE_INLINE_HASH_EXPLICIT = re.compile(r'^\$\{(?P<name>(?:[^}]+)\}(?=$|\s|[\/;(){}\[\],])')

# no-%-prefix hash, (implicit name | explicit name w/o {})
RE_RESOURCE = re.compile(r'^%(([_%@#$0-9A-Za-z]+)|\{([^}]+)\})(?=$|\s|[\/;(){}\[\],])')

RE_PUNCTUATION = re.compile(r"^[(){}\[\],]")

#endregion

#region ## PARSE MATCHED TOKENS ##

def parse_target(token:ParseToken) -> NoReturn:
    # pattern: RE_TARGET
    m:Match = token.match
    if m[2]: # explicit offset
        #NOTE: Python supports int('+1', 16), we don't need to handle it (if you're porting this, beware!)
        token.value = int(m[2], 16)
        token.kind = TokenKind.OFFSET
    elif m[3]: # address
        token.value = m[3]  #TODO: address target is stored as str
        # token.value = int(m[3], 16)
        token.kind = TokenKind.ADDRESS
    else: #elif m[4]: # label name
        token.value = m[4]
        token.kind = TokenKind.LABEL

def parse_label(token:ParseToken) -> NoReturn:
    # pattern: RE_LABEL
    m:Match = token.match
    if m[2]: # address
        token.value = m[2]  #TODO: address target is stored as str
        # token.value = int(m[2], 16)
        token.kind = TokenKind.ADDRESS
    else: #elif m[3]: # label name
        token.value = m[3]
        token.kind = TokenKind.LABEL

def parse_line_number(token:ParseToken) -> NoReturn:
    # pattern: RE_LINE_NUMBER
    m:Match = token.match
    token.value = int(m[1], 10)
    token.kind = TokenKind.LINE_NUMBER

def parse_keyword(token:ParseToken) -> NoReturn:
    name = token.text

    # types implementing function: cls.fromname(name:str, default=...)
    for kind,namecls in FROMNAME_KIND_MAP.items():
        nameval = namecls.fromname(name, None)
        if nameval is not None:
            # if kind is TokenKind.INVERT: and name in Opcode.ALIASES:
            if kind is TokenKind.INVERT:
                # handle context dependent keywords: notl, not
                opcode = Opcode.fromname(name, None)
                if opcode is not None:
                    # flags and opcodes will need to handle this awkward scenario
                    token.value = (Opcode.ALIASES[name], nameval)
                    token.kind = TokenKind.OPCODE_INVERT
                    return
            token.value = nameval
            token.kind = kind
            return

    # dictionaries of known keywords:
    # func|void, directives, directive arguments:
    for kind,kwddict in KEYWORD_KIND_MAP.items():
        kwdval = kwddict.get(name, None)
        if kwdval is not None:
            token.value = kwdval
            token.kind = kind
            return

    # point of no return: add some non-essential failures that may have happened
    if re.match(r"^dim\d+$", name):
        raise Exception(f'invalid variable dimension flag {name!r}')
    elif re.match(r"^n?op\.[0-9a-f]{3}$", name):
        raise Exception(f'invalid opcode value {name!r}')
    else:
        raise Exception(f'unknown symbol or keyword {name!r}')

def parse_string(token:ParseToken) -> NoReturn:
    # pattern: RE_LITERAL_STRING
    m:Match = token.match
    token.value = unescape_string(m[2])
    token.kind = TokenKind.LITERAL_STRING

def parse_float(token:ParseToken) -> NoReturn:
    # pattern: RE_LITERAL_FLOAT
    # Python supports parsing all formats: [+-]fixed, [+-]exponent, [+-]inf(inity), NaN
    token.value = float(token.text)
    token.kind = TokenKind.LITERAL_FLOAT

def parse_int(token:ParseToken) -> NoReturn:
    # pattern: RE_LITERAL_INT
    token.value = signed_i(int(token.text, 0))  # 0 checks prefix for base type
    token.kind = TokenKind.LITERAL_INT

def parse_hash(token:ParseToken) -> NoReturn:
    # pattern: RE_ANY_HASH
    m:Match = token.match
    if m[2]: # hex
        token.value = int(m[2], 16)
        token.kind = TokenKind.LITERAL_HASH
    elif m[3]: # inline implicit
        token.value = m[3]
        token.kind = TokenKind.INLINE_HASH
    else: #elif m[4]: # inline explicit
        token.value = m[4]
        token.kind = TokenKind.INLINE_HASH

def parse_resource(token:ParseToken) -> NoReturn:
    ## pattern: RE_RESOURCE
    m:Match = token.match
    if m[2]: # inline implicit
        token.value = m[2]
        token.kind = TokenKind.INLINE_RESOURCE
    else: #elif m[3]: # inline explicit
        token.value = m[3]
        token.kind = TokenKind.INLINE_RESOURCE

def parse_punctuation(token:ParseToken) -> NoReturn:
    # pattern: RE_PUNCTUATION
    token.value = token.text
    token.kind = TokenKind.PUNCTUATION

def parse_whitespace(token:ParseToken) -> NoReturn:
    # pattern: RE_WHITESPACE
    token.value = token.text
    token.kind = TokenKind.WHITESPACE

def parse_eol(token:ParseToken) -> NoReturn:
    # pattern: RE_EOL
    token.value = ''
    token.kind = TokenKind.EOL

#endregion

#region ## TOKEN MATCHING TABLE ##

MATCHING:Dict[TokenType, Tuple[Pattern,Callable]] = OrderedDict({
    TokenType.EOL:         (RE_EOL, parse_eol),                 # [] empty string
    TokenType.WHITESPACE:  (RE_WHITESPACE, parse_whitespace),   # [ \t] and comments (//|;|/**/)
    #NOTE: float goes above all else to lazily steal any INF/NAN matches from the KEYWORD regex
    TokenType.FLOAT:       (RE_LITERAL_FLOAT, parse_float),     # [.] contains, [+-]Inf(inity), NaN
    TokenType.LABEL:       (RE_LABEL, parse_label),             # [0-9A-Za-z_] prefix, [:] postfix
    TokenType.TARGET:      (RE_TARGET, parse_target),           # [@] prefix
    TokenType.LINE_NUMBER: (RE_LINE_NUMBER, parse_line_number), # [#] prefix
    TokenType.KEYWORD:     (RE_KEYWORD, parse_keyword),         # [A-Za-z_] prefix
    TokenType.STRING:      (RE_LITERAL_STRING, parse_string),   # [""] surrounds
    TokenType.INT:         (RE_LITERAL_INT, parse_int),         # [^.] postfix
    TokenType.HASH:        (RE_ANY_HASH, parse_hash),           # [$] prefix
    TokenType.RESOURCE:    (RE_RESOURCE, parse_resource),       # [%] prefix
    TokenType.PUNCTUATION: (RE_PUNCTUATION, parse_punctuation), # [(){}[],]
})

# MATCHING:Dict[TokenType, Tuple[Pattern,Callable]] = OrderedDict({
#     TokenType.EOL:         RE_EOL,            # [] empty string
#     TokenType.WHITESPACE:  RE_WHITESPACE,     # [ \t] and comments (//|;|/**/)
#     TokenType.LABEL:       RE_LABEL,          # [0-9A-Za-z_] prefix, [:] postfix
#     TokenType.TARGET:      RE_TARGET,         # [@] prefix
#     TokenType.LINE_NUMBER: RE_LINE_NUMBER,    # [#] prefix
#     TokenType.KEYWORD:     RE_KEYWORD,        # [A-Za-z_] prefix
#     TokenType.STRING:      RE_LITERAL_STRING, # [""] surrounds
#     TokenType.FLOAT:       RE_LITERAL_FLOAT,  # [.] contains 1
#     TokenType.INT:         RE_LITERAL_INT,    # [^.] postfix
#     TokenType.HASH:        RE_ANY_HASH,       # [$] prefix
#     TokenType.PUNCTUATION: RE_PUNCTUATION,    # [(){}[],]

#     # unimplemented:
#     #TokenType.RESOURCE:    RE_RESOURCE,       # [%] prefix
# })

#endregion

# RE_COMMENT_INLINE  = re.compile(r"(?P<inline>\/\*[^\n]*?\*\/)|(?P<line>(?:\/\/|;).*$)")
RE_STRIP_COMMENTS  = re.compile(r"(\/\*[^\n]*?\*\/)|((?:\/\/|;).*$|(\/*))")
def strip_comments(string:str, pos:int=0, preserve_ws:Optional[bool]=True) -> Tuple[str, int]:
    """tuple[1] > -1 for position of an unclosed block comment
    """
    if preserve_ws is None:
        space = ''
    elif preserve_ws is False:
        space = ' '
    elif preserve_ws is not True:
        # True -> ' ' * len(match)
        raise ValueError(f'argument \'preserve_ws\' must be True, False, or None, not {preserve_ws.__class__.__name__}')
    m:Match = RE_STRIP_COMMENTS.search(string, pos)
    unclosed:int = -1
    while m:
        if m[1]:  # inline block comment
            if preserve_ws is True:
                space = re.sub(r"[^\r\n]", r" ", string[m.start()+pos:m.end()+pos])
                # space = ' ' * (m.end()+pos - (m.start()+pos))
            elif preserve_ws is False:
                space = re.sub(r"[^\r\n]", r"", string[m.start()+pos:m.end()+pos]) or ' ' # minimum one space
            # preserve newlines
            # space = re.sub(r"[^\r\n]", r" ", string[m.start()+pos:m.end()+pos])
            string = space.join( (string[:m.start()+pos], string[m.end()+pos:]) )
        elif m[2]:  # line comment
            #string = ''.join( (string[:m.start()+pos], string[m.end()+pos:]) )
            string = string[:m.start()+pos]
            break  # safely finish loop
        else: #elif m[3]:  # unclosed block comment
            # unclosed block comment
            string = string[:m.start()+pos]
            unclosed = m.start()+pos
            break
        
        pos += m.end()
        m = RE_STRIP_COMMENTS.search(string, pos)
    return (string, unclosed)


#region ## UNESCAPE STRING ##

LITERAL_ESCAPES:Dict[str,str] = OrderedDict({
    '\\': '\\',
    '\'': '\'',
    '\"': '\"',
    'a': '\a',
    'b': '\b',
    'f': '\f',
    'n': '\n',
    'r': '\r',
    't': '\t',
    'v': '\v',
})

def unescape_string(string:str, useless_escapes:bool=False) -> str:
    sb = io.StringIO()
    i = 0
    while i < len(string):
        c = string[i]
        if c != '\\': # character
            sb.write(c)
            i += 1
        else: # escape
            c = string[i+1]
            if c in LITERAL_ESCAPES: # \_
                sb.write(LITERAL_ESCAPES[c])
                i += 2
            elif c == 'x': # \xFF
                sb.write(chr(int(string[i+2:i+4], 16)))
                i += 4
            elif c == 'u': # \uFFFF
                sb.write(chr(int(string[i+2:i+6], 16)))
                i += 6
            elif c == 'U': # \UFFFFFFFF
                #sb.write(chr(int(string[i+1:i+9], 16)))
                #i += 10
                raise Exception('UTF-32 escape \\UXXXXXXXX is not supported')
            elif ('0' <= c <= '7'): # \7, \77, \777
                if not ('0' <= string[i+1] <= '7'):
                    octlen = 1
                elif not ('0' <= string[i+2] <= '7'):
                    octlen = 2
                else:
                    octlen = 3
                sb.write(chr(int(string[i+1:i+1+octlen], 8)))
                i += 1 + octlen
            elif useless_escapes: # useless literal escape
                sb.write(c)
            else:
                #TODO: choose to handle useless escapes here
                raise Exception('Unexpected escape character {!r} in string literal!'.format(c))
    return sb.getvalue()

#endregion

#region ## INSTRUCTION SIZE ##

InstructionSize = namedtuple('InstructionSize', ('size', 'is_fixed'))

def opcode_size(opcode:Opcode) -> InstructionSize:
    size:int = calcsize('<H')  # opcode
    is_fixed:bool = True
    for operand in opcode.encoding:
        if operand == 't':
            # type list
            size += calcsize('<H')  # count
            is_fixed = False  # variable-length (types)
            # size += calcsize(f'<{len(instr.type_list):d}B')  # types
        elif operand == 's':
            # string data
            size += calcsize('<H')  # string size + null-terminator
            is_fixed = False  # variable-length (string + null-terminator)
            # size += calcsize(f'<{len(instr.string.encode("cp932"))+1:d}s')  # string + null terminator
        elif operand == 'f':
            # flags
            size += calcsize('<H')  # flags bitmask
        elif operand == 'h':
            # hash value
            size += calcsize('<I')  # hash value
        elif operand == 'o':
            # variable offset
            size += calcsize('<h')  # variable offset
        elif operand == '0':
            # 4 byte address placeholder
            size += calcsize('<I')  # 4 byte address placeholder
        elif operand == 'i':
            # integer constant
            size += calcsize('<i')  # integer constant
        elif operand == 'r':
            # float constant
            size += calcsize('<f')  # float constant
        elif operand == 'a':
            # argument count
            size += calcsize('<H')  # argument count
        elif operand == 'j':
            # jump offset
            size += calcsize('<i')  # jump offset
        elif operand == 'l':
            # line number
            size += calcsize('<H')  # line number
        elif operand == 'c':
            # switch case table
            size += calcsize('<H')  # count
            is_fixed = False  # variable-length (cases)
            # size += calcsize(f'<{len(instr.switch_cases):d}i')  # cases
        else:
            raise Exception(f'unrecognized encoding specifier: {operand!r}')
    return InstructionSize(size, is_fixed)

# lookup (via Opcode.value) of FIXED instruction sizes (where operands do not take a variable length of arguments)
# all variable-length instructions will return None
INSTRUCTION_SIZES:Dict[int, InstructionSize] = OrderedDict((o.value, opcode_size(o)) for o in Opcode.LIST)

def instruction_size(instr:Instruction) -> int:
    instr_size:InstructionSize = INSTRUCTION_SIZES[instr.opcode.value]
    if instr_size.is_fixed:
        return instr_size.size
    #
    size = instr_size.size  # minimum instruction size (excludes required str null-terminator)
    for operand in instr.opcode.encoding:
        if operand == 't':
            # type list
            size += calcsize(f'<{len(instr.type_list):d}B')  # types
        elif operand == 's':
            # string data
            ## support multi codepage
            tmpstr = instr.string
            pattern = r"\[\[(.+?)\]\]"
            m = re.search(pattern, tmpstr)
            if m: tmpstr = re.sub(pattern, "", tmpstr)
            try:  # string + null terminator
                size += calcsize(f'<{len(tmpstr.encode("cp932"))+1:d}s')  
            except UnicodeEncodeError:
                size += calcsize(f'<{len(tmpstr.encode("cp936"))+1:d}s') 

        # elif operand == 'f':
        #     pass  # flags
        # elif operand == 'h':
        #     pass  # hash value
        # elif operand == 'o':
        #     pass  # variable offset
        # elif operand == '0':
        #     pass  # 4 byte address placeholder
        # elif operand == 'i':
        #     pass  # integer constant
        # elif operand == 'r':
        #     pass  # float constant
        # elif operand == 'a':
        #     pass  # argument count
        # elif operand == 'j':
        #     pass  # jump offset
        # elif operand == 'l':
        #     pass  # line number
        elif operand == 'c':
            # switch case table
            size += calcsize(f'<{len(instr.switch_cases):d}i')  # cases
        # else:
        #     raise Exception(f'unrecognized encoding specifier: {operand!r}')
    return size

#endregion


## IL PARSER/ASSEMBLER CLASS ##

class MjILAssembler:
    def __init__(self, filename:str, *, encoding:str='utf-8'):
        # IL script:
        self.script:MjoScript = MjoScript(MjoScript.SIGNATURE_DECRYPTED, None, 0, None, None, [], [])
        self.group_directive:Optional[str] = None
        self.resfile_directive:Optional[str] = None
        self.resource_dict:dict = None
        self.readmark_directive:Optional[bool] = None
        self.max_line:int = 0 # used for readmark enable

        # parsing:
        self.filename:str = filename
        self.encoding:str = encoding
        self.file:Optional[io.TextIOBase] = None
        self.line:Optional[str] = None
        self.pos:int = 0
        self.line_num:int = 0  # (MJIL FILE) 0 is none

        # IL storage:
        self.current_function:Optional[FunctionEntry] = None
        self.labels:Dict[str,Instruction] = OrderedDict()  # map of label name to index of next instruction
        self.unresolved_targets:Dict[str, Set[Instruction]] = {}
        self.current_labels:Set[str] = set()  # labels for the next instruction definition

        # special modes:
        self.is_block_comment:bool = False
        self.block_comment_line:Optional[int] = None
        self.block_comment_pos:Optional[int] = None
        self.is_eof:bool = False
        self.is_eol:bool = False
    #
    #region ## FILE OPEN/CLOSE ##
    #
    def close(self) -> bool:
        if self.file is not None:
            self.file.close()
            self.file = None
            return True
        return False
    def open(self) -> NoReturn:
        self.close()
        self.file = open(self.filename, 'rt', encoding=self.encoding)
        # self.line = None
        # self.pos = 0
        # self.line_num = 0
        # self.is_block_comment = False
        # self.is_eof = False
    #
    #endregion
    #
    #region ## PROPERTIES ##
    #
    @property
    def bytecode_pos(self) -> int:
        if not self.instructions:
            return 0
        instr = self.instructions[-1]
        return instr.offset + instr.size
    #
    @property
    def is_function(self) -> bool:
        return self.current_function is not None
    #
    @property
    def main_offset(self) -> Optional[int]:
        return self.script.main_offset
    @main_offset.setter
    def main_offset(self, main_offset:Optional[int]) -> NoReturn:
        self.script.main_offset = main_offset
    @property
    def bytecode_offset(self) -> Optional[int]:
        return self.script.bytecode_offset
    @bytecode_offset.setter
    def bytecode_offset(self, bytecode_offset:Optional[int]) -> NoReturn:
        self.script.bytecode_offset = bytecode_offset
    @property
    def bytecode_size(self) -> Optional[int]:
        return self.script.bytecode_size
    @bytecode_size.setter
    def bytecode_size(self, bytecode_size:Optional[int]) -> NoReturn:
        self.script.bytecode_size = bytecode_size
    #
    @property
    def line_count(self) -> int:
        return self.script.line_count
    @line_count.setter
    def line_count(self, line_count:int) -> NoReturn:
        self.script.line_count = line_count
    #
    @property
    def functions(self) -> List[FunctionEntry]:
        return self.script.functions
    @functions.setter
    def functions(self, functions:List[FunctionEntry]) -> NoReturn:
        self.script.functions = functions
    @property
    def instructions(self) -> List[Instruction]:
        return self.script.instructions
    @instructions.setter
    def instructions(self, instructions:List[Instruction]) -> NoReturn:
        self.script.instructions = instructions
    #
    #endregion
    #
    #region ## INLINE HASH ##
    #
    def inline_hash(self, name:str) -> int:
        if name[0] in '_%@#$':  # variable or function (not syscall)
            if name.find('@', 1) != -1:
                pass  # explicit group name, no extra handling
            elif name[0] == '_':  # local, group is always ""
                name += '@'  # implicit local group name
            elif self.group_directive is not None:
                name += f'@{self.group_directive}'
            else:
                raise Exception(f'Missing inline hash group for non-local {name!r} when group directive is \'none\'')
            # return zlib.crc32(name.encode('cp932'))
            return crypt.hash32(name)
        else:  # syscall
            #FIXME: Current syscall database always contains $ prefixes
            syscall = known_hashes.SYSCALLS_LOOKUP.get(f'${name}', None)
            if syscall is None:
                raise Exception(f'Inline hash syscall {name!s} could not be identied')
            return syscall
    #
    def inline_resource(self, name:str) -> str:
        if self.resfile_directive is None:
            raise Exception(f'Missing resfile directive, cannot lookup resource {name!r}')
        value = self.resource_dict.get(name, None)
        if value is None:
            raise Exception(f'Inline resource {name!s} could not be found')
        return value
    #
    def load_resources(self, resfile:str, *, delimiter:str=',', strict:bool=True, escaped:bool=False) -> dict:#, keyname:Union[str,int]='Key', valname:Union[str,int]='Value') -> dict:
        resources:dict = {}
        respath:str = os.path.join(os.path.dirname(self.filename), resfile)
        # keycol = keyname if isinstance(keyname, int) else None
        # valcol = valname if isinstance(valname, int) else None
        with open(respath, 'rt', encoding='utf-8') as f:
            print('Resources:')
            reader = csv.reader(f, delimiter=delimiter or ',')
            first = True
            for i,row in enumerate(reader):
                if not row: #TODO: is this possible?
                    continue
                if first:
                    keyname_, valname_ = row
                    print(keyname_, valname_)
                    first = False
                    if strict and tuple(r.lower() for r in row) != ('key', 'value'):
                        raise Exception(f'Invalid resource file {resfile!r}. Expected first row to have column names [\'Key\',\'Value\'], not {row!r}')
                    continue
                if not strict and len(row) == 1:
                    key, value = row[0], ''
                else:
                    key, value = row
                    if escaped:
                        value = unescape(value, not strict)
                if strict and key in resources:
                    raise Exception(f'Resource file {resfile!r} defines duplicate key {key!r} on line {(i+1)}')
                print(f'[{key!r}] {escape_ignorequotes(value)}')
                resources[key] = value
        return resources
    #
    #endregion
    #
    # def skipws(self, *, pos:int=..., peek:bool=False):
    #     if pos is Ellipsis: pos = self.pos
    #     token = self.parse_token(pos=pos, peek=True)
    #     while token.type is TokenType.WHITESPACE:
    #         pos = token.end
    #         if not peek:
    #             self.pos = pos
    #         token = self.parse_token(pos=pos, peek=True)
    #     return token.end
    #
    def next_line(self) -> bool:
        if self.is_eof:
            return False  # EOF
        self.is_eol = False
        self.line = self.file.readline()
        self.line_num += 1
        # print(f'{self.line_num} : ', end='')
        self.pos = 0
        if not self.line:
            self.is_eol = True
            self.is_eof = True
            return False  # EOF
        
        self.line = self.line.rstrip('\r\n')
        if not self.line:
            self.is_eol = True
        elif self.is_block_comment:
            # skip beginning whitespace
            self._next_token_handle_ws(self.pos)
        return True
    #
    def _next_token_handle_ws(self, pos:int=...) -> Optional[ParseToken]:
        """If the next token is whitespace, any directly-connected comments
        are merged into a single token.
        """
        if pos is Ellipsis: pos = self.pos
        end = pos
        token_type:TokenType = None

        if self.is_block_comment:
            RE_COMMENT_END = re.compile(r"^.*(\*\/)")
            m:Match = RE_COMMENT_END.search(self.line[pos:])
            if m:
                end = m.end() + pos
                self.is_block_comment = False
                self.block_comment_line = None
                self.block_comment_pos = None
                token_type = TokenType.WHITESPACE
            else:
                end = pos
                self.is_eol = True
                token_type = TokenType.EOL

        if not self.is_block_comment:
            # specially handle whitespace and normalize comments
            RE_ALL_WHITESPACE = re.compile(r"^(?:(\s+)|(\/\*[^\n]*?\*\/)|((?:\/\/|;).*$)|(\/\*)|($))")#|(.*\*\/)")
            # if not isinstance(pos, int): print(f'pos type is {pos.__class__.__name__}')
            m:Match = RE_ALL_WHITESPACE.search(self.line[pos:])
            while m:
                if m[1]:  # whitespace
                    end = m.end() + pos
                    token_type = TokenType.WHITESPACE
                elif m[2]:  # inline comment
                    # pad with whitespace to preserve character position
                    #space = re.sub(r"[^\r\n]", r" ", self.line[m.start()+pos:m.end()+pos])
                    #self.line = space.join( (self.line[:m.start()+pos], self.line[m.end()+pos:]) )
                    end = m.end() + pos
                    token_type = TokenType.WHITESPACE # inline-comments constitute whitespace (even if VSCode doesn't show it)
                elif m[3]:  # line comment (EOL)
                    # self.line = self.line[:m.start()+pos]
                    end = m.start() + pos
                    self.is_eol = True
                    token_type = TokenType.EOL
                    break  # break, we're done
                elif m[4]:  # open block comment (EOL+)
                    # self.line = self.line[:m.start()+pos]
                    end = m.start() + pos
                    self.is_eol = True
                    self.is_block_comment = True
                    self.block_comment_line = self.line_num
                    self.block_comment_pos = m.start() + pos
                    token_type = TokenType.EOL
                    break  # break, we're done
                elif m[5] is not None: # EOL
                    end = m.start() + pos
                    self.is_eol = True
                    token_type = TokenType.EOL
                    break  # break, we're done
                # next match
                m = RE_ALL_WHITESPACE.search(self.line[m.end()+pos:])

        if token_type is TokenType.WHITESPACE:
            # only when there's non-whitespace left on the line
            token = ParseToken(token_type, self.line[pos:end], self.line, self.line_num, pos, end)
            parse_whitespace(token)
            self.pos = token.end
            return token
        elif token_type is TokenType.EOL:
            # fudge the numbers for poorly written token parsing :)
            token = ParseToken(token_type, '', self.line, self.line_num, pos, pos)
            parse_eol(token)
            self.pos = token.end
            return token
        return None # not whitespace, carry on~

    def next_token(self, pos:int=...) -> ParseToken:
        """parse and return the next token.
        """
        if pos is Ellipsis: pos = self.pos
        if self.is_eol or self.is_eof: #TODO: remove is_eof check?
            token = ParseToken(TokenType.EOL, '', self.line, self.line_num, pos, pos)
            parse_eol(token)
            if self.is_eof:
                token.kind = TokenKind.EOF
            else:
                token.kind = TokenKind.EOL
            return token

        # specially handle whitespace and normalize comments
        token = self._next_token_handle_ws(pos)
        if token is not None:
            self.pos = token.end
            return token

        # try to match normal tokens
        for token_type,(pattern,parser) in MATCHING.items():
            m:Match = pattern.search(self.line[pos:])
            if m:
                # if 'func' in m[0] or 'void' in m[0]:
                #     input('found it!')
                token = ParseToken(token_type, m, self.line, self.line_num, m.start()+pos, m.end()+pos)
                self.pos = token.end
                parser(token)  # extracts token value
                return token
        print(f'failed to find token type at line {self.line_num}, pos {pos+1}\n{self.line!s}')
        print(' ' * pos + '^')
        raise Exception(f'failed to find token type at line {self.line_num}, pos {pos+1}\n{self.line!r}')

    def next_token_skipws(self, nextline:bool=False) -> ParseToken:
        token:TokenType = self.next_token()
        while token.type is TokenType.WHITESPACE or (token.kind is TokenKind.EOL and nextline):
            if token.kind is TokenKind.EOL:
                self.next_line()
            token = self.next_token()
        return token

    def begin_function(self, func_token:ParseToken):
        if self.current_function is not None:
            raise Exception('attempted to declare new function while previous has not been closed')
        self.require_ws(func_token)
        # token = self.next_token()
        # if token.type is not TokenType.WHITESPACE:
        #     raise Exception(f'no whitespace after function {func_token.text!r} keyword')
        hash_token = token = self.next_token()
        if token.type is not TokenType.HASH:
            raise Exception(f'expected hash name after function {func_token.text!r} keyword')
        if token.kind is TokenKind.INLINE_HASH:
            token.value = self.inline_hash(token.value)
            token.kind = TokenKind.LITERAL_HASH
        function = FunctionEntry(token.value, self.bytecode_pos)
        token = self.next_token_skipws(nextline=True)
        if token.type is not TokenType.PUNCTUATION or token.value != '(':
            raise Exception(f'expected function argument declarations for {func_token.text!r} {hash_token.value!r}')
        token = self.next_token_skipws(nextline=True)
        type_list:list = []  # not actually used
        last_type = None
        while token.type is not TokenType.PUNCTUATION or token.value != ')':
            if token.type is TokenType.PUNCTUATION:
                if token.value != ',':
                    raise Exception(f'unexpected punctuation {token.value!r} during function parameter declaration during {func_token.text!r} {hash_token.value!r}')
                elif last_type is None:
                    raise Exception(f'unexpected punctuation {token.value!r}, no type since last punctuation during {func_token.text!r} {hash_token.value!r}')
                else:
                    last_type = None
            elif token.kind is TokenKind.TYPE:
                if last_type is not None:
                    raise Exception(f'unexpected type {token.value!r} during function parameter declaration without comma separator during {func_token.text!r} {hash_token.value!r}')
                else:
                    last_type = token.value
                    type_list.append(token.value)
            else:
                raise Exception(f'unexpected token during function declaration parsing {token!r} during {func_token.text!r} {hash_token.value!r}')
            token = self.next_token_skipws(nextline=True)
        if type_list and last_type is None:
            raise Exception(f'unexpected extra punctuation \',\' before closing type list during {func_token.text!r} {hash_token.value!r}')

        # check for potential entrypoint directive
        token = self.next_token_skipws(nextline=True)
        if token.kind is TokenKind.DIRECTIVE and token.value == 'entrypoint': #TODO: don't use hardcoded names here
            if self.main_offset is not None:
                raise Exception(f'more than one entrypoint defined during {func_token.text!r} {hash_token.value!r}')
            self.main_offset = self.bytecode_pos
            token = self.next_token_skipws(nextline=True)
        

        if token.type is not TokenType.PUNCTUATION or token.value != '{':
            raise Exception(f'expected function opening brace after parameters declarations for {func_token.text!r} {hash_token.value!r}')

        self.require_eol(token)
        self.current_function = function
        self.functions.append(function)
        #TODO: clear label caches, and start anew
        
    def end_function(self, end_token:ParseToken):
        if self.current_function is None:
            raise Exception(f'closing {end_token.value!r} found without starting function')
        self.require_eol(end_token)
        self.current_function = None
        if self.current_labels:
            raise Exception(f'{len(self.current_labels)} labels defined with no next instruction at end of function')
        if self.unresolved_targets:
            def fmt_instr(i:Instruction):
                if i.opcode.mnemonic == "switch":
                    return f'{i.offset:05x}: {i.opcode.mnemonic} {i.switch_targets!r}'
                else:
                    return f'{i.offset:05x}: {i.opcode.mnemonic} {i.jump_target!r}'
            for s in self.unresolved_targets.values():
                print(', '.join(repr(fmt_instr(i)) for i in s))
            #print(list(f'{i.offset:05x}: {i.opcode.mnemonic} self.unresolved_targets.values()))
            raise Exception(f'{len(self.unresolved_targets)} unresolved targets defined with no label found by end of function')
        self.unresolved_targets.clear()
        self.current_labels.clear()
        self.labels.clear()
        #TODO: clear label caches and enforce that all referenced labels are identified

    def require_eol(self, last_token:ParseToken):
        token = self.next_token() #_skipws()
        if token.type is not TokenType.EOL:
            raise Exception(f'expected end of line after last token {last_token!r}, not token {token!r}')
    def require_ws(self, last_token:ParseToken):
        token = self.next_token() #_skipws()
        if token.type is not TokenType.WHITESPACE:
            raise Exception(f'expected whitespace after previous token {last_token!r}, not token {token!r}')


    def parse_line(self):
        if not self.next_line():
            return False  # EOF

        token = self.next_token_skipws()
        if token.type is TokenType.EOL:
            return
        if token.kind is TokenKind.DIRECTIVE:
            if token.value in ('readmark', 'group', 'resfile'):
                directive = token
                self.require_ws(directive)
                token = self.next_token()
                if token.kind is TokenKind.DIRECTIVE_ARG:
                    if directive.value == 'group':
                        if token.value is not None:
                            raise Exception(f'invalid argument {token.text!r} for {directive.value} directive')
                        self.group_directive = token.value
                    elif directive.value == 'resfile':
                        if token.value is not None:
                            raise Exception(f'invalid argument {token.text!r} for {directive.value} directive')
                        self.resfile_directive = token.value
                        self.resource_dict = None #TODO: unload this?
                    else:
                        if token.value is None:
                            raise Exception(f'invalid argument {token.text!r} for {directive.value} directive')
                        if self.readmark_directive is not None:
                            raise Exception(f'readmark directive already previously defined as {self.readmark_directive!r}')
                        self.readmark_directive = token.value
                elif token.kind is TokenKind.LITERAL_STRING and directive.value in ('group', 'resfile'):
                    if directive.value == 'group':
                        if '@' in token.value:
                            raise Exception(f'group directive cannot contain \'@\' character')
                        self.group_directive = token.value
                    else: #elif directive.value == 'resfile':
                        if not token.value:
                            raise Exception(f'empty resfile directive name')
                        self.resource_dict = self.load_resources(token.value, strict=True)
                        self.resfile_directive = token.value
                else:
                    raise Exception(f'unexpected token {token!r} for {directive.value} directive')
                self.require_eol(directive)
            elif token.value == 'entrypoint':
                raise Exception(f'misplaced entrypoint directive without function declaration')
        elif token.kind is TokenKind.FUNC:
            # print('start function')
            # input('start function!')
            self.begin_function(token)
        elif self.is_function:
            if token.type is TokenType.PUNCTUATION and token.value == '}':
                self.end_function(token)
                # if token.value == '}':
                #     if self.current_function is not None:
                #         self.current_function
                # if token.value in '{}': # be lazy for now and ignore WEEEE~~
                #     token = self.next_token_skipws()
            while token.type is TokenType.LABEL:
                ##TODO: is it legal to stack multiple labels on the same line?
                ##TODO: handle labels
                self.current_labels.add(token.value)
                token = self.next_token_skipws()
            if token.kind is TokenKind.OPCODE_INVERT:
                token.kind = TokenKind.OPCODE
                token.value = token.value[0] # (opcode, invert)
                
            if token.kind is TokenKind.OPCODE: # or token.kind is TokenKind.OPCODE_INVERT:
                # begin next instruction
                self.parse_instruction(token)
        else:
            raise Exception(f'unexpected token {token!r} while parsing line')
    def define_target(self, target_name:str, instr:Instruction) -> Optional[Instruction]:
        label_instr = self.labels.get(target_name, None)
        if label_instr is not None:
            return label_instr
        
        self.unresolved_targets.setdefault(target_name, set())
        self.unresolved_targets[target_name].add(instr)

    def define_label(self, label_name:str, instr:Instruction):
        # clearing label from current_labels is handled by the parent caller
        self.labels[label_name] = instr

        targets = self.unresolved_targets.get(label_name, None)
        if targets is None:
            return # nothing to do
        
        for target_instr in targets:
            for operand in target_instr.opcode.encoding:
                if operand == 'j':
                    # jump offset
                    jump = target_instr.jump_target
                    if isinstance(jump, str) and jump == label_name:
                        # if target_instr.jump_target == label_name:
                        target_instr.jump_target = instr
                        target_instr.jump_offset = instr.offset - target_instr.offset - target_instr.size
                elif operand == 'c':
                    # case offsets
                    for i,case in enumerate(target_instr.switch_targets):
                        if isinstance(case, str) and case == label_name:
                            target_instr.switch_targets[i] = instr
                            target_instr.switch_cases[i] = instr.offset - target_instr.offset - 4 - 4 - (i * 4)
        
        del self.unresolved_targets[label_name]

    def parse_instruction(self, opcode_token:ParseToken):
        opcode = opcode_token.value
        instr:Instruction = Instruction(opcode, self.bytecode_pos)
        for label_name in self.current_labels:
            self.define_label(label_name, instr)
        self.current_labels.clear()

        # for operand in instr.opcode.encoding:
        # opcode_value:int = reader.unpackone('<H')
        # opcode:Opcode = Opcode.BYVALUE.get(opcode_value, None)
        # if not opcode:
        #     raise Exception('Invalid opcode found at offset 0x{:08X}: 0x{:04X}'.format(offset, opcode_value))
        # instruction:Instruction = Instruction(opcode, offset)
        last_token = token = opcode_token
        if opcode.encoding:
            self.require_ws(last_token)
            token = self.next_token()
        for j,operand in enumerate(opcode.encoding):
            if operand == 't':
                # type list
                # if token.type is not TokenType.PUNCTUATION and token.value != '[':
                #     raise Exception(f'Expected opening \'[\' for start of type list operand, not token {token!r}')
                #     token = self.next_token_skipws(nextline=True)
                if token.type is not TokenType.PUNCTUATION or token.value != '[':
                    raise Exception(f'Expected opening \'[\' for start of type list operand, not token {token!r}')
                token = self.next_token_skipws(nextline=True)
                type_list:list = []  # not actually used
                last_type = None
                while token.type is not TokenType.PUNCTUATION or token.value != ']':
                    if token.type is TokenType.PUNCTUATION:
                        if token.value != ',':
                            raise Exception(f'unexpected punctuation {token.value!r} during type list operand')
                        elif last_type is None:
                            raise Exception(f'unexpected punctuation {token.value!r}, no type since last punctuation during type list operand')
                        else:
                            last_type = None
                    elif token.kind is TokenKind.TYPE:
                        if last_type is not None:
                            raise Exception(f'unexpected type {token.value!r} during type list operand without comma separator')
                        else:
                            last_type = token.value
                            type_list.append(token.value)
                    else:
                        raise Exception(f'unexpected token during type list operand parsing, got {token!r}')
                    token = self.next_token_skipws(nextline=True)
                if type_list and last_type is None:
                    raise Exception(f'unexpected extra punctuation \',\' before closing type list operand')
                instr.type_list = type_list
            elif operand == 's':
                # string data
                # self.require_ws(last_token)
                # token = self.next_token()
                if token.type is TokenType.RESOURCE:
                    #NOTE: Currently inline resource lookup function is only use of resource
                    instr.string = self.inline_resource(token.value)
                elif token.type is TokenType.STRING:
                    instr.string = token.value
                else:
                    raise Exception(f'expected string operand, not token {token!r}')
            elif operand == 'f':
                # flags
                invert:MjoInvert = None
                modifier:MjoModifier = None
                vartype:MjoType = None
                scope:MjoScope = None
                dimension:int = None
                # self.require_ws(last_token)
                # last_token = token = self.next_token()
                while token.type is not TokenType.HASH:
                    if token.kind is TokenKind.OPCODE_INVERT:
                        token.kind = TokenKind.INVERT
                        token.value = token.value[1]  # (opcode, invert)
                    if token.kind is TokenKind.INVERT:
                        if invert is not None:
                            raise Exception(f'invert flag already defined as {invert!r}, got {token!r}')
                        invert = token.value
                    elif token.kind is TokenKind.MODIFIER:
                        if modifier is not None:
                            raise Exception(f'modifier flag already defined as {modifier!r}, got {token!r}')
                        modifier = token.value
                    elif token.kind is TokenKind.TYPE:
                        if vartype is not None:
                            raise Exception(f'var type flag already defined as {vartype!r}, got {token!r}')
                        vartype = token.value
                    elif token.kind is TokenKind.SCOPE:
                        if scope is not None:
                            raise Exception(f'scope flag already defined as {scope!r}, got {token!r}')
                        scope = token.value
                        # print(f'scope = {token.value} {token!r}')
                    elif token.kind is TokenKind.DIMENSION:
                        if dimension is not None:
                            raise Exception(f'dimension flag already defined as {dimension!r}, got {token!r}')
                        dimension = token.value
                    else:
                        raise Exception(f'unexpected token {token!r} while reading var flags, expected flag or hash')
                        
                    self.require_ws(last_token)
                    last_token = token = self.next_token()
                if invert is None:
                    invert = MjoInvert.NONE
                if modifier is None:
                    modifier = MjoModifier.NONE
                if dimension is None:
                    if opcode.mnemonic.startswith('ldelem') or opcode.mnemonic.startswith('stelem'):
                        raise Exception(f'dimension flag is required for {opcode.mnemonic} instructions flags operand')
                    dimension = 0
                if scope is None:
                    raise Exception(f'scope flag is required for flags operand')
                if vartype is None:
                    raise Exception(f'var type flag is required for flags operand')
                
                instr.flags = MjoFlags.fromflags(scope=scope, type=vartype, dimension=dimension, modifier=modifier, invert=invert)

                continue # force continue since we already have the next operand (essential since we read until not a flag)
                # hash_token = token
                # if token.kind is TokenKind.INLINE_HASH:
                #     token.kind = TokenKind.LITERAL_HASH
                #     token.value = self.inline_hash(token.value)

                # token = self.next_token()
                # if token.type is TokenType.EOL:
                #     if scope is 



                # instruction.flags = MjoFlags(reader.unpackone('<H'))
            elif operand == 'h':
                # hash value
                if token.type is not TokenType.HASH:
                    raise Exception(f'expected hash operand, not token {token!r}')
                if token.kind is TokenKind.INLINE_HASH:
                    token.kind = TokenKind.LITERAL_HASH
                    token.value = self.inline_hash(token.value)
                instr.hash = token.value
                if 'o' in opcode.encoding: # has var offset
                    # special behavior, continue now and let var offset handle reading its own token
                    continue
            elif operand == 'o':
                # variable offset
                required = instr.flags.scope is MjoScope.LOCAL
                instr.var_offset = -1 # default until handled
                if required:
                    self.require_ws(last_token)
                    last_token = token = self.next_token()
                    if token.type is not TokenType.INT:
                        raise Exception(f'expected variable offset operand for local scope, not token {token!r}')
                    instr.var_offset = token.value
                else:
                    token = self.next_token()
                    if token.type is TokenType.EOL:
                        # implicit -1 var offset
                        instr.var_offset = -1
                    elif token.type is not TokenType.WHITESPACE:
                        raise Exception('unexpected token {token!r} when looking for optional var offset, must be EOL or whitespace before var offset')
                    else:
                        last_token = token = self.next_token()
                        if token.type is not TokenType.INT:
                            raise Exception(f'expected variable offset operand after hash after whitespace, not token {token!r}')
                        instr.var_offset = token.value
                # instruction.var_offset = reader.unpackone('<h')
            elif operand == '0':
                # 4 byte address placeholder
                # instr.
                # not even stored by instruction, so we don't do anything
                continue  # continue because we haven't consumed this token
                # assert(reader.unpackone('<I') == 0)
            elif operand == 'i':
                # integer constant
                if token.kind is TokenKind.INLINE_HASH:
                    token.kind = TokenKind.LITERAL_HASH
                    token.value = self.inline_hash(token.value) #TODO: inline hash function should really be handled during parsing...
                if token.type not in (TokenType.INT, TokenType.HASH):
                    raise Exception(f'expected integer literal or hash operand, not token {token!r}')
                instr.int_value = signed_i(token.value)
            elif operand == 'r':
                # float constant
                if token.type is TokenType.INT:
                    instr.float_value = float(token.value)
                elif token.type is TokenType.FLOAT:
                    instr.float_value = token.value
                else:
                    raise Exception(f'expected float literal operand, not token {token!r}')
            elif operand == 'a':
                # argument count
                if token.type is not TokenType.PUNCTUATION or token.value != '(':
                    raise Exception(f'expected opening \'(\' for argument count, not token {token!r}')
                last_token = token = self.next_token_skipws()
                if token.type is not TokenType.INT:
                    raise Exception(f'expected integer argument count, not token {token!r}')
                instr.argument_count = token.value
                last_token = token = self.next_token_skipws()
                if token.type is not TokenType.PUNCTUATION or token.value != ')':
                    raise Exception(f'expected closing \')\' for argument count, not token {token!r}')
            elif operand == 'j':
                # jump offset
                if token.type is not TokenType.TARGET:
                    raise Exception(f'expected jump target operand, not token {token!r}')
                if token.kind is TokenKind.OFFSET:
                    # explicit offset, no label handling
                    instr.jump_offset = token.value
                    instr.jump_target = None
                else:
                    label_instr = self.define_target(token.value, instr)
                    if label_instr is not None:
                        instr.jump_offset = label_instr.offset - instr.offset - instruction_size(instr)
                        instr.jump_target = label_instr
                    else:
                        instr.jump_target = token.value
            elif operand == 'l':
                # line number
                if token.type is not TokenType.LINE_NUMBER:
                    raise Exception(f'expected line number operand #NNNN, not token {token!r}')
                instr.line_number = token.value
                self.max_line = max(self.max_line, instr.line_number)
            elif operand == 'c':
                # switch case table
                # cases = []
                last_case = None
                no_brace = token.type is not TokenType.PUNCTUATION or token.value != '['
                # if token.type is not TokenType.PUNCTUATION or token.value != '[':
                #     raise Exception(f'Expected opening \'[\' for start of type list operand, not token {token!r}')
                if not no_brace:
                    last_token = token = self.next_token_skipws(nextline=True)
                case_list:list = []  # not actually used
                last_case = None
                i = 0
                instr.switch_targets = []
                instr.switch_cases = []
                while (token.type is not TokenType.PUNCTUATION or token.value != ']') and token.type is not TokenType.EOL:
                    if token.type is TokenType.PUNCTUATION:
                        if token.value != ',':
                            raise Exception(f'unexpected punctuation {token.value!r} during switch case list operand')
                        elif last_case is None:
                            raise Exception(f'unexpected punctuation {token.value!r}, no case target since last punctuation during switch case list operand')
                        else:
                            last_case = None
                    elif token.type is TokenType.TARGET:
                        if last_case is not None:
                            raise Exception(f'unexpected switch case {token.value!r} during switch case list operand without comma separator')
                        else:
                            last_case = token.value
                            case_list.append(last_case)
                            if token.kind is TokenKind.OFFSET:
                                # explicit offset, no label handling
                                instr.switch_cases.append(token.value)
                                instr.switch_targets.append(None)
                            else:
                                label_instr = self.define_target(token.value, instr)
                                if label_instr is not None:
                                    instr.switch_cases.append(label_instr.offset - instr.offset - 4 - 4 - (i * 4))
                                    instr.switch_targets.append(label_instr)
                                else:
                                    instr.switch_cases.append(None)
                                    instr.switch_targets.append(token.value)
                        i += 1
                    else:
                        raise Exception(f'unexpected token during switch case list operand parsing, got {token!r}')

                    token = self.next_token_skipws(nextline=not no_brace)
                if case_list and last_case is None:
                    raise Exception(f'unexpected extra punctuation \',\' before closing switch case list operand')
                ##TODO: Proper handling of []'s or no []'s for switch cases, right now it just thinks of them as a common courtasy
            else:
                raise Exception('Unrecognized encoding specifier: {!r}'.format(operand))
            if j + 1 < len(opcode.encoding):
                if not self.is_eol:
                    self.require_ws(last_token)
                last_token = token = self.next_token()
        
        instr.size = instruction_size(instr) # calculates size of variable-length operands
        self.require_eol(token)
        self.instructions.append(instr)

        # RE_COMMENT_INLINE  = re.compile(r"^(\/\*[^\n]*?\*\/)")
        # token:ParseToken = self.parse_token_skipws()
        # if token.type in (TokenType.EOL, TokenType.COMMENT):
        #     return True
        # if token.type is TokenType.WHITESPACE:
        #     pass # shouldn't happen
        # elif token.type is TokenType.PREPROCESSOR:
        #     self.parse_preprocessor(token)
        # #FIXME: screw it, we'll parse function signatures and variables regardless, WE WANT THOSE HASHES!
        # # elif self.pre_ignore:
        # #     return True
        # elif token.type is TokenType.KEYWORD:
        #     if token.text in ('void', 'func'):
        #         self.parse_funcsig(token)
        #     elif token.text == 'var':
        #         self.parse_varsig(token)
        # #FIXME: Moved below function/variable parsing for ALL THE HASHES!
        # elif self.pre_ignore:
        #     return True
        # else:
        #     pass # do fuck-all about everything else
        
        return True
    #
    
    def read(self):
        self.open() #self.filename, encoding=self.encoding)
        # this is stuuupiiiiiiiid
        self.parse_line()
        while not self.is_eof:
            self.parse_line()
        self.close()
        self.bytecode_offset = calcsize(f'<16sIII{len(self.functions)}I')
        self.bytecode_size = self.bytecode_pos
        self.line_count = self.max_line if self.readmark_directive else 0


# class Assembler:
#     def __init__(self):
#         self.group_directive:Optional[str] = None
#         self.readmark_directive:Optional[bool] = None
#         self.main_offset:Optional[int] = None
#         self.line_count:int = 0  # 0 is default

# def tryit(filename:str, encoding:str='utf-8') -> ControlFlowGraph:
# def tryit(filename:str, encoding:str='utf-8') -> MjoScript:
#     print('Something need doing?')
#     assembler = MjILAssembler(filename, encoding=encoding)
#     print('Work work...')
#     assembler.read()
#     print(f'Job done!\nRead {len(assembler.instructions)} instructions and {len(assembler.functions)} functions')

#     # script = assembler.script
#     # with open(filename + '.assembler.mjo', 'wb+') as f:
#     #     f.write(struct.pack('<16sIII', script.signature, script.main_offset, script.line_count, len(script.functions)))
#     #     for fn in script.functions:
#     #         f.write(struct.pack('<II', *fn))  # fn.name_hash, fn.offset
#     #     f.write(struct.pack('<I', script.bytecode_size))
#     #     for instr in script.instructions:
#     #         offset = f.tell()
#     #         opcode = instr.opcode
#     #         f.write(struct.pack('<H', opcode.value))
#     #         for operand in opcode.encoding:
#     #             if operand == 't':
#     #                 # type list
#     #                 f.write(struct.pack('<H', len(instr.type_list)))  # count
#     #                 f.write(struct.pack(f'<{len(instr.type_list)}B', *[t.value for t in instr.type_list]))  # types
#     #                 # count = reader.unpackone('<H')
#     #                 # instruction.type_list = [MjoType(b) for b in reader.unpack('<{:d}B'.format(count))]
#     #             elif operand == 's':
#     #                 # string data
#     #                 f.write(struct.pack('<H', len(instr.string.encode("cp932"))+1))  # size + null terminator
#     #                 f.write(struct.pack(f'<{len(instr.string.encode("cp932"))+1}s', instr.string.encode("cp932")))  # string + null terminator
#     #                 # size = reader.unpackone('<H') 
#     #                 # instruction.string = reader.read(size).rstrip(b'\x00').decode('cp932')
#     #             elif operand == 'f':
#     #                 # flags
#     #                 f.write(struct.pack('<H', int(instr.flags)))  #currently flags is a type that subclasses int, but do this anyway
#     #                 # instruction.flags = MjoFlags(reader.unpackone('<H'))
#     #             elif operand == 'h':
#     #                 # hash value
#     #                 if instr.hash < 0:  # this shouldn't happen... buuuuut
#     #                     instr.hash &= 0xffffffff
#     #                 f.write(struct.pack('<I', instr.hash))  # hash value
#     #                 # instruction.hash = reader.unpackone('<I')
#     #             elif operand == 'o':
#     #                 # variable offset
#     #                 f.write(struct.pack('<h', instr.var_offset))
#     #                 # instruction.var_offset = reader.unpackone('<h')
#     #             elif operand == '0':
#     #                 # 4 byte address placeholder
#     #                 f.write(struct.pack('<I', 0))  # 4 byte address placeholder
#     #                 # assert(reader.unpackone('<I') == 0)
#     #             elif operand == 'i':
#     #                 # integer constant
#     #                 f.write(struct.pack('<i', signed_i(instr.int_value)))  # integer constant
#     #                 # instruction.int_value = reader.unpackone('<i')
#     #             elif operand == 'r':
#     #                 # float constant
#     #                 f.write(struct.pack('<f', instr.float_value))  # float constant
#     #                 # instruction.float_value = reader.unpackone('<f')
#     #             elif operand == 'a':
#     #                 # argument count
#     #                 f.write(struct.pack('<H', instr.argument_count))  # argument count
#     #                 # instruction.argument_count = reader.unpackone('<H')
#     #             elif operand == 'j':
#     #                 # jump offset
#     #                 f.write(struct.pack('<i', instr.jump_offset))  # jump offset
#     #                 # instruction.jump_offset = reader.unpackone('<i')
#     #             elif operand == 'l':
#     #                 # line number
#     #                 f.write(struct.pack('<H', instr.line_number))  # line number
#     #                 # instruction.line_number = reader.unpackone('<H')
#     #             elif operand == 'c':
#     #                 # switch case table
#     #                 f.write(struct.pack('<H', len(instr.switch_cases)))  # count
#     #                 f.write(struct.pack(f'<{len(instr.switch_cases)}i', *instr.switch_cases))  # cases
#     #                 # count = reader.unpackone('<H')
#     #                 # instruction.switch_cases = list(reader.unpack('<{:d}i'.format(count)))
#     #             else:
#     #                 raise Exception('Unrecognized encoding specifier: {!r}'.format(operand))
#     #         assert(instr.size == (f.tell() - offset)), f'{instr.offset:05x}: {opcode.mnemonic}'
                
#     #     f.flush()
#     # cfg:ControlFlowGraph = ControlFlowGraph.build_from_script(assembler.script)
#     # return cfg
#     return assembler.script