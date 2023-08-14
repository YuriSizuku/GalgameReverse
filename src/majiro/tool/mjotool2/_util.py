#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Utility classes and functions
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'

__all__ = ['StructIO', 'Colors', 'DummyColors', 'hd_span', 'print_hexdump']

#######################################################################################

import io, re, struct
from collections import namedtuple
from struct import calcsize, pack, unpack
from types import SimpleNamespace
from typing import Any, List, Match, NoReturn, Union

#region ## FILE HELPERS ##

class StructIO:
    """IO wrapper with built-in struct packing and unpacking.
    """
    __slots__ = ('_stream')
    def __init__(self, stream:Union[io.BufferedReader, io.BufferedWriter, io.BufferedRandom]):
        self._stream = stream
    def __getattr__(self, name):
        return self._stream.__getattribute__(name)
    def length(self) -> int:
        position = self._stream.tell()
        self._stream.seek(0, 2)
        length = self._stream.tell()
        self._stream.seek(position, 0)
        return length
    def unpack(self, fmt:str) -> tuple:
        return unpack(fmt, self._stream.read(calcsize(fmt)))
    def unpackone(self, fmt:str) -> Any:
        return unpack(fmt, self._stream.read(calcsize(fmt)))[0]
    def pack(self, fmt:str, *v) -> NoReturn:
        return self._stream.write(pack(fmt, *v))

#endregion

#region ## INT SIGNEDNESS HELPERS ##

def signed_b(num:int) -> int:
    """Return signed value of unsigned (or signed) 8-bit integer (struct fmt 'b')
    also performs bounds checking
    """
    if num > 0x7f: # greater than SCHAR_MAX
        return unpack('=b', pack('=B', num))[0]
    else: # lazy limits bounds checking
        return unpack('=b', pack('=b', num))[0]

def unsigned_B(num:int) -> int:
    """Return unsigned value of signed (or unsigned) 8-bit integer (struct fmt 'B')
    also performs bounds checking
    """
    if num < 0: # signed
        return unpack('=B', pack('=b', num))[0]
    else: # lazy limits bounds checking
        return unpack('=B', pack('=B', num))[0]

def signed_h(num:int) -> int:
    """Return signed value of unsigned (or signed) 16-bit integer (struct fmt 'h')
    also performs bounds checking
    """
    if num > 0x7fff: # greater than SHRT_MAX
        return unpack('=h', pack('=H', num))[0]
    else: # lazy limits bounds checking
        return unpack('=h', pack('=h', num))[0]

def unsigned_H(num:int) -> int:
    """Return unsigned value of signed (or unsigned) 16-bit integer (struct fmt 'H')
    also performs bounds checking
    """
    if num < 0: # signed
        return unpack('=H', pack('=h', num))[0]
    else: # lazy limits bounds checking
        return unpack('=H', pack('=H', num))[0]

def signed_i(num:int) -> int:
    """Return signed value of unsigned (or signed) 32-bit integer (struct fmt 'i')
    also performs bounds checking
    """
    if num > 0x7fffffff: # greater than INT_MAX
        return unpack('=i', pack('=I', num))[0]
    else: # lazy limits bounds checking
        return unpack('=i', pack('=i', num))[0]

def unsigned_I(num:int) -> int:
    """Return unsigned value of signed (or unsigned) 32-bit integer (struct fmt 'I')
    also performs bounds checking
    """
    if num < 0: # signed
        return unpack('=I', pack('=i', num))[0]
    else: # lazy limits bounds checking
        return unpack('=I', pack('=I', num))[0]

def signed_q(num:int) -> int:
    """Return signed value of unsigned (or signed) 64-bit integer (struct fmt 'q')
    also performs bounds checking
    """
    if num > 0x7fffffffffffffff: # greater than LLONG_MAX
        return unpack('=q', pack('=Q', num))[0]
    else: # lazy limits bounds checking
        return unpack('=q', pack('=q', num))[0]

def unsigned_Q(num:int) -> int:
    """Return unsigned value of signed (or unsigned) 64-bit integer (struct fmt 'Q')
    also performs bounds checking
    """
    if num < 0: # signed
        return unpack('=Q', pack('=q', num))[0]
    else: # lazy limits bounds checking
        return unpack('=Q', pack('=Q', num))[0]

#endregion

#region ## STRING HELPERS ##

def strip_ansi(string:str) -> str:
    r"""Strips all basic terminal ANSI "\x1b[...m" escapes from a string
    """
    return re.sub(r"\x1b\[[^m]m", r"", string)

def len_ansi(string:str) -> int:
    r"""Measures the length of a string with all  terminal ANSI "\x1b[...m" escapes removed
    """
    return len(strip_ansi(string))

def repl_tabs(string:str, tab_size:int=4, space:str=' ') -> str:
    """Replace tabs in a string with accurate space equivalents
    
    Does NOT handle proper spacing of fullwidth characters or emoji
    """
    if tab_size == 1:
        return string.replace('\t', space) # no difference
    indent = 0
    parts = []

    last_tab = 0  # stored as idx+1 for easier math
    tab = string.find('\t')
    while tab != -1:
        if tab != last_tab:  # append normal string parts
            indent += tab - last_tab
            parts.append(string[last_tab:tab])

        new_indent = (indent // tab_size + 1) * tab_size
        parts.append(space * (new_indent - indent))
        indent = new_indent

        last_tab = tab + 1  # store as idx+1 for easier math
        tab = string.find('\t', tab + 1)

    if not parts:
        return string  # no tabs

    if last_tab != len(string):  # append final string part
        parts.append(string[last_tab:])
    return ''.join(parts)

def len_tabs(string:str, tab_size:int=4) -> int:
    """Measures the length of a string with all tabs converted to spacing of a specified width

    Does NOT handle proper spacing of fullwidth characters or emoji
    """
    if tab_size == 1:
        return len(string) # no difference
    indent = 0

    last_tab = 0  # stored as idx+1 for easier math
    tab = string.find('\t')
    while tab != -1:
        indent = ((indent + tab - last_tab) // tab_size + 1) * tab_size
    
        last_tab = tab + 1  # store as idx+1 for easier math
        tab = string.find('\t', tab + 1)

    indent += len(string) - last_tab
    return indent

def doublequote(string:str, is_repr:bool=False) -> str:
    """Doublequote (Python) string representation
    """
    if not is_repr: string = repr(string)
    # remove current quotes to avoid accidental escaping
    string = string[1:-1]
    # this pattern ensures ignoring any leading escaped backslashes
    # unescape single-quotes
    string = re.sub(r'''(?<!\\)((?:\\\\)*)(?:\\('))''', r'\1\2', string)
    # escape double-quotes
    string = re.sub(r'''(?<!\\)((?:\\\\)*)(?:("))''', r'\1\\\2', string)
    return f'"{string}"'

def sub_escapes(repl:str, string:str, useless_escapes:bool=False, count:int=0) -> str:
    r"""Regex substitution for all (Python) string escapes
    \0 matches the full esacpe
    \1 matches the full pattern after the escape '\'

    ESCAPES: \xFF, \uFFFF, \UFFFFFFFF, \777{1,3}, \\, \', \", \a, \b, \f, \n, \r, \t, \v

    useless_escapes will match any character pattern \.
    """
    # \xXX, \uXXXX, \UXXXXXXXX, \ooo{1,3}, \\, \', \", \a, \b, \f, \n, \r, \t, \v
    if not useless_escapes:
        return re.sub(r'''\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[\\\'\"abfnrtv])''', repl, string, count=count)
    else:
        return re.sub(r'''\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|.)''', repl, string, count=count)

LITERAL_ESCAPES:dict = {
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
}

def escape_ignorequotes(string:str) -> str:
    return repr(string)[1:-1].replace('\\\'', '\'')

def unescape(string:str, useless_escapes:bool=False) -> str:
    r"""Unescape for all (Python) string escapes

    ESCAPES: \xFF, \uFFFF, \UFFFFFFFF, \777{1,3}, \\, \', \", \a, \b, \f, \n, \r, \t, \v

    useless_escapes will match any character pattern \.
    """
    # \xXX, \uXXXX, \UXXXXXXXX, \ooo{1,3}, \\, \', \", \a, \b, \f, \n, \r, \t, \v
    # match no '\', ( hex with prefix char | octal | literal | invalid )
    PATTERN = r'''\\((x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})|([0-7]{1,3})|([\\\'\"abfnrtv])|(.|$))'''
    
    parts = []
    last_end = 0
    for m in re.finditer(PATTERN, string):
        if m.start() != last_end:
            parts.append(string[last_end:m.start()])
        if m[2]: # hex: [xuU](\h+)
            if m[2][0] == 'U':
                raise ValueError(f'UTF-32 escape {m[0]!r} is not supported by Python')
            c = chr(int(m[2][1:], 16))
        elif m[3]:
            c = chr(int(m[3], 8))
        elif m[4]:
            c = LITERAL_ESCAPES[m[4]]
        elif m[5] is not None: # match could be empty
            if not useless_escapes:
                raise ValueError(f'Invalid escape {m[0]!r}')
            c = m[5] # treat as literal (same goes for EOL, just "")
        parts.append(c)
        last_end = m.end()
    
    if last_end != 0:
        if last_end < len(string):
            parts.append(string[last_end:])
        return ''.join(parts)
    return string
    
    # [s[:m.start()] + r + s[m.end():] for m in re.finditer(p,s)]
    # if not useless_escapes:
    #     return re.sub(r'''\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[\\\'\"abfnrtv])''', repl, string, count=count)
    # else:
    #     return re.sub(r'''\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|.|$)''', repl, string, count=count)

#endregion

#region ## COLOR HELPERS ##

# dummy color namespaces for disabled color
DummyFore = SimpleNamespace(RESET='', BLACK='', BLUE='', CYAN='', GREEN='', MAGENTA='', RED='', WHITE='', YELLOW='', LIGHTBLACK_EX='', LIGHTBLUE_EX='', LIGHTCYAN_EX='', LIGHTGREEN_EX='', LIGHTMAGENTA_EX='', LIGHTRED_EX='', LIGHTWHITE_EX='', LIGHTYELLOW_EX='')
DummyBack = SimpleNamespace(RESET='', BLACK='', BLUE='', CYAN='', GREEN='', MAGENTA='', RED='', WHITE='', YELLOW='', LIGHTBLACK_EX='', LIGHTBLUE_EX='', LIGHTCYAN_EX='', LIGHTGREEN_EX='', LIGHTMAGENTA_EX='', LIGHTRED_EX='', LIGHTWHITE_EX='', LIGHTYELLOW_EX='')
DummyStyle = SimpleNamespace(RESET_ALL='', BRIGHT='', DIM='', NORMAL='') #, BOLD='', ITALIC='', UNDERLINE='', BLINKING='', INVERSE='', INVISIBLE='', STRIKETHROUGH='')

# normal color namespaces 
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init()  # comment out init if extended color support is needed in Windows Terminal
except ImportError:
    # colorama not installed. fine, I'll do it myself
    # this expects Windows Terminal or equivalent terminal color code support
    Fore = SimpleNamespace(RESET='\x1b[39m', BLACK='\x1b[30m', BLUE='\x1b[34m', CYAN='\x1b[36m', GREEN='\x1b[32m', MAGENTA='\x1b[35m', RED='\x1b[31m', WHITE='\x1b[37m', YELLOW='\x1b[33m', LIGHTBLACK_EX='\x1b[90m', LIGHTBLUE_EX='\x1b[94m', LIGHTCYAN_EX='\x1b[96m', LIGHTGREEN_EX='\x1b[92m', LIGHTMAGENTA_EX='\x1b[95m', LIGHTRED_EX='\x1b[91m', LIGHTWHITE_EX='\x1b[97m', LIGHTYELLOW_EX='\x1b[93m')
    Back = SimpleNamespace(RESET='\x1b[49m', BLACK='\x1b[40m', BLUE='\x1b[44m', CYAN='\x1b[46m', GREEN='\x1b[42m', MAGENTA='\x1b[45m', RED='\x1b[41m', WHITE='\x1b[47m', YELLOW='\x1b[43m', LIGHTBLACK_EX='\x1b[100m', LIGHTBLUE_EX='\x1b[104m', LIGHTCYAN_EX='\x1b[106m', LIGHTGREEN_EX='\x1b[102m', LIGHTMAGENTA_EX='\x1b[105m', LIGHTRED_EX='\x1b[101m', LIGHTWHITE_EX='\x1b[107m', LIGHTYELLOW_EX='\x1b[103m')
    # extended styles not part of colorama
    Style = SimpleNamespace(RESET_ALL='\x1b[0m', BRIGHT='\x1b[1m', DIM='\x1b[2m', NORMAL='\x1b[22m') #, BOLD='\x1b[1m', ITALIC='\x1b[3m', UNDERLINE='\x1b[4m', BLINKING='\x1b[5m', INVERSE='\x1b[7m', INVISIBLE='\x1b[8m', STRIKETHROUGH='\x1b[9m')

# dictionaries for easier **foreground** color formatting
# >>> '{DIM}{GREEN}{!s}{RESET_ALL}'.format('hello world', **Colors)
DummyColors = dict(**DummyFore.__dict__, **DummyStyle.__dict__)
Colors = dict(**Fore.__dict__, **Style.__dict__)

#endregion

#region ## HEXDUMP HELPERS ##

_hexdump_span = namedtuple('_hexdump_span', ('start', 'stop', 'text', 'left', 'right'))

class hd_span:
    """Highlighting span used by print_hexdump() highlights argument
    """
    def __init__(self, start:int=None, stop:int=None, braces:str='  ', textcolor:str=None, bracecolor:str=None, *, color:str=...):
        self.start = start
        self.stop  = stop
        if color is not Ellipsis:
            textcolor = bracecolor = color
        left  = braces[ :1] if braces else None
        right = braces[-1:] if braces else None
        if textcolor:            textcolor = '{}{{:02x}}{{RESET_ALL}}'.format(textcolor)
        if left  and left  != ' ' and bracecolor: left  = '{}{}{{RESET_ALL}}'.format(bracecolor, left)
        if right and right != ' ' and bracecolor: right = '{}{}{{RESET_ALL}}'.format(bracecolor, right)
        self._text  = textcolor or None
        self._left  = left  or None
        self._right = right or None

    def indices(self, size:int) -> tuple:
        start, stop, _ = slice(self.start, self.stop).indices(size)
        if stop == start:
            stop = -1
        text  = self._text
        left  = self._left
        right = self._right
        return _hexdump_span(start, stop, text, left, right)

def print_hexdump(data:bytes, start:int=None, stop:int=None, *highlights:List[hd_span], show_header:bool=True, color:bool=False):
    """
    highlight = (start, stop, color, openbrace, closebrace, colorall=False)
    """
    colors = Colors if color else DummyColors
    # ignore msb for chars, default to '.' for control chars, space, and del
    CHARMAP = tuple((chr(b&0x7f) if (32<b<127) else '.') for b in range(256))
    # # default to '.' for control chars, space, del, and non-ascii chars
    # CHARMAP = tuple((chr(b) if (32<b<127) else '.') for b in range(256))

    highlights = [h.indices(len(data)) for h in highlights]

    def hexbyte(i:int) -> str:
        left = '' if (i <= stop) else ' '
        text = '' if (i < stop) else '  '
        # right = '' if ((i & 0xf) == 0xf or i+1 == len(data)) else ...
        right = '' if (i & 0xf) == 0xf else ...
        # if (i & 0xf) != 0xf: right = ...   # don't attempt right brace handling when not at edge of row

        for h in highlights:
            if not (h.start <= i <= h.stop):
                continue

            if   not text and h.text  and i != h.stop:   text = h.text
            if   not left and h.left  and i == h.start:  left = h.left
            elif not left and h.right and i & 0xf and i == h.stop: left = h.right # previously ended span
            if  not right and h.right and i+1 == h.stop: right = h.right # end of span on right edge of row or end of final row

        return ((left or ' ') + (text or '{:02x}') + ((right or ' ') if right is not Ellipsis else '')).format(data[i] if i < len(data) else 0, **colors)

    start, stop, _ = slice(start, stop).indices(len(data))
    rowstart = start     & ~0xf  # floor, units of 16
    rowstop = (stop+0xf) & ~0xf  # ceil,  units of 16

    if show_header:
        print('{BRIGHT}{BLUE}  Offset: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F \t{RESET_ALL}'.format(**colors))

    for off in range(rowstart, rowstop, 16):
        # ignore bytes outside of specified range
        rowbytes = ''.join((hexbyte(i) if (start<=i<rowstop) else '   ') for i in range(off,off+16))
        # ignore bytes outside of specified range (inclusive stop for closing braces)
        # rowbytes = ''.join((hexbyte(i) if (start<=i<=stop) else '   ') for i in range(off,off+16))
        # ignore chars outside of specified range (use ' ')
        rowchars = ''.join((CHARMAP[data[i]] if (start<=i<stop) else ' ') for i in range(off,off+16))

        print('{BRIGHT}{BLUE}{:08x}:{RESET_ALL}{}   {BRIGHT}{GREEN}{!s}{RESET_ALL}'.format(off, rowbytes, rowchars, **colors))

#endregion


del namedtuple, SimpleNamespace, Any, List, Match, NoReturn, Union  # cleanup declaration-only imports
