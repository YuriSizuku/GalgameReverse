#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro script disassembler
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

__all__ = ['Instruction', 'MjoScript', 'BasicBlock', 'Function']

#######################################################################################

import os, io, math, re  # math used for isnan()
from abc import abstractproperty
from collections import namedtuple
from typing import Iterator, List, NoReturn, Optional, Tuple  # for hinting in declarations

# import flags
from ._util import StructIO, DummyColors, Colors, signed_i, unsigned_I
from .flags import MjoType, MjoScope, MjoInvert, MjoModifier, MjoDimension, MjoFlags
from .opcodes import Opcode
from . import crypt
from . import known_hashes

## FORMAT OPTIONS ##

#NOTE: This is a temporary class until the real formatter module is complete

class ILFormat:
    # very lazy storage for default options
    DEFAULT:'ILFormat' = None
    def __init__(self):
        self.color:bool = False  # print colors to the console
        self.braces:bool = True  # add braces around functions
        self.known_hashes:bool = True
        self.annotations:bool = True   # ; $known_hash, _knownvar, etc. [when: inline_hash=False]
                                       # ; $XXXXXXXX [when: inline_hash=True]
        self.inline_hash:bool = False  # $hashname (when known) [requires: known_hashes=True]
        self.explicit_inline_hash:bool = False  # ${hashname}  [requires: inline_hash=True]
        self.syscall_inline_hash:bool = False  # include inline hashing for syscalls
                                               # this will lose backwards compatibility as known hash names are updated
        self.int_inline_hash:bool = True  # inline hashes for integer literals
        self.group_directive:str = None  # default group to disassemble with (removes @GROUPNAME when found)
        self.resfile_directive:str = None  # output all `text` opcode lines to a csv file with the given name
        self._resfile_path:str = None  # defined by __main__ for quick access
        self.explicit_inline_resource:bool = False  # %{hashname}  [requires: resfile_directive="anything"]
        self.implicit_local_groups:bool = False  # always exclude empty group name from known local names
        self.annotate_hex:bool     = True  # enables/disables ; $XXXXXXXX annotations when using inline hashes

        # aliasing and operands:
        self.modifier_aliases:bool = False  # (variable flags) inc.x, dec.x, x.inc, x.dec
        self.invert_aliases:bool   = False  # (variable flags) -, -, -, -  (NOTE: there are no aliases, added for conformity)
        self.scope_aliases:bool    = False  # (variable flags) persist, save, -, -
        self.vartype_aliases:bool  = False  # (variable flags) i, r, s, iarr, rarr, sarr
        self.typelist_aliases:bool = False  # (typelist operand) i, r, s, iarr, rarr, sarr
        self.functype_aliases:bool = False  # (function declaration) i, r, s, iarr, rarr, sarr
        self.explicit_dim0:bool    = False  # (variable flags) always include dim0 flag  #WHY WOULD YOU WANT THIS?
        self.explicit_varoffset:bool = False  # always include -1 for non-local var offsets
        
        # space-savers:
        self.address_len:int       = 5     # len of XXXXX: addresses before every opcode
        self.address_labels:bool   = True  # include address labels at all before every opcode
        self.opcode_padding:int    = 13    # number of EXTRA spaces to pad opcodes with (from the start of the opcode)
                                           # one mandatory space is always added AFTER this for operands

    def set_address_len(self, bytecode_size:int) -> NoReturn:
        self.address_len = max(2, len(f'{bytecode_size:x}'))

    def address_fmt(self, offset) -> str:
        return '{{:0{0}x}}'.format(max(2, int(self.address_len))).format(offset)

    def needs_explicit_hash(self, known_hash:str) -> bool:
        import re
        # return True if setting is enabled, or unsupported identifier characters exist
        #source: <https://stackoverflow.com/a/1325265/7517185>
        return self.explicit_inline_hash or bool(re.search(r'[^_%@#$0-9A-Za-z]', known_hash))
        
    
    @classmethod
    def properties(self) -> List[str]:
        return [k for k in ILFormat.DEFAULT.__dict__.keys() if k[0] != '_' and k != 'group_directive']  # quick dumb handling

    @property
    def colors(self) -> dict:
        return Colors if self.color else DummyColors

ILFormat.DEFAULT = ILFormat()


class Instruction:
    """Bytecode instruction of opcode, offset, operands, and optionally analysis data
    """
    def __init__(self, opcode:Opcode, offset:int):
        # general #
        self.opcode:Opcode = opcode
        self.offset:int = offset  # bytecode offset
        self.size:int = 0  # instruction size in bytecode

        # operands #
        self.flags:MjoFlags = MjoFlags(0)  # flags for ld* st* variable opcodes
        self.hash:int = 0  # identifier hash for ld* st* variable opcodes, and call* syscall* function opcodes
        self.var_offset:int = 0  # stack offset for ld* st* local variables (-1 used for non-local)
        self.type_list:List[MjoType] = None  # type list operand for argcheck opcode
        self.string:str = None  # string operand for ldstr, text, ctrl opcodes
        self.int_value:int = 0  # int operand for ldc.i opcode (SHOULD ALWAYS BE STORED AS SIGNED)
        self.float_value:float = 0.0  # float operand for ldc.r opcode
        self.argument_count:int = 0  # argument count operand for call* syscall* function opcodes
        self.line_number:int = 0  # line number operand for line opcode
        self.jump_offset:int = 0  # jump offset operand for b* opcodes
        self.switch_cases:List[int] = None  # switch jump offset operands for switch opcode

        # analysis #
        self.jump_target:'BasicBlock' = None  # analyzed jump target location
        self.switch_targets:List['BasicBlock'] = None  # analyzed switch jump target locations

    @property
    def is_jump(self) -> bool: return self.opcode.is_jump
    @property
    def is_switch(self) -> bool: return self.opcode.mnemonic == "switch"  # 0x850
    @property
    def is_return(self) -> bool: return self.opcode.mnemonic == "ret"  # 0x82b
    @property
    def is_argcheck(self) -> bool: return self.opcode.mnemonic == "argcheck"  # 0x836
    @property
    def is_syscall(self) -> bool: return self.opcode.mnemonic in ("syscall", "syscallp")  # 0x834, 0x835
    @property
    def is_call(self) -> bool: return self.opcode.mnemonic in ("call", "callp")  # 0x80f, 0x810
    # ldc.i 0x800, ldstr 0x801, ldc.r 0x803
    @property
    def is_literal(self) -> bool: return self.opcode.mnemonic in ("ldc.i", "ldc.r", "ldstr")
    # ld 0x802, ldelem 0x837
    @property
    def is_load(self) -> bool: return self.opcode.mnemonic in ("ld", "ldelem")
    # st.* 0x1b0~0x200, stp.* 0x210~0x260, stelem.* 0x270~0x2c0, stelemp.* 0x2d0~0x320
    @property
    def is_store(self) -> bool: return self.opcode.mnemonic.startswith("st")

    def __str__(self) -> str:
        return self.format_instruction()
    def __repr__(self) -> str:
        return self.format_instruction()
        
    @classmethod
    def format_string(cls, string:str, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        import re
        colors:dict = options.colors
        # unescape single quotes and escape double-quotes
        # string = repr(string)[1:-1].replace('\\\'', '\'').replace('\"', '\\\"')
        string = repr(string)[1:-1]
        # this pattern ensures ignoring any leading escaped backslashes
        # unescape single-quotes
        string = re.sub(r'''(?<!\\)((?:\\\\)*)(?:\\('))''', r'\1\2', string)
        # escape double-quotes
        string = re.sub(r'''(?<!\\)((?:\\\\)*)(?:("))''', r'\1\\\2', string)
        if options.color:
            # brighten escapes
            string = re.sub(r'''\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[\\\\'\\"abfnrtv])''', r'{BRIGHT}\0{DIM}'.format(**colors), string)
        return '{DIM}{GREEN}"{}"{RESET_ALL}'.format(string, **colors)

    @classmethod
    def check_hash_group(cls, name:str, syscall:bool=False, *, options:ILFormat=ILFormat.DEFAULT) -> Optional[str]: # name
        # attempt implicit groups/group directive:
        #  has found name   and not a syscall hash
        if name is not None and not syscall and (options.group_directive is not None or options.implicit_local_groups):
            # handle group stripping
            idx = name.find('@', 1)  # first char can't be group
            if idx != -1 and name.find('@', idx + 1) == -1:
                basename, group = name[:idx], name[idx+1:]
                if options.implicit_local_groups and basename[0] == '_' and group == '':
                    # local var
                    name = basename
                elif group == options.group_directive and basename[0] != '_':
                    # same group as group directive, not allowed for locals
                    name = basename
            else:
                # we can't handle this: group not found, or more than one '@'
                #  (more than one '@' does not make a valid group!!!)
                pass
        return name

    def check_known_hash(self, *, options:ILFormat=ILFormat.DEFAULT) -> Optional[Tuple[str, bool]]: # (name, is_syscall)
        name, syscall = (None, False)  # not an opcode that relates to hashes
        if self.is_syscall:
            name = known_hashes.SYSCALLS.get(self.hash, None)
            syscall = True
        elif self.is_call:
            name = known_hashes.FUNCTIONS.get(self.hash, None)
        elif self.is_load or self.is_store:
            # TODO: this could be optimized to use the type flags
            #       and search in the scope-independent dicts
            name = known_hashes.VARIABLES.get(self.hash, None)
        elif self.opcode.mnemonic == "ldc.i": # 0x800
            name = known_hashes.FUNCTIONS.get(unsigned_I(self.int_value), None)
            # TODO: Uncomment if it's observed that int literals
            #       will use hashes for types other than usercalls
            if name is None:
                name = known_hashes.VARIABLES.get(unsigned_I(self.int_value), None)
            if name is None:
                name = known_hashes.SYSCALLS.get(unsigned_I(self.int_value), None)
                syscall = True

        return (self.check_hash_group(name, syscall, options=options), syscall)

    def print_instruction(self, *, options:ILFormat=ILFormat.DEFAULT, resource_key:str=None, **kwargs) -> NoReturn:
        print(self.format_instruction(options=options, resource_key=resource_key), **kwargs)
    def format_instruction(self, *, options:ILFormat=ILFormat.DEFAULT, resource_key:str=None) -> str:
        colors:dict = options.colors
        sb:str = ''

        if options.address_labels:
            address = options.address_fmt(self.offset)
            sb += '{BRIGHT}{BLACK}{0}:{RESET_ALL} '.format(address, **colors)
        if self.opcode.mnemonic == "line":  # 0x83a
            sb += '{BRIGHT}{BLACK}{0.opcode.mnemonic}{RESET_ALL}'.format(self, **colors)
        else:
            sb += '{BRIGHT}{WHITE}{0.opcode.mnemonic}{RESET_ALL}'.format(self, **colors)

        if not self.opcode.encoding:
            return sb  # no operands, nothing to add

        # padding after opcode (min 1 space, which is not included in padding option count)
        sb += ' ' + (' ' * max(0, options.opcode_padding - len(self.opcode.mnemonic)))

        known_hash_name, known_hash_is_syscall = None, False
        if options.known_hashes:
            known_hash_name, known_hash_is_syscall = self.check_known_hash(options=options)

        operands = []
        for operand in self.opcode.encoding:
            op = None  # if assigned, append to operands at bottom of loop

            if operand == 't':
                # type list
                types = ', '.join('{BRIGHT}{CYAN}{}{RESET_ALL}'.format(t.getname(options.typelist_aliases), **colors) for t in self.type_list)
                op = '[{}]'.format(types)
            elif operand == 's':
                # string data
                if resource_key is None:
                    op = self.format_string(self.string, options=options)
                elif options.explicit_inline_resource:
                    op = '{BRIGHT}{CYAN}%{{{RESET_ALL}{}{BRIGHT}{CYAN}}}{RESET_ALL}'.format(resource_key, **colors)
                else:
                    op = '{BRIGHT}{CYAN}%{RESET_ALL}{}'.format(resource_key, **colors)
            elif operand == 'f':
                # flags
                flags = self.flags
                keywords:list = []
                keywords.append(flags.scope.getname(options.scope_aliases))
                keywords.append(flags.type.getname(options.vartype_aliases))
                if flags.dimension or options.explicit_dim0:  #NOTE: dim0 is legal, just not required or recommended
                    keywords.append(flags.dimension.getname(options.explicit_dim0))
                if flags.invert:
                    keywords.append(flags.invert.getname(options.invert_aliases))
                if flags.modifier:
                    keywords.append(flags.modifier.getname(options.modifier_aliases))

                # push joined flag keywords as one operand, since technically it is only one
                op = '{BRIGHT}{CYAN}{}{RESET_ALL}'.format(' '.join(keywords), **colors)
            elif operand == 'h':
                # hash value
                if self.is_syscall:
                    hash_color = '{BRIGHT}{YELLOW}'.format(**colors)
                elif self.is_call:
                    hash_color = '{BRIGHT}{BLUE}'.format(**colors)
                else: #elif self.is_load or self.is_store:
                    hash_color = '{BRIGHT}{RED}'.format(**colors)
                if known_hash_name and options.inline_hash and (options.syscall_inline_hash or not self.is_syscall):
                    known_hash_name2 = known_hash_name
                    if self.is_syscall:
                        known_hash_name2 = known_hash_name.lstrip('$') # requirement for syscall hash lookup syntax
                    if options.needs_explicit_hash(known_hash_name2):
                        op = '{BRIGHT}{CYAN}${{{RESET_ALL}{}{}{RESET_ALL}{BRIGHT}{CYAN}}}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                    else:
                        op = '{BRIGHT}{CYAN}${RESET_ALL}{}{}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                else:
                    op = '${:08x}{RESET_ALL}'.format(self.hash, **colors)
            elif operand == 'o':
                # variable offset
                #NEW: exclude -1 offsets for non-local variables, because that operand
                #     isn't used. still output erroneous var offsets (aka anything other than -1)
                if options.explicit_varoffset or self.var_offset != -1 or self.flags.scope is MjoScope.LOCAL:
                    op = '{:d}'.format(self.var_offset)
            elif operand == '0':
                # 4 byte address placeholder
                pass
            elif operand == 'i':
                # integer constant
                # integer literals will sometimes use hashes for usercall function pointers
                # this entire if statement tree is terrifying...
                if known_hash_name is not None:
                    if known_hash_is_syscall:
                        hash_color = '{BRIGHT}{YELLOW}'.format(**colors)
                    elif known_hash_name[0] == '$':
                        hash_color = '{BRIGHT}{BLUE}'.format(**colors)
                    else: #elif self.is_load or self.is_store:
                        hash_color = '{BRIGHT}{RED}'.format(**colors)

                    if options.inline_hash and options.int_inline_hash and (options.syscall_inline_hash or not known_hash_is_syscall):
                        known_hash_name2 = known_hash_name
                        if known_hash_is_syscall:
                            known_hash_name2 = known_hash_name.lstrip('$') # requirement for syscall hash lookup syntax
                        if options.needs_explicit_hash(known_hash_name2):
                            op = '{BRIGHT}{CYAN}${{{RESET_ALL}{}{}{RESET_ALL}{BRIGHT}{CYAN}}}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                        else:
                            op = '{BRIGHT}{CYAN}${RESET_ALL}{}{}{RESET_ALL}'.format(hash_color, known_hash_name2, **colors)
                    else:
                        # print as hex for simplicity (this can also be printed with $XXXXXXXX notation)
                        op = '0x{:08x}'.format(unsigned_I(self.int_value))
                else:
                    op = '{:d}'.format(signed_i(self.int_value))
            elif operand == 'r':
                # float constant
                if self.float_value == float('inf'):
                    op = '+Inf'
                elif self.float_value == float('-inf'):
                    op = '-Inf'
                elif math.isnan(self.float_value):
                    op = 'NaN'
                else:
                    op = '{:g}'.format(self.float_value)  # fixed or exponential
                    try:
                        int(op, 10)  # test if no decimal or exponent
                        op += '.0'  # append '.0' for all floats that parse to integers
                    except:
                        pass  # fine just the way it is
            elif operand == 'a':
                # argument count
                op = '({:d})'.format(self.argument_count)
            elif operand == 'j':
                # jump offset
                if self.jump_target is not None:
                    op = '{BRIGHT}{MAGENTA}@{}{RESET_ALL}'.format(self.jump_target.name, **colors)
                else:
                    op = '{BRIGHT}{MAGENTA}@~{:+04x}{RESET_ALL}'.format(self.jump_offset, **colors)
            elif operand == 'l':
                # line number
                op = '{BRIGHT}{BLACK}#{:d}{RESET_ALL}'.format(self.line_number, **colors)
            elif operand == 'c':
                # switch case table
                if self.switch_targets: # is not None:
                    op = ', '.join('{BRIGHT}{MAGENTA}@{}{RESET_ALL}'.format(t.name, **colors) for t in self.switch_targets) # pylint: disable=not-an-iterable
                else:
                    op = ', '.join(', '.join('{BRIGHT}{MAGENTA}@~{:+04x}{RESET_ALL}'.format(o, **colors) for o in self.switch_cases))
            else:
                raise Exception('Unrecognized encoding specifier: {!r}'.format(operand))
            
            # append operand (if defined)
            if op is not None:
                operands.append(op)
        
        if operands: # append space-separated operands
            sb += ' '.join(operands)

        if known_hash_name is None or not options.annotations:
            pass  # no hash name comments
        elif self.is_syscall: # 0x834, 0x835
            if not options.inline_hash or not options.syscall_inline_hash:
                # sb = sb.ljust(ops_offset + 16 + len(colors["BRIGHT"]) + len(colors["YELLOW"]) + len(colors["RESET_ALL"]))
                sb += '  {BRIGHT}{BLACK}; {DIM}{YELLOW}{}{RESET_ALL}'.format(known_hash_name, **colors)
            elif options.annotate_hex:
                sb += '  {BRIGHT}{BLACK}; {DIM}{YELLOW}${:08x}{RESET_ALL}'.format(self.hash, **colors)
        elif self.is_call: # 0x80f, 0x810
            if not options.inline_hash:
                # sb = sb.ljust(ops_offset + 16 + len(colors["BRIGHT"]) + len(colors["BLUE"]) + len(colors["RESET_ALL"]))
                sb += '  {BRIGHT}{BLACK}; {DIM}{BLUE}{}{RESET_ALL}'.format(known_hash_name, **colors)
            elif options.annotate_hex:
                sb += '  {BRIGHT}{BLACK}; {DIM}{BLUE}${:08x}{RESET_ALL}'.format(self.hash, **colors)
        elif self.is_load or self.is_store:
            if not options.inline_hash:
                sb += '  {BRIGHT}{BLACK}; {DIM}{RED}{}{RESET_ALL}'.format(known_hash_name, **colors)
            elif options.annotate_hex:
                sb += '  {BRIGHT}{BLACK}; {DIM}{RED}${:08x}{RESET_ALL}'.format(self.hash, **colors)
        elif self.opcode.mnemonic == "ldc.i": # 0x800
            # check for loading function hashes (which are often passed to )
            if known_hash_is_syscall:
                hash_color = '{DIM}{YELLOW}'.format(**colors)
            elif known_hash_name[0] == '$':
                hash_color = '{DIM}{BLUE}'.format(**colors)
            else: #elif self.is_load or self.is_store:
                hash_color = '{DIM}{RED}'.format(**colors)

            ## testing reversal of the conditional branching behemoth below:
            # def test(a,b,c,d): return (not a or not b or (c and not d)) == (a and b and (not c or d))
            # [tuple(o) for o in combos if test(*o)]
            if not options.inline_hash or not options.int_inline_hash or (known_hash_is_syscall and not options.syscall_inline_hash):
                #sb = sb.ljust(ops_offset + 16)
                sb += '  {BRIGHT}{BLACK}; {RESET_ALL}{}{}{RESET_ALL}'.format(hash_color, known_hash_name, **colors)
            elif options.annotate_hex:
                sb += '  {BRIGHT}{BLACK}; {RESET_ALL}{}${:08x}{RESET_ALL}'.format(hash_color, unsigned_I(self.int_value), **colors)
        return sb

    @classmethod
    def read_instruction(cls, reader:StructIO, offset:int) -> 'Instruction':
        opcode_value:int = reader.unpackone('<H')
        opcode:Opcode = Opcode.BYVALUE.get(opcode_value, None)
        if not opcode:
            raise Exception('Invalid opcode found at offset 0x{:08X}: 0x{:04X}'.format(offset, opcode_value))
        instruction:Instruction = Instruction(opcode, offset)

        for operand in opcode.encoding:
            if operand == 't':
                # type list
                count = reader.unpackone('<H')
                instruction.type_list = [MjoType(b) for b in reader.unpack('<{:d}B'.format(count))]
            elif operand == 's':
                # string data
                size = reader.unpackone('<H')
                instruction.string = reader.read(size).rstrip(b'\x00').decode('cp932')
            elif operand == 'f':
                # flags
                instruction.flags = MjoFlags(reader.unpackone('<H'))
            elif operand == 'h':
                # hash value
                instruction.hash = reader.unpackone('<I')
            elif operand == 'o':
                # variable offset
                instruction.var_offset = reader.unpackone('<h')
            elif operand == '0':
                # 4 byte address placeholder
                assert(reader.unpackone('<I') == 0)
            elif operand == 'i':
                # integer constant
                instruction.int_value = reader.unpackone('<i')
            elif operand == 'r':
                # float constant
                instruction.float_value = reader.unpackone('<f')
            elif operand == 'a':
                # argument count
                instruction.argument_count = reader.unpackone('<H')
            elif operand == 'j':
                # jump offset
                instruction.jump_offset = reader.unpackone('<i')
            elif operand == 'l':
                # line number
                instruction.line_number = reader.unpackone('<H')
            elif operand == 'c':
                # switch case table
                count = reader.unpackone('<H')
                instruction.switch_cases = list(reader.unpack('<{:d}i'.format(count)))
            else:
                raise Exception('Unrecognized encoding specifier: {!r}'.format(operand))
        
        instruction.size = reader.tell() - offset
        return instruction
    
    def write_instruction(self, writer:StructIO) -> NoReturn:
        offset = writer.tell()
        opcode = self.opcode
        writer.pack('<H', opcode.value)
        for operand in opcode.encoding:
            if operand == 't':
                # type list
                writer.pack('<H', len(self.type_list))  # count
                writer.pack(f'<{len(self.type_list)}B', *[t.value for t in self.type_list])  # types
            elif operand == 's':
                # string data
                ## support multi codepage
                encoding = 'cp932'
                pattern = r"\[\[(.+?)\]\]"
                m = re.search(pattern, self.string)
                if m: 
                    encoding = m.group(1)
                    self.string = re.sub(pattern, "", self.string)
                elif opcode.mnemonic == 'text': 
                    encoding = os.environ["TEXT_ENCODING"]
                writer.pack('<H', len(self.string.encode(encoding))+1)  # size + null terminator
                writer.pack(f'<{len(self.string.encode(encoding))+1}s', self.string.encode(encoding))  # string + null terminator
            elif operand == 'f':
                # flags
                writer.pack('<H', int(self.flags))  #currently flags is a type that subclasses int, but do this anyway
            elif operand == 'h':
                # hash value
                # this shouldn't happen... buuuuut, be safe and force unsigned
                writer.pack('<I', unsigned_I(self.hash))  # hash value
            elif operand == 'o':
                # variable offset
                writer.pack('<h', self.var_offset)
            elif operand == '0':
                # 4 byte address placeholder
                writer.pack('<I', 0)  # 4 byte address placeholder  (always 0)
            elif operand == 'i':
                # integer constant
                writer.pack('<i', signed_i(self.int_value))  # integer constant
            elif operand == 'r':
                # float constant
                writer.pack('<f', self.float_value)  # float constant
            elif operand == 'a':
                # argument count
                writer.pack('<H', self.argument_count)  # argument count
            elif operand == 'j':
                # jump offset
                writer.pack('<i', self.jump_offset)  # jump offset
            elif operand == 'l':
                # line number
                writer.pack('<H', self.line_number)  # line number
            elif operand == 'c':
                # switch case table
                writer.pack('<H', len(self.switch_cases))  # count
                writer.pack(f'<{len(self.switch_cases)}i', *self.switch_cases)  # cases
            else:
                raise Exception('Unrecognized encoding specifier: {!r}'.format(operand))
        assert(self.size == (writer.tell() - offset)), f'{self.offset:05x}: {opcode.mnemonic}'


# function entry type declared in table in MjoScript header before bytecode
FunctionEntry = namedtuple('FunctionEntry', ('name_hash', 'offset'))


class MjoScript:
    """Majiro .mjo script type and disassembler
    """
    SIGNATURE_ENCRYPTED:bytes = b'MajiroObjX1.000\x00'  # encrypted bytecode
    SIGNATURE_DECRYPTED:bytes = b'MajiroObjV1.000\x00'  # decrypted bytecode (majiro)
    SIGNATURE_PLAIN:bytes = b'MjPlainBytecode\x00'  # decrypted bytecode (mjdisasm)
    def __init__(self, signature:bytes, main_offset:int, line_count:int, bytecode_offset:int, bytecode_size:int, functions:List[FunctionEntry], instructions:List[Instruction]):
        self.signature:bytes = signature
        self.main_offset:int = main_offset
        self.line_count:int = line_count
        self.bytecode_offset:int = bytecode_offset
        self.bytecode_size:int = bytecode_size
        self.functions:List[FunctionEntry] = functions
        self.instructions:List[Instruction] = instructions

    def get_resource_key(self, instruction:Instruction, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        if options.resfile_directive and instruction.opcode.mnemonic == "text": # 0x840
            # count = 0
            number = 0
            for instr in self.instructions:
                if instr.opcode.mnemonic == "text": # 0x840
                    # count += 1
                    number += 1
                    if instr.offset == instruction.offset:
                        # number = count
                        # break
                        return f'L{number}' # number will be 1-indexed
            # return f'L{number}'
        return None
        # index = self.instruction_index_from_offset(instruction.offset)
        # number = len([1 for i in range(index) if self.instructions[i].opcode.mnemonic == "text"]) # 0x840
    @property
    def is_readmark(self) -> bool:
        # preprocessor "#use_readflg on" setting, we need to export this with IL
        return bool(self.line_count)
    @property
    def main_function(self) -> FunctionEntry:
        for fn in self.functions:
            if fn.offset == self.main_offset:
                return fn
        return None

    def instruction_index_from_offset(self, offset:int) -> int:
        for i,instr in enumerate(self.instructions):
            if instr.offset == offset:
                return i
        return -1
    
    def assemble_script(self, writer:io.BufferedWriter) -> NoReturn:
        if not isinstance(writer, StructIO):
            writer = StructIO(writer)

        # header:
        if self.signature not in (self.SIGNATURE_ENCRYPTED, self.SIGNATURE_DECRYPTED):
            raise Exception(f'{self.__class__.__name__} signature must be {self.SIGNATURE_ENCRYPTED.decode("cp932")!r} or {self.SIGNATURE_DECRYPTED.decode("cp932")!r}, not {self.signature.decode("cp932")!r}')
        writer.pack('<16sIII', self.signature, self.main_offset, self.line_count, len(self.functions))
        is_encrypted:bool = (self.signature == self.SIGNATURE_ENCRYPTED)
        assert(is_encrypted ^ (self.signature in (self.SIGNATURE_DECRYPTED, self.SIGNATURE_PLAIN)))

        # functions table:
        for fn in self.functions:
            writer.pack('<II', *fn)  # fn.name_hash, fn.offset

        # bytecode:
        writer.pack('<I', self.bytecode_size)

        # initialize full-length of bytecode ahead of time (is this actually efficient in Python?)
        ms:io.BytesIO = io.BytesIO(bytes(self.bytecode_size))
        self.assemble_bytecode(StructIO(ms))
        ms.flush()

        bytecode:bytes = ms.getvalue()
        if is_encrypted:
            bytecode = crypt.crypt32(bytecode)  # encrypt bytecode
        written_size = writer.write(bytecode)
        assert(written_size == self.bytecode_size)

    @classmethod
    def disassemble_script(cls, reader:io.BufferedReader) -> 'MjoScript':
        if not isinstance(reader, StructIO):
            reader = StructIO(reader)

        # header:
        signature, main_offset, line_count, function_count = reader.unpack('<16sIII')
        is_encrypted:bool = (signature == cls.SIGNATURE_ENCRYPTED)
        assert(is_encrypted ^ (signature in (cls.SIGNATURE_DECRYPTED, cls.SIGNATURE_PLAIN)))

        # functions table:
        functions:List[FunctionEntry] = []
        for _ in range(function_count):
            functions.append(FunctionEntry(*reader.unpack('<II')))

        # bytecode:
        bytecode_size:int = reader.unpackone('<I')

        bytecode_offset:int = reader.tell()
        bytecode:bytes = reader.read(bytecode_size)
        if is_encrypted:
            bytecode = crypt.crypt32(bytecode)  # decrypt bytecode
        ms:io.BytesIO = io.BytesIO(bytecode)
        instructions:List[Instruction] = cls.disassemble_bytecode(StructIO(ms))

        return MjoScript(signature, main_offset, line_count, bytecode_offset, bytecode_size, functions, instructions)

    def assemble_bytecode(self, writer:StructIO) -> NoReturn:
        if not isinstance(writer, StructIO):
            writer = StructIO(writer)

        for instruction in self.instructions:
            instruction.write_instruction(writer)

    @classmethod
    def disassemble_bytecode(cls, reader:StructIO) -> List[Instruction]:
        if not isinstance(reader, StructIO):
            reader = StructIO(reader)

        length:int = reader.length()
        offset:int = reader.tell()

        instructions:List[Instruction] = []
        while offset != length:
            instruction:Instruction = Instruction.read_instruction(reader, offset)
            instructions.append(instruction)
            offset = reader.tell()

        return instructions

    def print_readmark(self, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> NoReturn:
        print(self.format_readmark(options=options), **kwargs)
    def format_readmark(self, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        #FIXME: temp solution to print all directives in one go
        colors:dict = options.colors
        setting = ('{GREEN}enable' if self.is_readmark else '{RED}disable').format(**colors)
        s = '{DIM}{YELLOW}readmark{RESET_ALL} {BRIGHT}{}{RESET_ALL}'.format(setting, **colors)
        s += '\n'
        if options.group_directive is None:
            s += '{DIM}{YELLOW}group{RESET_ALL} {BRIGHT}{RED}none{RESET_ALL}'.format(**colors)
        else:
            s += '{DIM}{YELLOW}group{RESET_ALL} {}'.format(Instruction.format_string(options.group_directive, options=options), **colors)
        if options.resfile_directive is not None:
            s += '\n'
            s += '{DIM}{YELLOW}resfile{RESET_ALL} {}'.format(Instruction.format_string(options.resfile_directive, options=options), **colors)
        return s



class _Block:
    """Base class for bytecode block analysis
    """
    def __init__(self):
        self.first_instruction_index:int = -1
        self.last_instruction_index:int = -1
    @abstractproperty
    def script(self) -> MjoScript:
        raise NotImplementedError('_Block.script')
    @property
    def instruction_count(self) -> int:
        if self.first_instruction_index == -1 or self.last_instruction_index == -1:
            return -1
        return self.last_instruction_index - self.first_instruction_index + 1
    @property
    def instructions(self) -> Iterator[Instruction]:
        if self.first_instruction_index == -1 or self.last_instruction_index == -1:
            return []
        return self.script.instructions[self.first_instruction_index:self.last_instruction_index + 1]  # pylint: disable=no-member
        # for i in range(self.first_instruction_index, self.last_instruction_index + 1):
        #     yield self.script.instructions[i]
    @property
    def start_offset(self) -> int:
        if self.first_instruction_index == -1 or self.last_instruction_index == -1:
            return -1
        return self.script.instructions[self.first_instruction_index].offset  # pylint: disable=no-member
        # for instruction in self.instructions:
        #     return instruction.offset
        # return -1

class BasicBlock(_Block):
    """Simple block of instructions
    """
    def __init__(self, function:'Function'):
        super().__init__()
        self.function = function
        self.is_entry_block:bool = False
        self.is_exit_block:bool = False
        self.is_dtor_block:bool = False  # destructor {} syntax with op.847 (bsel.5)
        self.predecessors:List['BasicBlock'] = []
        self.successors:List['BasicBlock'] = []
    @property
    def script(self) -> MjoScript:
        return self.function._script
    @property
    def name(self) -> str:
        if self.is_entry_block:
            return 'entry'
        elif self.is_dtor_block:
            return 'destructor_{:05x}'.format(self.start_offset)
        elif self.is_exit_block:
            return 'exit_{:05x}'.format(self.start_offset)
        else:
            return 'block_{:05x}'.format(self.start_offset)

    def print_basic_block(self, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> NoReturn:
        print(self.format_basic_block(options=options), **kwargs)
    def format_basic_block(self, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        colors:dict = options.colors
        return '{BRIGHT}{MAGENTA}{.name}:{RESET_ALL}'.format(self, **colors)

class _BlockContainer(_Block):
    """Block, and container for nested instruction blocks
    """
    def __init__(self):
        super().__init__()
        self.basic_blocks:List[BasicBlock] = []
    def basic_block_from_offset(self, offset:int) -> BasicBlock:
        for block in self.basic_blocks:
            if self.script.instructions[block.first_instruction_index].offset == offset:  # pylint: disable=no-member
                return block
        return None

class Function(_BlockContainer):
    """Function block, containing nested instruction blocks
    """
    def __init__(self, script:MjoScript, name_hash:int):
        super().__init__()
        self._script:MjoScript = script
        self.name_hash:int = name_hash
        self.entry_block:BasicBlock = None
        self.exit_blocks:List[BasicBlock] = None
        self.parameter_types:List[MjoType] = None
    @property
    def script(self) -> MjoScript:
        return self._script
    @property
    def is_entrypoint(self) -> bool:
        return self.start_offset == self.script.main_offset

    def print_function(self, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> NoReturn:
        print(self.format_function(options=options), **kwargs)
    def format_function(self, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        colors:dict = options.colors

        # always "func" as, "void" can only be confirmed by all-zero return values
        s = '{BRIGHT}{BLUE}func '.format(**colors)

        known_hash:str = None
        if options.known_hashes:
            known_hash = known_hashes.FUNCTIONS.get(self.name_hash, None)
        if known_hash is not None:
            #TODO: move check hash function somewhere more fitting
            known_hash = Instruction.check_hash_group(known_hash, False, options=options)
        if known_hash is not None and options.inline_hash:
            if options.needs_explicit_hash(known_hash):
                s += '{BRIGHT}{CYAN}${{{BRIGHT}{BLUE}{}{BRIGHT}{CYAN}}}{BRIGHT}{BLUE}'.format(known_hash, **colors)
            else:
                s += '{BRIGHT}{CYAN}${BRIGHT}{BLUE}{}'.format(known_hash, **colors)
        else:
            s += '${.name_hash:08x}'.format(self)

        args = ', '.join('{BRIGHT}{CYAN}{}{RESET_ALL}'.format(t.getname(options.functype_aliases), **colors) for t in self.parameter_types) # pylint: disable=not-an-iterable
        s += '{RESET_ALL}({})'.format(args, **colors)

        # "entrypoint" states which function to declare as "main" to the IL assembler
        if self.is_entrypoint:
            s += ' {DIM}{YELLOW}entrypoint{RESET_ALL}'.format(**colors)
    
        # optional brace formatting
        if options.braces:
            s += ' {'

        if known_hash is not None and options.annotations:
            if not options.inline_hash:
                s += '  {BRIGHT}{BLACK}; {DIM}{BLUE}{}{RESET_ALL}'.format(known_hash, **colors)
            elif options.annotate_hex:
                s += '  {BRIGHT}{BLACK}; {DIM}{BLUE}${.name_hash:08x}{RESET_ALL}'.format(self, **colors)
    
        return s
    def print_function_close(self, *, options:ILFormat=ILFormat.DEFAULT, **kwargs) -> NoReturn:
        print(self.format_function_close(options=options), **kwargs)
    def format_function_close(self, *, options:ILFormat=ILFormat.DEFAULT) -> str:
        return '}' if options.braces else ''


del abstractproperty, namedtuple, Iterator, NoReturn, Optional, Tuple  # cleanup declaration-only imports
