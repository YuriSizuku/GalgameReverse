#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Majiro disassembled script analyzer
"""

__version__ = '0.1.0'
__date__    = '2021-04-04'
__author__  = 'Robert Jordan'
__credits__ = '''Original C# implementation by AtomCrafty - 2021
Converted to Python library by Robert Jordan - 2021
'''

__all__ = ['ControlFlowGraph']

#######################################################################################

from typing import Iterator, List, NoReturn, Set  # for hinting in declarations

from ._util import DummyColors, Colors
from .script import Instruction, MjoScript, BasicBlock, Function


class ControlFlowGraph:
    def __init__(self, functions:List[Function]):
        self.functions:List[Function] = functions
    
    @classmethod
    def build_from_script(cls, script:MjoScript) -> 'ControlFlowGraph':
        start_indices:Set[int] = set()
        functions:List[Function] = []

        # mark function start indices
        for function_entry in script.functions:
            offset:int = function_entry.offset
            index:int = script.instruction_index_from_offset(offset)
            if index < 0: raise Exception('No instruction found at offset 0x{:08x}'.format(offset))

            function:Function = Function(script, function_entry.name_hash)
            function.first_instruction_index = index
            functions.append(function)
            start_indices.add(index)
        
        # find function ends
        for function in functions:
            for i in range(function.first_instruction_index, len(script.instructions)):
                if i + 1 == len(script.instructions) or (i + 1) in start_indices:
                    function.last_instruction_index = i
                    break
            
            if function.last_instruction_index == -1:
                raise Exception('Unable to find last instruction of function ${.name_hash:08x}'.format(function))
        
        for function in functions:
            cls.analyze_function(function)
        
        return ControlFlowGraph(functions)

    @classmethod
    def possible_next_instruction_offsets(cls, instruction:Instruction) -> Iterator[int]:
        yield instruction.offset + instruction.size

        if instruction.opcode.is_jump:
            yield instruction.offset + instruction.size + instruction.jump_offset
        
        elif instruction.switch_cases is not None:
            # hardcoded handling
            for i,case_offset in enumerate(instruction.switch_cases):
                #FIXME: Harcoded handling of switch target operand offsets
                # target operands are relative to after the individual target is read
                # sizeof(opcode) + sizeof(count) + sizeof(offset) * (i+1)
                yield instruction.offset + 2 + 2 + (i + 1)*4 + case_offset

    @classmethod
    def analyze_function(cls, function:Function) -> NoReturn:
        script:MjoScript = function.script
        instructions:List[Instruction] = script.instructions

        entry_block:BasicBlock = BasicBlock(function)
        entry_block.first_instruction_index = function.first_instruction_index
        entry_block.is_entry_block = True
        function.entry_block = entry_block
        function.exit_blocks = []  # BasicBlock[]

        start_indices:Set[int] = {function.first_instruction_index}
        basic_blocks:List[BasicBlock] = [entry_block]

        def mark_basic_block_start(offset:int, origin:Instruction=None):
            index = script.instruction_index_from_offset(offset)
            if index == -1:
                function.print_function(color=True)
                # print('{BRIGHT}{BLUE}func ${.name_hash:08x}({!s}){RESET_ALL}'.format(function, ', '.join(t.name for t in function.parameter_types), **Colors))
                #for basic_block in function.basic_blocks:
                #    print('{BRIGHT}{MAGENTA}{.name!s}:{RESET_ALL}'.format(basic_block, **colors))
                for instruction in function.instructions:
                    # if instruction.opcode.mnemonic.startswith('bsel'):
                    #print(Disassembler.format_instruction(instruction, color=True))
                    instruction.print_instruction(color=True)
                if origin:
                    print()
                    print('Offending instruction:')
                    #print(Disassembler.format_instruction(origin, color=True))
                    origin.print_instruction(color=True)
                    # print(origin.is_jump, origin.is_switch, origin.opcode, origin.offset)
                raise Exception('Unable to determine jump target of 0x{:08x} in function ${.name_hash:08x}'.format(offset, function))
            set_len = len(start_indices)
            start_indices.add(index)
            if len(start_indices) != set_len: # new block
                basic_block:BasicBlock = BasicBlock(function)
                if offset != origin.offset + origin.size and origin.opcode.mnemonic == "bsel.5":  # 0x847
                    basic_block.is_dtor_block = True
                basic_block.first_instruction_index = index
                basic_blocks.append(basic_block)
        
        # mark basic block boundaries
        #TODO: should this: " < function.last_instruction_index " be "<=" ? ( + 1)
        for i in range(function.first_instruction_index, function.last_instruction_index):
            instruction:Instruction = instructions[i]

            if instruction.is_jump or instruction.is_switch:
                for offset in cls.possible_next_instruction_offsets(instruction):
                    mark_basic_block_start(offset, instruction)
            elif instruction.is_argcheck:
                function.parameter_types = instruction.type_list

        # find basic block ends
        for basic_block in basic_blocks:
            for i in range(basic_block.first_instruction_index, function.last_instruction_index + 1):
                if i == function.last_instruction_index or (i + 1) in start_indices:
                    basic_block.last_instruction_index = i
                    break
            
            if basic_block.last_instruction_index == -1:
                raise Exception('Unable to find last instruction')
        
        basic_blocks.sort(key=lambda b: b.first_instruction_index)
        function.basic_blocks = basic_blocks

        for basic_block in basic_blocks:
            cls.analyze_basic_block(basic_block)

    @classmethod
    def analyze_basic_block(cls, basic_block:BasicBlock) -> NoReturn:
        function:Function = basic_block.function
        script:MjoScript = function.script
        instructions:List[Instruction] = script.instructions

        last_instruction:Instruction = instructions[basic_block.last_instruction_index]

        if last_instruction.is_return:
            function.exit_blocks.append(basic_block)
            basic_block.is_exit_block = True
            return
        
        for offset in cls.possible_next_instruction_offsets(last_instruction):
            next_block:BasicBlock = function.basic_block_from_offset(offset)
            if next_block is None:
                raise Exception('Invalid jump target')
            basic_block.successors.append(next_block)
            next_block.predecessors.append(basic_block)
        
        if last_instruction.is_jump:
            target = last_instruction.offset + last_instruction.size + last_instruction.jump_offset
            last_instruction.jump_target = function.basic_block_from_offset(target)
        elif last_instruction.is_switch:
            last_instruction.switch_targets = [None] * len(last_instruction.switch_cases)
            for i,case_offset in enumerate(last_instruction.switch_cases):
                #FIXME: Harcoded handling of switch target operand offsets
                # target operands are relative to after the individual target is read
                # sizeof(opcode) + sizeof(count) + sizeof(offset) * (i+1)
                target = last_instruction.offset + 2 + 2 + (i + 1)*4 + case_offset
                last_instruction.switch_targets[i] = function.basic_block_from_offset(target)


del Iterator, NoReturn  # cleanup declaration-only imports
