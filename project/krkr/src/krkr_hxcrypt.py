"""
rewrite c# to python

refer:
https://github.com/crskycode/GARbro/blob/master/ArcFormats/KiriKiri/KiriKiriCx.cs
https://github.com/crskycode/GARbro/blob/master/ArcFormats/KiriKiri/HxCrypt.cs

"""

import struct
from dataclasses import dataclass, field
from typing import List, override

# cx class
class CxProgramException(Exception):
    pass

class InvalidEncryptionScheme(Exception):
    pass

class CxByteCode:
    NOP = 0
    RETN = 1
    MOV_EDI_ARG = 2
    PUSH_EBX = 3
    POP_EBX = 4
    PUSH_ECX = 5
    POP_ECX = 6
    MOV_EAX_EBX = 7
    MOV_EBX_EAX = 8
    MOV_ECX_EBX = 9
    MOV_EAX_CONTROL_BLOCK = 10
    MOV_EAX_EDI = 11
    MOV_EAX_INDIRECT = 12
    ADD_EAX_EBX = 13
    SUB_EAX_EBX = 14
    IMUL_EAX_EBX = 15
    AND_ECX_0F = 16
    SHR_EBX_1 = 17
    SHL_EAX_1 = 18
    SHR_EAX_CL = 19
    SHL_EAX_CL = 20
    OR_EAX_EBX = 21
    NOT_EAX = 22
    NEG_EAX = 23
    DEC_EAX = 24
    INC_EAX = 25

    IMMED = 0x100
    MOV_EAX_IMMED = 0x101
    AND_EBX_IMMED = 0x102
    AND_EAX_IMMED = 0x103
    XOR_EAX_IMMED = 0x104
    ADD_EAX_IMMED = 0x105
    SUB_EAX_IMMED = 0x106

@dataclass
class CxScheme:
    mask = 0
    offset = 0
    prolog_order: List[int] = None
    odd_branch_order: List[int] = None
    even_branch_order: List[int] = None
    control_block: List[int] = None # uint32_t * 1024

class CxProgram:
    LENGTH_LIMIT = 0x80

    class Context:
        def __init__(self):
            self.eax = 0
            self.ebx = 0
            self.ecx = 0
            self.edi = 0
            self.stack = []

    def __init__(self, seed, control_block):
        self.code = [] # stores uints
        self.control_block = control_block
        self.length = 0
        self.seed = seed

    def execute(self, hash_val):
        ctx = self.Context()
        iterator = iter(self.code)
        
        try:
            while True:
                bytecode = next(iterator)
                immed = 0
                
                # Check for IMMED flag
                if (bytecode & CxByteCode.IMMED) == CxByteCode.IMMED:
                    immed = next(iterator)
                
                # Python 3.10+ match case could be used here, but using if/elif for compatibility
                bc_type = bytecode
                
                if bc_type == CxByteCode.NOP: pass
                elif bc_type == CxByteCode.IMMED: pass
                elif bc_type == CxByteCode.MOV_EDI_ARG: ctx.edi = hash_val
                elif bc_type == CxByteCode.PUSH_EBX: ctx.stack.append(ctx.ebx)
                elif bc_type == CxByteCode.POP_EBX: ctx.ebx = ctx.stack.pop()
                elif bc_type == CxByteCode.PUSH_ECX: ctx.stack.append(ctx.ecx)
                elif bc_type == CxByteCode.POP_ECX: ctx.ecx = ctx.stack.pop()
                elif bc_type == CxByteCode.MOV_EBX_EAX: ctx.ebx = ctx.eax
                elif bc_type == CxByteCode.MOV_EAX_EDI: ctx.eax = ctx.edi
                elif bc_type == CxByteCode.MOV_ECX_EBX: ctx.ecx = ctx.ebx
                elif bc_type == CxByteCode.MOV_EAX_EBX: ctx.eax = ctx.ebx
                
                elif bc_type == CxByteCode.AND_ECX_0F: ctx.ecx &= 0x0f
                elif bc_type == CxByteCode.SHR_EBX_1: ctx.ebx >>= 1
                elif bc_type == CxByteCode.SHL_EAX_1: ctx.eax = (ctx.eax << 1) & 0xFFFFFFFF
                elif bc_type == CxByteCode.SHR_EAX_CL: ctx.eax >>= (ctx.ecx & 0x1F) # Safety mask for shift count
                elif bc_type == CxByteCode.SHL_EAX_CL: ctx.eax = (ctx.eax << (ctx.ecx & 0x1F)) & 0xFFFFFFFF
                elif bc_type == CxByteCode.OR_EAX_EBX: ctx.eax |= ctx.ebx
                elif bc_type == CxByteCode.NOT_EAX: ctx.eax = (~ctx.eax) & 0xFFFFFFFF
                elif bc_type == CxByteCode.NEG_EAX: ctx.eax = (-ctx.eax) & 0xFFFFFFFF
                elif bc_type == CxByteCode.DEC_EAX: ctx.eax = (ctx.eax - 1) & 0xFFFFFFFF
                elif bc_type == CxByteCode.INC_EAX: ctx.eax = (ctx.eax + 1) & 0xFFFFFFFF

                elif bc_type == CxByteCode.ADD_EAX_EBX: ctx.eax = (ctx.eax + ctx.ebx) & 0xFFFFFFFF
                elif bc_type == CxByteCode.SUB_EAX_EBX: ctx.eax = (ctx.eax - ctx.ebx) & 0xFFFFFFFF
                elif bc_type == CxByteCode.IMUL_EAX_EBX: ctx.eax = (ctx.eax * ctx.ebx) & 0xFFFFFFFF

                elif bc_type == CxByteCode.ADD_EAX_IMMED: ctx.eax = (ctx.eax + immed) & 0xFFFFFFFF
                elif bc_type == CxByteCode.SUB_EAX_IMMED: ctx.eax = (ctx.eax - immed) & 0xFFFFFFFF
                elif bc_type == CxByteCode.AND_EBX_IMMED: ctx.ebx &= immed
                elif bc_type == CxByteCode.AND_EAX_IMMED: ctx.eax &= immed
                elif bc_type == CxByteCode.XOR_EAX_IMMED: ctx.eax ^= immed
                elif bc_type == CxByteCode.MOV_EAX_IMMED: ctx.eax = immed
                elif bc_type == CxByteCode.MOV_EAX_INDIRECT:
                    if ctx.eax >= len(self.control_block):
                        raise CxProgramException("Index out of bounds in CxEncryption program")
                    # C#: ~m_ControlBlock[context.eax]
                    ctx.eax = (~self.control_block[ctx.eax]) & 0xFFFFFFFF
                
                elif bc_type == CxByteCode.RETN:
                    if len(ctx.stack) > 0:
                        raise CxProgramException("Imbalanced stack in CxEncryption program")
                    return ctx.eax
                
                else:
                    raise CxProgramException(f"Invalid bytecode {bc_type} in CxEncryption program")

        except StopIteration:
            raise CxProgramException("CxEncryption program without RETN bytecode")

    def clear(self):
        self.length = 0
        self.code.clear()

    def emit_nop(self, count):
        if self.length + count > self.LENGTH_LIMIT:
            return False
        self.length += count
        return True

    def emit(self, code, length=1):
        if self.length + length > self.LENGTH_LIMIT:
            return False
        self.length += length
        self.code.append(code)
        return True

    def emit_uint32(self, x):
        if self.length + 4 > self.LENGTH_LIMIT:
            return False
        self.length += 4
        self.code.append(x)
        return True

    def emit_random(self):
        return self.emit_uint32(self.get_random())

    def get_random(self):
        seed = self.seed
        # LCG: 1103515245 * seed + 12345
        self.seed = (1103515245 * seed + 12345) & 0xFFFFFFFF
        # Return: m_seed ^ (seed << 16) ^ (seed >> 16)
        res = self.seed ^ ((seed << 16) & 0xFFFFFFFF) ^ (seed >> 16)
        return res

class CxEncryption:
    S_CTL_BLOCK_SIGNATURE = b" Encryption control block"

    def __init__(self, scheme):
        self.m_mask = scheme.mask
        self.m_offset = scheme.offset
        
        self.prolog_order = scheme.prolog_order
        self.odd_branch_order = scheme.odd_branch_order
        self.even_branch_order = scheme.even_branch_order
        
        self.control_block = scheme.control_block
        
        # In Python list is dynamic, but we initialize with None to simulate the array
        self.m_program_list: List[CxProgram] = [None] * 0x80

    def __str__(self):
        return f"CxEncryption(0x{self.m_mask:X}, 0x{self.m_offset:X})"

    def get_base_offset(self, hash_val):
        return ((hash_val & self.m_mask) + self.m_offset) & 0xFFFFFFFF

    def decrypt_byte(self, hash_val, offset, value):
        """Decrypt a single byte"""
        key = hash_val
        base_offset = self.get_base_offset(key)
        
        if offset >= base_offset:
            key = ((key >> 16) ^ key) & 0xFFFFFFFF
            
        buffer = bytearray([value])
        self.decode(key, offset, buffer, 0, 1)
        return buffer[0]

    def decrypt_buffer(self, hash_val, offset, buffer, pos, count):
        """
        Decrypt a buffer in place.
        buffer: bytearray or mutable list of ints
        """

        key = hash_val
        base_offset = self.get_base_offset(key)
        
        if offset < base_offset:
            base_length = min(base_offset - offset, count)
            # Ensure types are int for length
            base_length = int(base_length)
            
            self.decode(key, offset, buffer, pos, base_length)
            offset += base_length
            pos += base_length
            count -= base_length
            
        if count > 0:
            key = ((key >> 16) ^ key) & 0xFFFFFFFF
            self.decode(key, offset, buffer, pos, count)

    def decode(self, key, offset, buffer, pos, count):
        ret1, ret2 = self.execute_xcode(key)
        
        key1 = ret2 >> 16
        key2 = ret2 & 0xFFFF
        key3 = ret1 & 0xFF  # (byte)ret.Item1
        
        if key1 == key2:
            key2 = (key2 + 1) & 0xFFFF
        if key3 == 0:
            key3 = 1
            
        # Optimization: pre-calc loop bounds if possible, but python slice is easiest if contiguous,
        # however 'buffer' might be a large array and we operate on a segment.
        
        # Apply XOR for key2 match
        if offset <= key2 < offset + count:
            idx = pos + int(key2 - offset)
            buffer[idx] ^= (ret1 >> 16) & 0xFF

        # Apply XOR for key1 match
        if offset <= key1 < offset + count:
            idx = pos + int(key1 - offset)
            buffer[idx] ^= (ret1 >> 8) & 0xFF
            
        # Bulk XOR
        for i in range(count):
            buffer[pos + i] ^= key3

    def execute_xcode(self, hash_val):
        seed = hash_val & 0x7f
        if self.m_program_list[seed] is None:
            self.m_program_list[seed] = self.generate_program(seed)
            
        program = self.m_program_list[seed]
        
        hash_shifted = hash_val >> 7
        ret1 = program.execute(hash_shifted)
        ret2 = program.execute((~hash_shifted) & 0xFFFFFFFF)
        
        return (ret1, ret2)

    def generate_program(self, seed):
        program = self.new_program(seed)
        for stage in range(5, 0, -1):
            if self.emit_code(program, stage):
                return program
            # print(f"stage {stage} failed for seed {seed}")
            program.clear()
            
        raise CxProgramException("Overly large CxEncryption bytecode")

    def new_program(self, seed):
        return CxProgram(seed, self.control_block)

    def emit_code(self, program, stage):
        return (program.emit_nop(5)
                and program.emit(CxByteCode.MOV_EDI_ARG, 4)
                and self.emit_body(program, stage)
                and program.emit_nop(5)
                and program.emit(CxByteCode.RETN))

    def emit_body(self, program, stage):
        if stage == 1:
            return self.emit_prolog(program)
            
        if not program.emit(CxByteCode.PUSH_EBX):
            return False
            
        if (program.get_random() & 1) != 0:
            if not self.emit_body(program, stage - 1):
                return False
        elif not self.emit_body2(program, stage - 1):
            return False
            
        if not program.emit(CxByteCode.MOV_EBX_EAX, 2):
            return False
            
        if (program.get_random() & 1) != 0:
            if not self.emit_body(program, stage - 1):
                return False
        elif not self.emit_body2(program, stage - 1):
            return False
            
        return self.emit_odd_branch(program) and program.emit(CxByteCode.POP_EBX)

    def emit_body2(self, program, stage):
        if stage == 1:
            return self.emit_prolog(program)
            
        rc = True
        if (program.get_random() & 1) != 0:
            rc = self.emit_body(program, stage - 1)
        else:
            rc = self.emit_body2(program, stage - 1)
            
        return rc and self.emit_even_branch(program)

    def emit_prolog(self, program):
        rc = True
        choice = self.prolog_order[program.get_random() % 3]
        
        if choice == 2:
            # MOV EAX, (Random() & 0x3ff)
            # MOV EAX, EncryptionControlBlock[EAX]
            rc = (program.emit_nop(5)
                  and program.emit(CxByteCode.MOV_EAX_IMMED, 2)
                  and program.emit_uint32(program.get_random() & 0x3ff)
                  and program.emit(CxByteCode.MOV_EAX_INDIRECT, 0))
        elif choice == 1:
             rc = program.emit(CxByteCode.MOV_EAX_EDI, 2)
        elif choice == 0:
             # MOV EAX, Random()
             rc = (program.emit(CxByteCode.MOV_EAX_IMMED)
                   and program.emit_random())
        return rc

    def emit_even_branch(self, program):
        rc = True
        choice = self.even_branch_order[program.get_random() & 7]
        
        if choice == 0:
            rc = program.emit(CxByteCode.NOT_EAX, 2)
        elif choice == 1:
            rc = program.emit(CxByteCode.DEC_EAX)
        elif choice == 2:
            rc = program.emit(CxByteCode.NEG_EAX, 2)
        elif choice == 3:
            rc = program.emit(CxByteCode.INC_EAX)
        elif choice == 4:
            rc = (program.emit_nop(5)
                  and program.emit(CxByteCode.AND_EAX_IMMED)
                  and program.emit_uint32(0x3ff)
                  and program.emit(CxByteCode.MOV_EAX_INDIRECT, 3))
        elif choice == 5:
            rc = (program.emit(CxByteCode.PUSH_EBX)
                  and program.emit(CxByteCode.MOV_EBX_EAX, 2)
                  and program.emit(CxByteCode.AND_EBX_IMMED, 2)
                  and program.emit_uint32(0xaaaaaaaa)
                  and program.emit(CxByteCode.AND_EAX_IMMED)
                  and program.emit_uint32(0x55555555)
                  and program.emit(CxByteCode.SHR_EBX_1, 2)
                  and program.emit(CxByteCode.SHL_EAX_1, 2)
                  and program.emit(CxByteCode.OR_EAX_EBX, 2)
                  and program.emit(CxByteCode.POP_EBX))
        elif choice == 6:
            rc = (program.emit(CxByteCode.XOR_EAX_IMMED)
                  and program.emit_random())
        elif choice == 7:
            if (program.get_random() & 1) != 0:
                rc = program.emit(CxByteCode.ADD_EAX_IMMED)
            else:
                rc = program.emit(CxByteCode.SUB_EAX_IMMED)
            rc = rc and program.emit_random()
            
        return rc

    def emit_odd_branch(self, program):
        rc = True
        choice = self.odd_branch_order[program.get_random() % 6]
        
        if choice == 0:
            rc = (program.emit(CxByteCode.PUSH_ECX)
                  and program.emit(CxByteCode.MOV_ECX_EBX, 2)
                  and program.emit(CxByteCode.AND_ECX_0F, 3)
                  and program.emit(CxByteCode.SHR_EAX_CL, 2)
                  and program.emit(CxByteCode.POP_ECX))
        elif choice == 1:
            rc = (program.emit(CxByteCode.PUSH_ECX)
                  and program.emit(CxByteCode.MOV_ECX_EBX, 2)
                  and program.emit(CxByteCode.AND_ECX_0F, 3)
                  and program.emit(CxByteCode.SHL_EAX_CL, 2)
                  and program.emit(CxByteCode.POP_ECX))
        elif choice == 2:
            rc = program.emit(CxByteCode.ADD_EAX_EBX, 2)
        elif choice == 3:
            rc = (program.emit(CxByteCode.NEG_EAX, 2)
                  and program.emit(CxByteCode.ADD_EAX_EBX, 2))
        elif choice == 4:
            rc = program.emit(CxByteCode.IMUL_EAX_EBX, 3)
        elif choice == 5:
            rc = program.emit(CxByteCode.SUB_EAX_EBX, 2)
            
        return rc

# hx class
@dataclass
class HxSchme(CxScheme):
    filter_key = 0
    random_type = 0

@dataclass
class HxFilterKey:
    header_key: bytearray = None # 16 bytes
    span_key: List[int] = field(default_factory=lambda: [0, 0]) # ulong[2]
    split_pos: int = 0

class HxSplittableRandom:
    def __init__(self, seed: int):
        self.m_seed = seed & 0xFFFFFFFFFFFFFFFF

    def next(self) -> int:
        self.m_seed = (self.m_seed + 0x9e3779b97f4a7c15) & 0xFFFFFFFFFFFFFFFF
        z = self.m_seed
        
        z ^= (z >> 30)
        z = (z * 0xbf58476d1ce4e5b9) & 0xFFFFFFFFFFFFFFFF
        z ^= (z >> 27)
        z = (z * 0x94d049bb133111eb) & 0xFFFFFFFFFFFFFFFF
        z ^= (z >> 31)
        
        return z

class HxProgram(CxProgram):
    class M64:
        """Mimics the C# Union struct explicit layout"""
        def __init__(self):
            self._u64 = 0

        @property
        def u64(self):
            return self._u64

        @u64.setter
        def u64(self, val):
            self._u64 = val & 0xFFFFFFFFFFFFFFFF

        @property
        def u32_lo(self):
            return self._u64 & 0xFFFFFFFF

        @u32_lo.setter
        def u32_lo(self, val):
            self._u64 = (self._u64 & 0xFFFFFFFF00000000) | (val & 0xFFFFFFFF)

        @property
        def u32_hi(self):
            return (self._u64 >> 32) & 0xFFFFFFFF

        @u32_hi.setter
        def u32_hi(self, val):
            high = (val & 0xFFFFFFFF) << 32
            self._u64 = (self._u64 & 0x00000000FFFFFFFF) | high

    def __init__(self, seed: int, control_block: List[int], random_method: int):
        super().__init__(seed, control_block)
        self.m_random_method = random_method
        self.m_seed = [self.M64(), self.M64()]
        
        # ulong s = seed
        s = seed & 0xFFFFFFFF
        # s = (s & 0xffffffff) | (~s << 32);
        s_inv = (~s) & 0xFFFFFFFF
        s = s | (s_inv << 32)
        
        r = HxSplittableRandom(s)
        self.m_seed[0].u64 = r.next()
        self.m_seed[1].u64 = r.next()

    def get_old_random(self) -> int:
        a, b, c, d, e = self.M64(), self.M64(), self.M64(), self.M64(), self.M64()
        
        a.u64 = self.m_seed[0].u64
        b.u64 = self.m_seed[1].u64
        
        c.u32_lo = a.u32_hi ^ b.u32_hi
        c.u32_hi = a.u32_lo ^ b.u32_lo
        
        e.u32_lo = c.u32_hi
        e.u32_hi = c.u32_lo
        
        t = (c.u32_hi << 21) & 0xFFFFFFFFFFFFFFFF
        t ^= (a.u64 >> 15)
        t ^= c.u32_hi
        self.m_seed[0].u32_lo = t
        
        t = a.u32_hi >> 15
        t |= (a.u32_lo << 17) & 0xFFFFFFFFFFFFFFFF
        t ^= (e.u64 >> 11)
        t ^= c.u32_lo
        self.m_seed[0].u32_hi = t
        
        self.m_seed[1].u32_hi = (e.u64 >> 4)
        self.m_seed[1].u32_lo = (c.u64 >> 4)
        
        d.u64 = (a.u64 + b.u64)
        
        t = (d.u64 << 17) & 0xFFFFFFFFFFFFFFFF
        t |= (d.u32_hi >> 15)
        t = (t + a.u64) & 0xFFFFFFFFFFFFFFFF
        
        return t

    def get_new_random(self) -> int:
        a, b, c, d = self.M64(), self.M64(), self.M64(), self.M64()
        
        a.u64 = self.m_seed[0].u64
        b.u64 = self.m_seed[1].u64
        
        c.u32_lo = a.u32_lo ^ b.u32_lo
        c.u32_hi = a.u32_hi ^ b.u32_hi
        
        t = (a.u32_lo << 24) & 0xFFFFFFFFFFFFFFFF
        t |= (a.u32_hi >> 8)
        t ^= (c.u32_lo << 16) & 0xFFFFFFFFFFFFFFFF
        t ^= c.u32_lo
        self.m_seed[0].u32_lo = t
        
        t = c.u64 >> 16
        t ^= (a.u64 >> 8)
        t ^= c.u32_hi
        self.m_seed[0].u32_hi = t
        
        t = c.u32_hi >> 27
        t |= (c.u32_lo << 5) & 0xFFFFFFFFFFFFFFFF
        self.m_seed[1].u32_hi = t
        
        self.m_seed[1].u32_lo = c.u64 >> 27
        
        d.u64 = 5 * a.u64
        
        t = d.u32_hi >> 25
        t |= (d.u64 << 7) & 0xFFFFFFFFFFFFFFFF
        t = (t * 9) & 0xFFFFFFFFFFFFFFFF
        
        return t

    @override
    def get_random(self) -> int:
        if self.m_random_method == 0:
            return self.get_old_random() & 0xFFFFFFFF
        else:
            return self.get_new_random() & 0xFFFFFFFF

class HxEncryption(CxEncryption):
    def __init__(self, scheme: HxSchme):
        super().__init__(scheme)
        self.filter_key: int = struct.unpack("<Q", scheme.filter_key)[0]
        self.random_type: int = scheme.random_type

    def create_filter_key(self, entry_key: int, entry_id: int) -> HxFilterKey:
        
        if (entry_id & 0x100000000) == 0: entry_key ^= self.filter_key
        header_key_seed = (~entry_key) & 0xFFFFFFFFFFFFFFFF

        # Create file key
        result = HxFilterKey()
        key0 = entry_key & 0xFFFFFFFF
        key1 = (entry_key >> 32) & 0xFFFFFFFF
        
        k0 = self.execute_xcode(key0)
        result.span_key[0] = (k0[0] | (k0[1] << 32)) & 0xFFFFFFFFFFFFFFFF
        
        k1 = self.execute_xcode(key1)
        result.span_key[1] = (k1[0] | (k1[1] << 32)) & 0xFFFFFFFFFFFFFFFF
        
        # Split position calculation
        # m_offset and m_mask are from base class CxEncryption
        idx = (entry_key >> 16) & self.m_mask
        result.split_pos = (self.m_offset + idx) & 0xFFFFFFFF
        
        # Create header key
        k3 = self.execute_xcode(header_key_seed & 0xFFFFFFFF)
        v5 = (k3[0] | (k3[1] << 32)) & 0xFFFFFFFFFFFFFFFF
        v5 = (~v5) & 0xFFFFFFFFFFFFFFFF
        
        result.header_key = bytearray(16)
        
        j = 56
        for i in range(8):
            result.header_key[i] = (v5 >> j) & 0xFF
            j -= 8
            
        k3 = self.execute_xcode(v5 & 0xFFFFFFFF)
        v5 = (k3[0] | (k3[1] << 32)) & 0xFFFFFFFFFFFFFFFF
        v5 = (~v5) & 0xFFFFFFFFFFFFFFFF
        
        j = 56
        for i in range(8):
            result.header_key[i+8] = (v5 >> j) & 0xFF
            j -= 8

        return result

    @override
    def new_program(self, seed: int) -> HxProgram:
        return HxProgram(seed, self.control_block, self.random_type)