from binaryninja import (
    InstructionTextToken,
    BranchType,
    InstructionTextTokenType,
    LowLevelILFunction,
    LowLevelILLabel
)

class BranchInfo:
    def __init__(self,_type,target=None):
        self.type = _type
        self.target = target

class Instruction():
    
    instruction_groups = {
        3: [{
            0x04: 'CALL',
            0x05: 'GOTO',
        }, 'CallGotoInstruction'],
        4: [{
            0x04: 'BCF',
            0x05: 'BSF',
            0x06: 'BTFSC',
            0x07: 'BTFSS',
        }, 'BitFSInstruction'],
        5: [{
            0x19: 'BRA',
        }, 'BRAInstruction'],
        6: {
            'BYTE_FILEREG_OP': [{
                0x01: 'CLRF',
                0x07: 'ADDWF',
                0x3D: 'ADDWFC',
                0x05: 'ANDWF',
                0x37: 'ASRF',
                0x35: 'LSLF',
                0x36: 'LSRF',
                0x09: 'COMF',
                0x03: 'DECF',
                0x0A: 'INCF',
                0x04: 'IORWF',
                0x08: 'MOVF',
                0x0D: 'RLF',
                0x0C: 'RRF',
                0x02: 'SUBWF',
                0x3B: 'SUBWFB',
                0x0E: 'SWAPF',
                0x06: 'XORWF',
                0x0B: 'DECFSZ',
                0x0F: 'INCFSZ',
            }, 'ByteFSInstruction'],
            'LITERAL_GENERAL': [{
                0x3E: 'ADDLW',
                0x39: 'ANDLW',
                0x38: 'IORLW',
                0x30: 'MOVLW',
                0x3C: 'SUBLW',
                0x3A: 'XORLW',
                0x34: 'RETLW',
            
            }, 'GeneralInstruction'],
        },
        7: {
            'MOVLP': [{
                0x63: 'MOVLP',
            }, 'MovlpInstruction'],
            'FSR_OFFSET': [{
                0x01: 'MOVWF',
                0x62: 'ADDFSR',
                0x7E: 'MOVIW',
                0x7F: 'MOVWI',
            }, 'FSROffsetInstruction'],
        },
        9: [{
            0x01: 'MOVLB',
        }, 'MovlbInstruction'],
        11: [{
            0x0C: 'TRIS',
            0x02: 'MOVIW',
            0x03: 'MOVWI',
        }, 'FSRIncInstruction'],
        12: [{
            0x40: 'CLRW',
        }, 'CLRWInstruction'],
        14: [{
            0x00: 'NOP',
            0x01: 'RESET',
            0x08: 'RETURN',
            0x09: 'RETFIE',
            0x0A: 'CALLW',
            0x0B: 'BRW',
            0x62: 'OPTION',
            0x63: 'SLEEP',
            0x64: 'CLRWDT',
        }, 'OPOnlyInstruction'],
    }
    
    def __init__(self, name, data, addr):
        self.name = name
        self.data = data
        self.addr = addr
        self.instr_text_padding = 8
        
        return
    
    @classmethod
    def new(self, data, addr):
        if len(data) < 2:
            return
        
        instr = int.from_bytes(data[:2], 'big')
        
        for opcode_len, group_data in self.instruction_groups.items():
            
            groups_to_check = []
            if type(group_data) == dict:
                groups_to_check += [g for mn, g in group_data.items()]
            else:
                groups_to_check += [group_data]
                
            for group in groups_to_check:
                instrs = group[0]
                handler = group[1]
                masked_instr = instr >> (14 - opcode_len)
                
                if masked_instr in instrs.keys():
                    mnemonic = instrs[masked_instr]
                    return globals()[handler](mnemonic, instr, addr)
                
        print(f'Failed parsing instruction {bin(instr)} @ {hex(addr)}')
        return
    
    @classmethod
    def disassemble_conditional_jump(self, data, addr):
        
        condition_ins = Instruction.new(data[0:2], addr)
        
        tokens = []
        match condition_ins.name:
            case 'BTFSS':
        
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "JEQ".ljust(8, " "))
                
            case 'BTFSC':
                
                InstructionTextToken(InstructionTextTokenType.InstructionToken, "JNEQ".ljust(8, " "))

        return tokens, []
    
    @classmethod
    def lift_conditional_jump(self, data, addr, il: LowLevelILFunction):
        print(f'Boutta Lift cond jump @ {hex(addr)}')
        
        condition_ins = Instruction.new(data[0:2], addr)
        skip_if_ins = Instruction.new(data[2:4], addr + 2)
        skip_if_not_ins = Instruction.new(data[4:6], addr + 4)
        
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        
        match condition_ins.name:
            case 'BTFSS':
        
                il.append(il.if_expr(il.compare_equal(1, il.load(1, il.const_pointer(1, condition_ins.f)), il.const(1, 0)), t, f))
        
                il.mark_label(t)
                skip_if_ins.lift(data[2:4], il)
                il.mark_label(f)
                skip_if_not_ins.lift(data[4:6], il)
                
            case 'BTFSC':
                
                il.append(il.if_expr(il.compare_not_equal(1, il.load(1, il.const_pointer(1, condition_ins.f)), il.const(1, 0)), t, f))
        
                il.mark_label(t)
                skip_if_ins.lift(data[2:4], il)
                il.mark_label(f)
                skip_if_not_ins.lift(data[4:6], il)
        
        
        return 6
        
        
    
class ByteFSInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.d = (data >> 7) & 1
        self.f = data & 0b1111111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        if self.d == 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "W     "))
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "f     "))
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{self.f:02x}", self.f))

        return tokens, []
    
    def lift(self, data: bytes, il: LowLevelILFunction):
        
        # 0x01: 'CLRF',
        # 0x07: 'ADDWF',
        # 0x3D: 'ADDWFC',
        # 0x05: 'ANDWF',
        # 0x37: 'ASRF',
        # 0x35: 'LSLF',
        # 0x36: 'LSRF',
        # 0x09: 'COMF',
        # 0x03: 'DECF',
        # 0x0A: 'INCF',
        # 0x04: 'IORWF',
        # 0x08: 'MOVF',
        # 0x0D: 'RLF',
        # 0x0C: 'RRF',
        # 0x02: 'SUBWF',
        # 0x3B: 'SUBWFB',
        # 0x0E: 'SWAPF',
        # 0x06: 'XORWF',
        # 0x0B: 'DECFSZ',
        # 0x0F: 'INCFSZ',
        
        match self.name:
            case 'CLRF':
                if self.d == 0:
                    # W
                    il.append(il.set_reg(1, "W", il.const(1, 0)))
                else:
                    # f
                    il.append(il.store(1, il.const_pointer(2, self.f), il.const(1, 0)))
                    
            case 'MOVF':
                il.append(il.set_reg(1, "W", il.load(1, il.const_pointer(1, self.f))))
                    
            case 'ADDWF':
                il.append(il.store(1, il.const_pointer(1, self.f), il.add(1, il.load(1, self.f), il.reg(1, "W"))))
                # il.append(il.set_reg(1, "W", il.add(1, il.reg(1, "W"), il.load(1, il.const(1, self.f)))))
                
            case 'ADDWFC':
                il.append(il.store(1, il.const_pointer(1, self.f), il.add_carry(1, il.load(1, self.f), il.reg(1, "W"), il.flag("c"))))
                # il.append(il.set_reg(1, "W", il.add_carry(1, il.reg(1, "W"), il.load(1, il.const(1, self.f)), il.flag("c"))))
                   
            case 'SUBWF':
                il.append(il.store(1, il.const_pointer(1, self.f), il.sub(1, il.load(1, self.f), il.reg(1, "W"))))
                # il.append(il.set_reg(1, "W", il.sub(1, il.reg(1, "W"), il.load(1, il.const(1, self.f)))))
                    
            case _:
                il.append(il.unimplemented())

        return
    
    
class BitFSInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.b = (data >> 7) & 0b111
        self.f = data & 0b1111111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{self.b:02x}  ", self.b))
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{self.f:02x}  ", self.f))
        
        return tokens, []
    
    def lift(self, data: bytes, il: LowLevelILFunction):


        match self.name:
            case 'BCF':
                freg = il.reg(1, f"F{self.f}")
                freg_clear = il.and_expr(1, freg, il.not_expr(1, il.const(1, self.b)))
                il.append(il.set_reg(1, f"F{self.f}", freg_clear))
                
            case 'BSF':
                freg = il.reg(1, f"F{self.f}")
                freg_clear = il.or_expr(1, freg, il.not_expr(1, il.const(1, self.b)))
                il.append(il.set_reg(1, f"F{self.f}", freg_clear))
                
            case _:
                il.append(il.unimplemented())        
        
        return 2
    
class GeneralInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.k = data & 0b11111111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{self.k:02x}", self.k))

        return tokens, []
    
    def lift(self, data: bytes, il: LowLevelILFunction):
        
        wreg = il.reg(1, "W")
        kconst = il.const(1, self.k)
        
        match self.name:
            case "ADDLW":
                il.append(il.set_reg(1, "W", il.add(1, wreg, kconst)))
                
            case "ANDLW":
                il.append(il.set_reg(1, "W", il.and_expr(1, wreg, kconst)))
                
            case "IORLW":
                il.append(il.set_reg(1, "W", il.or_expr(1, wreg, kconst)))
                
            case "XORLW":
                il.append(il.set_reg(1, "W", il.xor_expr(1, wreg, kconst)))
                
            case "SUBLW":
                il.append(il.set_reg(1, "W", il.sub(1, wreg, kconst)))
            
            case "MOVLW":
                il.append(il.set_reg(1, "W", kconst))
                
            case "RETLW":
                il.append(il.set_reg(1, "W", kconst))
                il.append(il.ret(0))
                
            case _:
                il.append(il.unimplemented())

        return 2
    
class CallGotoInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.k = data & 0b11111111111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.AddressDisplayToken, hex(self.k * 2), self.k * 2))
        
        branches = []
        if self.name == 'CALL':
            branches.append(BranchInfo(BranchType.CallDestination, self.k * 2))
        else:
            branches.append(BranchInfo(BranchType.UnconditionalBranch, self.k * 2))
        
        return tokens, branches
    
    def lift(self, data: bytes, il: LowLevelILFunction):
        
        target = il.const_pointer(2, self.k * 2)

        if self.name == 'CALL':
            il.append(il.call(target))
        else:
            il.append(il.jump(target))
        
        return 2
    
class MovlpInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.imm = data & 0b1111111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{self.imm:02x}", self.imm))
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.CommentToken, f"\tPCLATH = 0x{self.imm:02x}"))
        
        return tokens, []
    
    def lift(self, data: bytes, il: LowLevelILFunction):
        
        il.append(il.set_reg(1, "PCLATH", il.const(1, self.imm)))

        return 2
    
class MovlbInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.bank = data & 0b11111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{self.bank:02x}", self.bank))
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.CommentToken, f"\tselect bank {self.bank}"))
        
        return tokens, []
    
    def lift(self, data: bytes, il: LowLevelILFunction):

        il.append(il.set_reg(1, "BSR", il.const(1, self.bank)))

        return 2
    
class BRAInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.k = data & 0b111111111

        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.AddressDisplayToken, hex(self.addr + self.k * 2), self.addr + self.k * 2))
        
        return tokens, [BranchInfo(BranchType.UnconditionalBranch, self.addr + self.k * 2)]
    
    def lift(self, data: bytes, il: LowLevelILFunction):
        
        target = il.const_pointer(2, self.addr + self.k * 2)
        il.append(il.jump(target))

        return 2
    
class FSROffsetInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.n = (data >> 6) & 1
        self.k = data & 0b111111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        if self.n == 0:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "FSR   "))
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "INDF  "))
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{self.k:02x}", self.k))
        
        return tokens, []
    
    def lift(self, data: bytes, il: LowLevelILFunction):


        # 0x01: 'MOVWF',
        # 0x62: 'ADDFSR',
        # 0x7E: 'MOVIW',
        # 0x7F: 'MOVWI',
        match self.name:
            
            case "MOVWF":
                print(f'movwf @ {hex(self.addr)}')
                il.append(il.store(1, il.const_pointer(1, self.k + (self.n << 6)), il.reg(1, "W")))
                il.append(il.set_reg(1, f'F{self.k}', il.reg(1, "W")))
                
            case "ADDFSR":
                il.append(il.set_reg(1, f'FSR{self.n}', il.add_carry(il.reg(1, f'FSR{self.n}'), il.const(1, self.k))))
                
            case "MOVIW":
                il.append(il.set_reg(1, f'FSR{self.k}', il.reg(1, "W")))
                
            case "MOVWI":
                il.append(il.set_reg(1, f'W', il.reg(1, f'FSR{self.k}')))
                
            case _:
                il.append(il.unimplemented())

        return 2
    
class FSRIncInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.n = int(data[-3], 2)
        self.k = int(data[-2:], 2)
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(self.n), self.n))
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(self.m), self.m))
        
        return tokens, []
    
    def lift(self, data: bytes, il: LowLevelILFunction):
        
        il.append(il.unimplemented())

        return 2
    
    
class OPOnlyInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        branches = []
        if self.name == 'RETURN':
            branches.append(BranchInfo(BranchType.FunctionReturn, 0))
        
        return tokens, branches
    
    def lift(self, data: bytes, il: LowLevelILFunction):

        # TODO: fix RETURN return address
        match self.name:
            case "NOP":
                il.append(il.nop())
                
            case "RETURN":
                il.append(il.ret(il.const(2, 0)))
                
            case _:
                il.append(il.unimplemented())

        return 2
    
class CLRWInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        return tokens, []
    
    def lift(self, data: bytes, il: LowLevelILFunction):

        il.append(il.set_reg(1, "W", il.const(1, 0)))

        return 2