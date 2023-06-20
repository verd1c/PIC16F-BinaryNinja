from binaryninja import (
    InstructionTextToken,
    BranchType,
    InstructionTextTokenType
)

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

        return tokens
    
    
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
        
        return tokens
    
class GeneralInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.k = data & 0b11111111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{self.k:02x}", self.k))

        return tokens
    
class CallGotoInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.k = data & 0b11111111111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.AddressDisplayToken, hex(self.k), self.k))
        
        return tokens
    
class MovlpInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.imm = data & 0b1111111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{self.imm:02x}", self.imm))
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.CommentToken, f"\tPCLATH = 0x{self.imm:02x}"))
        
        return tokens
    
class MovlbInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        self.bank = data & 0b11111
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, f"0x{self.bank:02x}", self.bank))
        
        tokens.append(InstructionTextToken(InstructionTextTokenType.CommentToken, f"\tselect bank {self.bank}"))
        
        return tokens
    
class BRAInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
   
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        return tokens
    
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
        
        return tokens
    
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
        
        return tokens
    
    
class OPOnlyInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        return tokens
    
class CLRWInstruction(Instruction):
    
    def __init__(self, name, data, addr):
        super().__init__(name, data, addr)
        
        return     
        
    def disassemble(self):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, self.name.ljust(self.instr_text_padding, " "))]
        
        return tokens
    