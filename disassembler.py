from binaryninja import (
    InstructionTextToken,
    BranchType,
    InstructionTextTokenType
)

class Instruction():
    def __init__(self, data):
        
        
        
        return

class PIC16FDisassembler():
    
    def __init__(self):
        self.instructions = {
            "111000": ["addwf", self.addwf],
            "1010": ["bsf", self.bsf],
        }
        
        return
    
    def disassemble(self, data: bytes, addr: int):
        
        instr_asint = int.from_bytes(data, 'little')
        for opcode, instr_data in self.instructions.items():
            op = int(opcode, 2)
            print(f"instr_asint: {instr_asint}({bin(instr_asint)}) op:{op}({bin(op)}) xor: {bin(instr_asint ^ op)}({bin((2**len(opcode)) - 1)})")
            if (instr_asint ^ op) & ((2**len(opcode)) - 1) == 0:
                print('yes')
                handler = instr_data[1]
                return handler(instr_data[0], data, addr)
        
        print('didnt find')
        return
    
    def addwf(self, mnemonic, data, addr):
        print('addwf called')
        
        return [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic + " ")]
    
    def bsf(self, mnemonic, data, addr):
        print('bsf called')
        pass