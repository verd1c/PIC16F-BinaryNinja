from binaryninja import (
    InstructionTextToken,
    BranchType,
    InstructionTextTokenType
)
from .instruction import *

class PIC16FDisassembler():
    
    conditional_instructions = ["BTFSS", "BTFSC"]
    
    def __init__(self):
        
        return
    
    def disassemble(self, data: bytes, addr: int):
        
        if len(data) < 2:
            return
                
        if len(data) >= 6:
            cnd = Instruction.new(data[0:2], addr)
            if cnd.name in self.conditional_instructions:
                tokens, labels = Instruction.disassemble_conditional_jump(data, addr)
                return tokens, labels, 6
        
        tokens, labels = Instruction.new(data, addr).disassemble()
        return tokens, labels, 2