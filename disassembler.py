from binaryninja import (
    InstructionTextToken,
    BranchType,
    InstructionTextTokenType
)
from .instruction import *

class PIC16FDisassembler():
    
    def __init__(self):
        
        return
    
    def disassemble(self, data: bytes, addr: int):
        
        if len(data) < 2:
            return
        
        return Instruction.new(data, addr).disassemble()