from typing import List, Optional, Tuple
from binaryninja import (
    Architecture,
    RegisterInfo,
    IntrinsicInfo,
    InstructionTextToken,
    Type,
    InstructionInfo,
    function
)
from binaryninja.architecture import InstructionInfo
from .disassembler import PIC16FDisassembler

class PIC16Architecture(Architecture):
    name = "pic16"
    
    max_instr_size = 2
    instr_alignment = 2
    
    def __init__(self):
        super().__init__()
        
        self.disassembler = PIC16FDisassembler()
        
        return
    
    def get_instruction_info(self, data: bytes, addr: int) -> InstructionInfo | None:
        return InstructionInfo(2)
    
    def get_instruction_text(self, data: bytes, addr: int) -> Tuple[List[InstructionTextToken], int] | None:
        print(data)
        return self.disassembler.disassemble(data, addr), 2
    
    
    
