from typing import List, Optional, Tuple
from binaryninja import (
    Architecture,
    RegisterInfo,
    LowLevelILFunction,
    IntrinsicInfo,
    InstructionTextToken,
    Type,
    InstructionInfo,
    function,
    lowlevelil
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
        _, branches = self.disassembler.disassemble(data, addr)
        
        instr_info = InstructionInfo(2)
        for br in branches:
            instr_info.add_branch(branch_type=br.type, target=br.target)
        
        return instr_info
    
    def get_instruction_text(self, data: bytes, addr: int) -> Tuple[List[InstructionTextToken], int] | None:
        tokens, _ = self.disassembler.disassemble(data, addr)
        
        return tokens, 2
    
    def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> int | None:
        
        return 2
    
