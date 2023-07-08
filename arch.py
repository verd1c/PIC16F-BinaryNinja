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
from .lifter import PIC16FLifter

class PIC16Architecture(Architecture):
    name = "pic16"
    
    max_instr_size = 2
    instr_alignment = 2
    
    stack_pointer = "SP"
    
    regs = {}
    regs['PCLATH'] = RegisterInfo('PCLATH', 1)
    regs['BSR'] = RegisterInfo('BSR', 1)
    regs['W'] = RegisterInfo('W', 1)
    regs['SP'] = RegisterInfo('SP', 1)
    
    # file regs
    for i in range(0x80):
        regs[f'F{i}'] = RegisterInfo(f'F{i}', 1)
    
    # really not sure about this
    for i in range(0x80):
        regs[f'FSR{i}'] = RegisterInfo(f'FSR{i}', 1)
    
    def __init__(self):
        super().__init__()
        
        self.disassembler = PIC16FDisassembler()
        self.lifter = PIC16FLifter()
        
        return
    
    def get_instruction_info(self, data: bytes, addr: int) -> InstructionInfo | None:
        _, branches, ilen = self.disassembler.disassemble(data, addr)
        
        instr_info = InstructionInfo(ilen)
        for br in branches:
            instr_info.add_branch(branch_type=br.type, target=br.target)
        
        return instr_info
    
    def get_instruction_text(self, data: bytes, addr: int) -> Tuple[List[InstructionTextToken], int] | None:
        tokens, _, ilen = self.disassembler.disassemble(data, addr)
        
        return tokens, ilen
    
    def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> int | None:
        lllen = self.lifter.lift(data, addr, il)
        
        print(f'{lllen} @ {hex(addr)}')
        
        return 2
    
