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
        # self.instructions = {
        #     "111000": ["addwf", self.addwf],
        #     "1010": ["bsf", self.bsf],
        # }
        
        self.instruction_groups = {
            3: [{
                '100': 'CALL',
                '101': 'GOTO',
            }, self._disass_call_goto],
            4: [{
                '0100': 'BCF',
                '0101': 'BSF',
                '0110': 'BTFSC',
                '0111': 'BTFSS',
            }, self._disass_bit_filereg_op],
            5: [{
                '11001': 'BRA',
            }, self._disass_bra],
            6: [{
                '000111': 'ADDWF',
                '111101': 'ADDWFC',
                '000101': 'ANDWF',
                '110111': 'ASRF',
                '110101': 'LSLF',
                '110110': 'LSRF',
                '000001': 'CLRF',
                '001001': 'COMF',
                '000011': 'DECF',
                '001010': 'INCF',
                '000100': 'IORWF',
                '001000': 'MOVF',
                '001101': 'RLF',
                '001100': 'RRF',
                '000010': 'SUBWF',
                '111011': 'SUBWFB',
                '001110': 'SWAPF',
                '000110': 'XORWF',
                '001011': 'DECFSZ',
                '001111': 'INCFSZ',
                '111110': 'ADDLW',
                '111001': 'ANDLW',
                '111000': 'IORLW',
                '110000': 'MOVLW',
                '111100': 'SUBLW',
                '111010': 'XORLW',
                '110100': 'RETLW',
            }, self._disass_literal_general_n_byte_filereg_op],
            7: [{
                '0000001': 'MOVWF',
                '1100011': 'MOVLP',
                '1100010': 'ADDFSR',
                '1111110': 'MOVIWK',
                '1111111': 'MOVWIK',
            }, self._disass_movlp_n_fsr_offset],
            9: [{
                '000000001': 'MOVLB',
            }, self._disass_movlb],
            11: [{
                '00000001100': 'TRIS',
                '00000000010': 'MOVIW',
                '00000000011': 'MOVWI',
            }, self._disass_fsr_inc],
            14: [{
                '00000000001011': 'BRW',
                '00000000001010': 'CALLW',
                '00000000001001': 'RETFIE',
                '00000000001000': 'RETURN',
                '00000001100100': 'CLRWDT',
                '00000000000000': 'NOP',
                '00000001100010': 'OPTION',
                '00000000000001': 'RESET',
                '00000001100011': 'SLEEP',
            }, self._disass_opcode_only],
            
        }
        
        ops = {
            '000001000000': 'CLRW',
        }
        
        return
    
    # def disassemble(self, data: bytes, addr: int):
        
    #     if len(data) < 2:
    #         return
        
    #     instr = data[:2]
    #     instr_asint = int.from_bytes(instr, 'big')
    #     instr_bits = bin(instr_asint)[2:].zfill(16)[2:]
    #     for opcode, instr_data in self.instructions.items():
    #         op = int(opcode, 2)
    #         print(f"instr_bits: {instr_bits} instr_asint: {instr_asint}({bin(instr_asint)}) op:{op}({bin(op)}) xor: {bin(instr_asint ^ op)}({bin((2**len(opcode)) - 1)})")
    #         if (instr_asint ^ op) & ((2**len(opcode)) - 1) == 0:
    #             print('yes')
    #             handler = instr_data[1]
    #             return handler(instr_data[0], instr, addr)
        
    #     print('didnt find')
    #     return
    
    def disassemble(self, data: bytes, addr: int):
        
        if len(data) < 2:
            return
        
        instr = data[:2]
        instr_asint = int.from_bytes(instr, 'big')
        instr_bits = bin(instr_asint)[2:].zfill(16)[2:]
        
        for opcode_len, group_data in self.instruction_groups.items():
            # print(f'Searching len {opcode_len}')
            instrs = group_data[0]
            handler = group_data[1]
            masked_instr = int(instr_bits, 2) >> (14 - opcode_len)
            
            # print(masked_instr)
            # print(instrs.keys())
            
            if masked_instr in [int(i, 2) for i in instrs.keys()]:
                mnemonic = instrs[bin(masked_instr)[2:].zfill(opcode_len)]
                return handler(mnemonic, instr_bits, addr)
                
            # for opcode, instr_data in instrs.items():
            #     print(f'\tLen {opcode_len} instr_bits {instr_bits} mask {bin((2**opcode_len - 1))} opcode {opcode} | {int(instr_bits, 2) >> (14 - opcode_len)} == {int(opcode, 2)}')
            #     if int(instr_bits, 2) & (2**opcode_len - 1) == int(opcode, 2):
            #         return handler(instr_data[0], instr_bits, addr)
                    
        
        
        # for opcode, instr_data in self.instructions.items():
        #     op = int(opcode, 2)
        #     print(f"instr_bits: {instr_bits} instr_asint: {instr_asint}({bin(instr_asint)}) op:{op}({bin(op)}) xor: {bin(instr_asint ^ op)}({bin((2**len(opcode)) - 1)})")
        #     if (instr_asint ^ op) & ((2**len(opcode)) - 1) == 0:
        #         print('yes')
        #         handler = instr_data[1]
        #         return handler(instr_data[0], instr, addr)
        
        print('didnt find')
        return
    
    def _disass_call_goto(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic + " ")]
        return tokens
    
    def _disass_bit_filereg_op(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic + " ")]
        return tokens
    
    def _disass_bra(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic + " ")]
        return tokens
    
    def _disass_literal_general_n_byte_filereg_op(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic + " ")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(int(data[6:], 2)), int(data[6:], 2)))
        # print('_disass_literal_general_n_byte_filereg_op CALLED')
        print(data)
        return tokens
    
    def _disass_movlp_n_fsr_offset(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic + " ")]
        return tokens
    
    def _disass_movlb(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic + " ")]
        return tokens
    
    def _disass_fsr_inc(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic + " ")]
        return tokens
    
    def _disass_opcode_only(self, mnemonic, data, addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic + " ")]
        return tokens
    